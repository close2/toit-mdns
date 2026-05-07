import expect show *
import net
import net.udp
import net.modules.dns

import mdns.net.dns_helper as dns-helper
import mdns.net.mdns_socket show MdnsSocket
import mdns.server.conflict_manager show ConflictManager
import mdns.server.state_manager show StateManager
import .e2e_param show TEST-PORT

main:
  test-hostname-query-type-must-match
  test-known-answer-data-must-match
  test-legacy-query-uses-unicast-response
  test-case-insensitive-query
  test-single-response-per-packet
  test-meta-query-target
  test-ptr-known-answer-does-not-suppress-srv
  test-ptr-known-answer-does-not-suppress-txt

test-hostname-query-type-must-match:
  print "Test: Hostname responses honor qtype..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  local-ip := net.IpAddress.parse "192.168.1.50"
  sm := StateManager socket cm "typed.local" local-ip --expected-port=TEST-PORT
  sm.start

  try:
    sleep (Duration --ms=3000)
    monitor := MdnsSocket --network=network --port=TEST-PORT
    try:
      query := dns.create-dns-packet [dns.Question "typed.local" dns.RECORD-TXT] [] --id=0x1001 --is-response=false
      sm.process-packet (dns-helper.parse query) --source=monitor.local-address

      response := wait-for-mdns-response monitor "typed.local"
      expect-null response
      print "  PASS"
    finally:
      monitor.close
  finally:
    sm.stop
    socket.close

test-known-answer-data-must-match:
  print "Test: Known-answer suppression requires matching data..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  local-ip := net.IpAddress.parse "192.168.1.50"
  sm := StateManager socket cm "known-data.local" local-ip --expected-port=TEST-PORT
  sm.start

  try:
    sleep (Duration --ms=3000)
    monitor := MdnsSocket --network=network --port=TEST-PORT
    try:
      known-answer := dns.AResource "known-data.local" 80 (net.IpAddress.parse "192.168.1.99")
      query := dns.create-dns-packet [dns.Question "known-data.local" dns.RECORD-A] [known-answer]
          --id=0x1002
          --is-response=false
      sm.process-packet (dns-helper.parse query) --source=monitor.local-address

      response := wait-for-mdns-response monitor "known-data.local"
      expect-not-null response
      found-our-a := false
      response.resources.do: | res |
        if res.name == "known-data.local" and res.type == dns.RECORD-A:
          expect-equals local-ip (res as dns.AResource).address
          found-our-a = true
      expect found-our-a
      print "  PASS"
    finally:
      monitor.close
  finally:
    sm.stop
    socket.close

test-legacy-query-uses-unicast-response:
  print "Test: Legacy queries get conventional unicast responses..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  local-ip := net.IpAddress.parse "192.168.1.50"
  sm := StateManager socket cm "legacy.local" local-ip --expected-port=TEST-PORT
  sm.start

  try:
    sleep (Duration --ms=3000)
    receiver := network.udp-open --port=0
    try:
      query := dns.create-dns-packet [dns.Question "legacy.local" dns.RECORD-A] [] --id=0x4242 --is-response=false
      sm.process-packet (dns-helper.parse query) --source=receiver.local-address

      response := wait-for-unicast-response receiver "legacy.local"
      expect-not-null response
      expect-equals 0x4242 response.id
      expect-equals 1 response.questions.size
      expect-equals "legacy.local" response.questions[0].name
      expect-equals dns.RECORD-A response.questions[0].type
      found-a := false
      response.resources.do: | res |
        if res.name == "legacy.local" and res.type == dns.RECORD-A:
          found-a = true
        expect-not res.flush
      expect found-a
      print "  PASS"
    finally:
      receiver.close
  finally:
    sm.stop
    socket.close

wait-for-mdns-response socket/MdnsSocket name/string -> dns.DecodedPacket?:
  10.repeat:
    catch:
      with-timeout (Duration --ms=150):
        datagram := socket.receive
        if datagram:
          packet := dns-helper.parse datagram.data
          if packet.is-response and has-record-named packet name:
            return packet
  return null

wait-for-unicast-response socket name/string -> dns.DecodedPacket?:
  10.repeat:
    catch:
      with-timeout (Duration --ms=150):
        datagram := socket.receive
        if datagram:
          packet := dns-helper.parse datagram.data
          if packet.is-response and has-record-named packet name:
            return packet
  return null

has-record-named packet/dns.DecodedPacket name/string -> bool:
  packet.resources.do: | res |
    if res.name == name: return true
  return false

// ---------------------------------------------------------------------------
// New regression tests for additional bugs found in the second audit.
// ---------------------------------------------------------------------------

test-case-insensitive-query:
  print "Test: Queries are matched case-insensitively (RFC 6762 §16)..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  local-ip := net.IpAddress.parse "192.168.1.50"
  sm := StateManager socket cm "mixedcase.local" local-ip --expected-port=TEST-PORT
  sm.start
  try:
    sleep (Duration --ms=3000)
    monitor := MdnsSocket --network=network --port=TEST-PORT
    try:
      // Query for our hostname using mixed case. The implementation
      // must match it case-insensitively and respond with the A record.
      query := dns.create-dns-packet
          [dns.Question "MixedCase.LOCAL" dns.RECORD-A]
          []
          --id=0
          --is-response=false
      sm.process-packet (dns-helper.parse query) --source=monitor.local-address
      response := wait-for-mdns-response monitor "mixedcase.local"
      expect-not-null response
      found := false
      response.resources.do: | res |
        if res.type == dns.RECORD-A:
          expect-equals local-ip (res as dns.AResource).address
          found = true
      expect found
      print "  PASS"
    finally:
      monitor.close
  finally:
    sm.stop
    socket.close

test-single-response-per-packet:
  print "Test: One response per packet, even when multiple questions match..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  local-ip := net.IpAddress.parse "192.168.1.50"
  sm := StateManager socket cm "merge.local" local-ip --expected-port=TEST-PORT
  sm.register-service "_http._tcp" 8080 --txt={"path": "/"}
  sm.start
  try:
    sleep (Duration --ms=3000)
    monitor := MdnsSocket --network=network --port=TEST-PORT
    try:
      // Single packet with two relevant questions: hostname A AND
      // service PTR. The responder used to call send-response_ twice
      // for this case, leaking duplicate packets.
      questions := [
        dns.Question "merge.local" dns.RECORD-A,
        dns.Question "_http._tcp.local" dns.RECORD-PTR,
      ]
      query := dns.create-dns-packet questions [] --id=0 --is-response=false
      // Drain anything left over from announcements before sending.
      drain-socket monitor
      sm.process-packet (dns-helper.parse query) --source=monitor.local-address

      // Count how many response packets we actually receive in 1s.
      // Exactly one response packet must be sent.
      responses := collect-responses monitor "merge.local" (Duration --ms=1000)
      expect-equals 1 responses.size
      // And it should contain BOTH the A record and the PTR record.
      response := responses[0]
      saw-a := response.resources.any: | res |
        res.type == dns.RECORD-A and res.name == "merge.local"
      saw-ptr := response.resources.any: | res |
        res.type == dns.RECORD-PTR and res.name == "_http._tcp.local"
      expect saw-a
      expect saw-ptr
      print "  PASS"
    finally:
      monitor.close
  finally:
    sm.stop
    socket.close

test-meta-query-target:
  print "Test: _services._dns-sd._udp.local meta-query returns service type..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  local-ip := net.IpAddress.parse "192.168.1.50"
  sm := StateManager socket cm "meta.local" local-ip --expected-port=TEST-PORT
  sm.register-service "_http._tcp" 8080 --txt={"path": "/"}
  sm.start
  try:
    sleep (Duration --ms=3000)
    monitor := MdnsSocket --network=network --port=TEST-PORT
    try:
      query := dns.create-dns-packet
          [dns.Question "_services._dns-sd._udp.local" dns.RECORD-PTR]
          []
          --id=0
          --is-response=false
      drain-socket monitor
      sm.process-packet (dns-helper.parse query) --source=monitor.local-address

      response := wait-for-mdns-response monitor "_services._dns-sd._udp.local"
      expect-not-null response
      // Per RFC 6763 §9: response must be a PTR with
      //   owner = _services._dns-sd._udp.local
      //   rdata = the service type-domain (e.g. _http._tcp.local).
      meta-ptr := find-record-by-name response "_services._dns-sd._udp.local"
      expect-not-null meta-ptr
      expect meta-ptr is dns.StringResource
      expect-equals dns.RECORD-PTR meta-ptr.type
      expect-equals "_http._tcp.local" (meta-ptr as dns.StringResource).value
      // The responder must NOT confuse this with a regular type-domain
      // PTR (which would point to the instance name).
      expect-not ((meta-ptr as dns.StringResource).value.contains "meta.")
      print "  PASS"
    finally:
      monitor.close
  finally:
    sm.stop
    socket.close

test-ptr-known-answer-does-not-suppress-srv:
  print "Test: Known-answer for PTR must not suppress direct SRV question..."
  test-ptr-known-answer-does-not-suppress-record_ dns.RECORD-SRV "SRV"

test-ptr-known-answer-does-not-suppress-txt:
  print "Test: Known-answer for PTR must not suppress direct TXT question..."
  test-ptr-known-answer-does-not-suppress-record_ dns.RECORD-TXT "TXT"

test-ptr-known-answer-does-not-suppress-record_ direct-type/int label/string:
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  local-ip := net.IpAddress.parse "192.168.1.50"
  sm := StateManager socket cm "ka-skip.local" local-ip --expected-port=TEST-PORT
  sm.register-service "_http._tcp" 8080 --txt={"path": "/"}
  sm.start
  try:
    sleep (Duration --ms=3000)
    monitor := MdnsSocket --network=network --port=TEST-PORT
    try:
      // Known answer in the query: PTR pointing at the same instance.
      // This must suppress the PTR portion of the response, but it
      // must NOT skip the direct SRV/TXT questions for the instance.
      ka := dns.StringResource "_http._tcp.local" dns.RECORD-PTR 4500 false "ka-skip._http._tcp.local"
      questions := [
        dns.Question "_http._tcp.local" dns.RECORD-PTR,
        dns.Question "ka-skip._http._tcp.local" direct-type,
      ]
      query := dns.create-dns-packet questions [ka] --id=0 --is-response=false
      drain-socket monitor
      sm.process-packet (dns-helper.parse query) --source=monitor.local-address

      response := wait-for-mdns-response monitor "ka-skip._http._tcp.local"
      expect-not-null response
      saw-direct := response.resources.any: | res |
        res.type == direct-type and res.name == "ka-skip._http._tcp.local"
      expect saw-direct --message="$label answer must be present"
      print "  PASS"
    finally:
      monitor.close
  finally:
    sm.stop
    socket.close

drain-socket socket/MdnsSocket -> none:
  // Eat any pending datagrams (e.g. announcement packets) so the test
  // sees only the response we are about to provoke.
  16.repeat:
    catch:
      with-timeout (Duration --ms=20):
        socket.receive
      continue.repeat
    return

collect-responses socket/MdnsSocket name/string duration/Duration -> List:
  result := []
  deadline := Time.monotonic-us + duration.in-us
  while Time.monotonic-us < deadline:
    catch:
      remaining := deadline - Time.monotonic-us
      if remaining <= 0: return result
      with-timeout (Duration --us=remaining):
        datagram := socket.receive
        if datagram:
          packet := dns-helper.parse datagram.data
          if packet.is-response and (has-record-named packet name):
            result.add packet
  return result

find-record-by-name packet/dns.DecodedPacket name/string -> dns.Resource?:
  packet.resources.do: | res |
    if res.name == name: return res
  return null
