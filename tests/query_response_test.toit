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
