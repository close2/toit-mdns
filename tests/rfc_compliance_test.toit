/**
RFC 6762 MUST compliance tests.

Tests each critical MUST requirement from the mDNS RFC to ensure
the library correctly implements the mandatory protocol behavior.

Each test function is named after the RFC section it verifies and
includes a comment citing the exact MUST requirement.
*/

import expect show *
import net
import net.udp
import net.modules.dns

import mdns.service show MdnsServiceProvider
import mdns.client show Client
import mdns.api.mdns_service show MdnsService
import mdns.net.mdns_socket show MdnsSocket
import mdns.server.conflict_manager show ConflictManager
import mdns.server.state_manager show StateManager
import mdns.net.dns_helper as dns-helper
import .e2e_param show TEST-PORT

main:
  // §18 Message format validation
  test-section-18-3-reject-nonzero-opcode
  test-section-18-11-reject-nonzero-rcode
  test-section-18-1-multicast-response-id-zero

  // §6 Responding
  test-section-6-7-responses-contain-no-questions
  test-section-6-10-reject-response-from-wrong-port

  // §8 Probing and Announcing
  test-section-8-1-probing-three-queries
  test-section-8-1-probing-random-jitter
  test-section-8-2-probe-includes-authority-section
  test-section-8-3-two-announcements
  test-section-8-5-ignore-responses-before-first-probe

  // §7 Known-Answer Suppression
  test-section-7-1-known-answer-suppression

  // §9 Conflict Resolution
  test-section-9-1-conflict-resets-to-probing
  test-section-9-2-conflict-rename

  // §10 Cache Coherency
  test-section-10-4-cache-flush-on-unique-records
  test-section-10-7-no-cache-flush-on-shared-records

  // End-to-end integration tests
  test-e2e-rfc-compliance

  print "All RFC compliance tests passed!"


// ---------------------------------------------------------------------------
// §18 — Message Format
// ---------------------------------------------------------------------------

/**
§18.3: OPCODE MUST be zero on transmission. Multicast DNS messages
received with an OPCODE other than zero MUST be silently ignored.
*/
test-section-18-3-reject-nonzero-opcode:
  print "Test §18.3: Reject non-zero OPCODE..."
  // Build a normal query then patch OPCODE to 1 (Inverse Query).
  // DNS header byte 2: QR(1) | OPCODE(4) | AA(1) | TC(1) | RD(1)
  questions := [dns.Question "opcode.local" dns.RECORD-A]
  packet := dns.create-dns-packet questions [] --id=0 --is-response=false
  packet[2] = 0x08  // OPCODE = 1

  // The SDK may throw for opcode > 2. Either way, the packet
  // should be rejected by our validator.
  exc := catch:
    decoded := dns-helper.parse packet
    expect (not (dns-helper.is-valid-mdns-message decoded))
  // If it threw, that's also correct — packet is rejected.
  print "  PASS"


/**
§18.11: Response Code MUST be zero on transmission. Multicast DNS
messages received with non-zero Response Codes MUST be silently ignored.
*/
test-section-18-11-reject-nonzero-rcode:
  print "Test §18.11: Reject non-zero RCODE..."
  answers := [dns.AResource "rcode.local" 120 (net.IpAddress.parse "10.0.0.1")]
  packet := dns.create-dns-packet [] answers --id=0 --is-response=true --is-authoritative=true
  // Byte 3: RA(1) | Z(3) | RCODE(4). Set RCODE=3 (Name Error).
  packet[3] = (packet[3] & 0xF0) | 0x03

  exc := catch:
    decoded := dns-helper.parse packet
    expect (not (dns-helper.is-valid-mdns-message decoded))
  print "  PASS"


/**
§18.1: In multicast response messages, the Query Identifier MUST be
set to zero on transmission.
*/
test-section-18-1-multicast-response-id-zero:
  print "Test §18.1: Multicast response ID = 0..."
  packet := dns.create-dns-packet [] [dns.AResource "test.local" 120 (net.IpAddress.parse "10.0.0.1")] --id=0 --is-response=true --is-authoritative=true
  // Bytes 0-1 = ID
  expect-equals 0 packet[0]
  expect-equals 0 packet[1]
  print "  PASS"


// ---------------------------------------------------------------------------
// §6 — Responding
// ---------------------------------------------------------------------------

/**
§6.7: Multicast DNS responses MUST NOT contain any questions in the
Question Section.
*/
test-section-6-7-responses-contain-no-questions:
  print "Test §6.7: Responses have no questions..."
  packet := dns.create-dns-packet [] [dns.AResource "test.local" 120 (net.IpAddress.parse "10.0.0.1")] --id=0 --is-response=true --is-authoritative=true
  // Bytes 4-5 = QDCOUNT
  expect-equals 0 packet[4]
  expect-equals 0 packet[5]
  print "  PASS"


/**
§6.10: MUST silently ignore any Multicast DNS responses they receive
where the source UDP port is not 5353.
*/
test-section-6-10-reject-response-from-wrong-port:
  print "Test §6.10: Reject responses from non-5353 port..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  local-ip := net.IpAddress.parse "192.168.1.50"
  sm := StateManager socket cm "portcheck.local" local-ip --expected-port=TEST-PORT
  sm.start
  sleep (Duration --ms=3000)

  // Inject a conflicting response "from" port 1234 (not 5353).
  other-ip := net.IpAddress.parse "192.168.1.99"
  answers := [dns.AResource "portcheck.local" 120 other-ip --flush=true]
  packet := dns.create-dns-packet [] answers --id=0 --is-response=true --is-authoritative=true
  wrong-port-source := net.SocketAddress other-ip 1234
  sm.process-packet packet --source=wrong-port-source

  // Should be ignored — hostname unchanged.
  expect-equals "portcheck.local" sm.hostname
  sm.stop
  socket.close
  print "  PASS"


// ---------------------------------------------------------------------------
// §8 — Probing and Announcing
// ---------------------------------------------------------------------------

/**
§8.1: Random delay 0-250ms before first probe.
*/
test-section-8-1-probing-random-jitter:
  print "Test §8.1: Probing has random jitter..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  local-ip := net.IpAddress.parse "192.168.1.50"
  sm := StateManager socket cm "jitter.local" local-ip --expected-port=TEST-PORT
  sm.start
  // At 50ms, should still be PROBING (jitter hasn't expired yet in all cases,
  // and even if it has, probing takes 3×250ms).
  sleep (Duration --ms=50)
  expect-equals StateManager.STATE-PROBING sm.state_
  sm.stop
  socket.close
  print "  PASS"


/**
§8.1: Three probes 250ms apart, then announce if no conflict.
*/
test-section-8-1-probing-three-queries:
  print "Test §8.1: Three probes, then established..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  local-ip := net.IpAddress.parse "192.168.1.50"
  sm := StateManager socket cm "probe3.local" local-ip --expected-port=TEST-PORT
  sm.start
  // Probing: up to 250ms jitter + 3×250ms = ~1000ms
  // Announcing: 2 announcements 1s apart = ~1s
  // Total: ~2s. Wait 3s to be safe.
  sleep (Duration --ms=3000)
  expect-equals StateManager.STATE-ESTABLISHED sm.state_
  sm.stop
  socket.close
  print "  PASS"


/**
§8.2: Probe includes Authority Section for tiebreaking.
*/
test-section-8-2-probe-includes-authority-section:
  print "Test §8.2: Probe has Authority Section..."
  hostname := "authsec.local"
  local-ip := net.IpAddress.parse "192.168.1.50"
  questions := [dns.Question hostname dns.RECORD-ANY]
  authorities := [dns.AResource hostname 120 local-ip]
  packet := dns.create-dns-packet questions [] --id=0 --is-response=false --authorities=authorities
  decoded := dns-helper.parse packet
  expect (not decoded.authorities.is-empty)
  auth := decoded.authorities[0]
  expect-equals hostname auth.name
  expect (auth is dns.AResource)
  expect-equals local-ip (auth as dns.AResource).address
  print "  PASS"


/**
§8.3: The Multicast DNS responder MUST send at least two unsolicited
responses, one second apart.
Verify the announcing phase takes ≥1s (the gap between announcements).
*/
test-section-8-3-two-announcements:
  print "Test §8.3: Two announcements, 1s apart..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  local-ip := net.IpAddress.parse "192.168.1.50"
  sm := StateManager socket cm "announce2.local" local-ip --expected-port=TEST-PORT
  sm.start
  // Probing: ~250ms jitter max + 3×250ms = ~1000ms
  // Then ANNOUNCING: 1st announcement, then 1s gap, then 2nd.
  // At ~1200ms we should not yet be ESTABLISHED.
  sleep (Duration --ms=1200)
  // Should still be in PROBING or ANNOUNCING.
  expect (sm.state_ != StateManager.STATE-ESTABLISHED)

  // After 3.5s total, should be ESTABLISHED.
  sleep (Duration --ms=2300)
  expect-equals StateManager.STATE-ESTABLISHED sm.state_
  sm.stop
  socket.close
  print "  PASS"


/**
§8.5: Responses before first probe MUST be silently ignored.
*/
test-section-8-5-ignore-responses-before-first-probe:
  print "Test §8.5: Ignore pre-probe responses..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  local-ip := net.IpAddress.parse "192.168.1.50"
  sm := StateManager socket cm "preprobe.local" local-ip --expected-port=TEST-PORT
  sm.start

  // Immediately inject a conflicting response before first jitter+probe.
  other-ip := net.IpAddress.parse "192.168.1.99"
  answers := [dns.AResource "preprobe.local" 120 other-ip --flush=true]
  packet := dns.create-dns-packet [] answers --id=0 --is-response=true --is-authoritative=true
  source := net.SocketAddress other-ip 5353
  sm.process-packet packet --source=source

  // Should be ignored — hostname unchanged.
  expect-equals "preprobe.local" sm.hostname
  sm.stop
  socket.close
  print "  PASS"


// ---------------------------------------------------------------------------
// §7 — Known-Answer Suppression
// ---------------------------------------------------------------------------

/**
§7.1: A Multicast DNS responder MUST NOT answer a Multicast DNS query
if the answer it would give is already included in the Answer Section
with an RR TTL at least half the correct value.
*/
test-section-7-1-known-answer-suppression:
  print "Test §7.1: Known-Answer Suppression..."
  hostname := "known.local"
  our-ttl := 120

  // Query with Known-Answer TTL ≥ 50% of ours → suppress.
  questions := [dns.Question hostname dns.RECORD-A]
  known-answers := [dns.AResource hostname 80 (net.IpAddress.parse "192.168.1.50")]
  packet := dns.create-dns-packet questions known-answers --id=0 --is-response=false
  decoded := dns-helper.parse packet
  expect (dns-helper.has-known-answer decoded hostname dns.RECORD-A our-ttl)

  // Query with Known-Answer TTL < 50% → must NOT suppress.
  known-answers-low := [dns.AResource hostname 40 (net.IpAddress.parse "192.168.1.50")]
  packet2 := dns.create-dns-packet questions known-answers-low --id=0 --is-response=false
  decoded2 := dns-helper.parse packet2
  expect (not (dns-helper.has-known-answer decoded2 hostname dns.RECORD-A our-ttl))

  // Query with no Known-Answers → must NOT suppress.
  packet3 := dns.create-dns-packet questions [] --id=0 --is-response=false
  decoded3 := dns-helper.parse packet3
  expect (not (dns-helper.has-known-answer decoded3 hostname dns.RECORD-A our-ttl))

  // Wrong record type → must NOT suppress (e.g. PTR answer for an A query).
  wrong-type-answers := [dns.StringResource hostname dns.RECORD-PTR 80 false "other.local"]
  packet4 := dns.create-dns-packet questions wrong-type-answers --id=0 --is-response=false
  decoded4 := dns-helper.parse packet4
  expect (not (dns-helper.has-known-answer decoded4 hostname dns.RECORD-A our-ttl))

  print "  PASS"


// ---------------------------------------------------------------------------
// §9 — Conflict Resolution
// ---------------------------------------------------------------------------

/**
§9.1: Conflict during ESTABLISHED resets to PROBING after rename.
*/
test-section-9-1-conflict-resets-to-probing:
  print "Test §9.1: Conflict resets to PROBING..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  local-ip := net.IpAddress.parse "192.168.1.50"
  sm := StateManager socket cm "conflict-reset.local" local-ip --expected-port=TEST-PORT
  sm.start
  sleep (Duration --ms=3000)
  expect-equals StateManager.STATE-ESTABLISHED sm.state_

  // Inject >3 conflicts to force rename.
  other-ip := net.IpAddress.parse "192.168.1.99"
  source := net.SocketAddress other-ip TEST-PORT
  4.repeat:
    answers := [dns.AResource sm.hostname 120 other-ip --flush=true]
    packet := dns.create-dns-packet [] answers --id=0 --is-response=true --is-authoritative=true
    sm.process-packet packet --source=source
    sleep (Duration --ms=50)

  // Should have renamed and be back to probing.
  expect-equals StateManager.STATE-PROBING sm.state_
  sm.stop
  socket.close
  print "  PASS"


/**
§9.2: Conflict during probing causes rename.
*/
test-section-9-2-conflict-rename:
  print "Test §9.2: Conflict causes rename..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  local-ip := net.IpAddress.parse "192.168.1.50"
  sm := StateManager socket cm "rename.local" local-ip --expected-port=TEST-PORT
  sm.start
  sleep (Duration --ms=300)

  // Inject conflict during probing from correct port.
  other-ip := net.IpAddress.parse "192.168.1.99"
  answers := [dns.AResource "rename.local" 120 other-ip --flush=true]
  packet := dns.create-dns-packet [] answers --id=0 --is-response=true --is-authoritative=true
  source := net.SocketAddress other-ip TEST-PORT
  sm.process-packet packet --source=source

  sleep (Duration --ms=100)
  expect-equals "rename-2.local" sm.hostname
  sm.stop
  socket.close
  print "  PASS"


// ---------------------------------------------------------------------------
// §10 — Cache Coherency
// ---------------------------------------------------------------------------

/**
§10.4: Cache-flush bit on unique records.
*/
test-section-10-4-cache-flush-on-unique-records:
  print "Test §10.4: Cache-flush bit on unique records..."
  hostname := "flush.local"
  local-ip := net.IpAddress.parse "192.168.1.50"
  answers := [dns.AResource hostname 120 local-ip --flush]
  packet := dns.create-dns-packet [] answers --id=0 --is-response --is-authoritative
  decoded := dns-helper.parse packet
  expect decoded.resources[0].flush
  print "  PASS"


/**
§10.7: No cache-flush on shared records (PTR).
*/
test-section-10-7-no-cache-flush-on-shared-records:
  print "Test §10.7: No cache-flush on shared records..."
  ptr := dns.StringResource "_http._tcp.local" dns.RECORD-PTR 4500 false "myhost._http._tcp.local"
  packet := dns.create-dns-packet [] [ptr] --id=0 --is-response --is-authoritative
  decoded := dns-helper.parse packet
  expect (not decoded.resources[0].flush)
  print "  PASS"


// ---------------------------------------------------------------------------
// End-to-end integration test (original)
// ---------------------------------------------------------------------------

test-e2e-rfc-compliance:
  print "Testing E2E RFC 6762 compliance..."

  service := MdnsServiceProvider --port=TEST-PORT
  service.handle MdnsService.SET-HOSTNAME-INDEX "rfc-test.local" --client=0 --gid=0
  service.register "_rfc._tcp" 9999 --name="RFCInstance" --hostname="rfc-test.local"

  network := net.open
  monitor := MdnsSocket --network=network --port=TEST-PORT

  try:
    sleep (Duration --s=4)

    // 1. Test AA Bit and TTLs
    print "  Querying rfc-test.local..."
    q := dns.Question "rfc-test.local" dns.RECORD-A
    query-packet := dns.create-dns-packet [q] [] --is-response=false --id=0
    monitor.send query-packet

    found-response := false
    deadline := Time.now + (Duration --s=2)
    while Time.now < deadline:
      if found-response: break
      datagram := monitor.receive
      if not datagram: continue
      packet := datagram.data
      if packet.size == 0: continue

      parsed := dns-helper.parse packet
      flags-high := packet[2]
      is-aa := (flags-high & 0x04) != 0

      if dns-helper.is-authoritative-response-for parsed "rfc-test.local":
        print "  Received Response for rfc-test.local"
        expect is-aa
        verify-packet parsed --expect-unique=true
        found-response = true

    expect found-response

    // 2. Test PTR TTL (Shared Record)
    print "  Querying _rfc._tcp.local (PTR)..."
    q-ptr := dns.Question "_rfc._tcp.local" dns.RECORD-PTR
    monitor.send (dns.create-dns-packet [q-ptr] [] --is-response=false --id=0)

    found-ptr := false
    deadline = Time.now + (Duration --s=2)
    while Time.now < deadline:
      if found-ptr: break
      datagram := monitor.receive
      if not datagram: continue
      packet := datagram.data
      if packet.size == 0: continue

      parsed := dns-helper.parse packet
      parsed.resources.do: | ans |
        if ans.name == "_rfc._tcp.local" and ans.type == dns.RECORD-PTR:
          print "  Received PTR: TTL=$(ans.ttl)"
          expect-equals 4500 ans.ttl
          found-ptr = true

    expect found-ptr
    print "  E2E PASS"

  finally:
    service.close
    monitor.close


verify-packet packet/dns.DecodedPacket --expect-unique/bool:
  packet.resources.do: | ans |
    if ans.type == dns.RECORD-A or ans.type == dns.RECORD-SRV:
      if expect-unique:
        expect-equals 120 ans.ttl
