/**
Comprehensive security, memory-safety, and RFC 6762 / RFC 6763 regression tests.

Covers:
1. Compression-pointer loop DoS (0xC0 0x0C self-loop & forward pointers)
2. Excess section record-count DoS protection
3. Non-zero OPCODE 4 (NOTIFY) / 8 / 12 rejection (preserving AD-bit tolerance)
4. Corrupt RDATA / truncated TXT record rejection without stream misalignment
5. SDK DnsClient compatibility with List record-types & dns.dns-lookup
6. Optional --network=null ergonomics and Client.close reference release
7. Restricted-form NSEC negative responses (e.g. AAAA on IPv4-only host)
   and instant NSEC negative caching in QueryEngine
8. Multi-key, boolean, valueless, and binary TXT round-trip encoding/decoding
9. Goodbye (TTL=0, flush=false) eviction of cached flush=true unique records
10. Multi-responder PTR browse aggregation
11. Service reconnect deduplication after conflict rename
12. 63-octet DNS label truncation on conflict rename & case-insensitive .LOCAL
*/

import expect show *
import net
import net.modules.dns

import mdns.api.mdns-service show MdnsService
import mdns.client show Client LocalMdnsClient
import mdns.private.dns_helper as dns-helper
import mdns.private.mdns_socket show MdnsSocket
import mdns.private.cache show MdnsCache
import mdns.private.conflict_manager show ConflictManager
import mdns.private.state_manager show StateManager
import mdns.service show MdnsServiceProvider
import .e2e-param show TEST-PORT

main:
  test-compression-pointer-loop-rejected
  test-excess-record-count-rejected
  test-all-nonzero-opcodes-rejected
  test-corrupt-rdata-throws
  test-multi-and-binary-txt-roundtrip
  test-hostname-case-preserved
  test-goodbye-evicts-flushed-cache-entry
  test-conflict-manager-63-octet-and-case
  test-service-reconnect-dedup-after-rename
  test-nsec-negative-response-and-fast-lookup
  test-sdk-dns-lookup-and-client-close
  test-multi-responder-browse
  print "All security and RFC regression tests passed!"

test-compression-pointer-loop-rejected:
  print "Test: Compression-pointer self-loop and forward-pointer rejection..."
  // 18-byte packet whose question name at offset 12 jumps to offset 12 (0xC0 0x0C).
  self-loop := #[
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0x0c,
    0x00, 0x01, 0x00, 0x01,
  ]
  err := catch: dns-helper.parse self-loop
  expect-not-null err

  // Mutual / forward pointer: offset 12 jumps forward to offset 18, which jumps back to 12.
  mutual-loop := #[
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0x12, 0x00, 0x01, 0x00, 0x01,
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
  ]
  err2 := catch: dns-helper.parse mutual-loop
  expect-not-null err2
  print "  PASS"

test-excess-record-count-rejected:
  print "Test: Excess question/record count DoS rejection..."
  // Header claiming 200 questions.
  bomb-header := #[
    0x00, 0x00, 0x00, 0x00,
    0x00, 200,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ]
  err := catch: dns-helper.parse bomb-header
  expect-not-null err
  print "  PASS"

test-all-nonzero-opcodes-rejected:
  print "Test: Non-zero OPCODEs (1..15, including NOTIFY=4) rejected..."
  questions := [dns.Question "opcode-check.local" dns.RECORD-A]
  for opcode := 1; opcode <= 15; opcode++:
    pkt := dns-helper.encode-mdns-packet questions [] --id=0 --no-is-response
    pkt[2] = (pkt[2] & 0x87) | (opcode << 3)
    expect-not (dns-helper.is-valid-raw-mdns-header pkt)
    decoded := dns-helper.parse pkt
    expect-not (dns-helper.is-valid-mdns-message decoded)
  print "  PASS"

test-corrupt-rdata-throws:
  print "Test: Truncated TXT character-string throws instead of misaligning reader..."
  // TXT record with RDLENGTH=3, but character-string length byte claims 10 octets.
  corrupt-txt := #[
    0x00, 0x00, 0x84, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x03, 'f', 'o', 'o', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
    0x00, 0x10,              // TYPE = TXT (16)
    0x00, 0x01,              // CLASS = IN
    0x00, 0x00, 0x00, 0x78,  // TTL = 120
    0x00, 0x03,              // RDLENGTH = 3
    0x0a, 'a', 'b',          // Claimed string len 10 > remaining 2!
  ]
  err := catch: dns-helper.parse corrupt-txt
  expect-not-null err
  print "  PASS"

test-multi-and-binary-txt-roundtrip:
  print "Test: Multi-key, boolean, valueless, and binary TXT round-trip..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  sm := StateManager socket cm "txt-host.local" (net.IpAddress.parse "192.168.1.10") --expected-port=TEST-PORT
  txt-entries := sm.build-txt-list_ {
    "path": "/api",
    "ver": "2",
    "flag": true,
    "empty": null,
    "disabled": false,
    "bin": #[0xff, 0x00, 0x41],
  }
  socket.close

  // "disabled": false must be omitted; 5 entries remain.
  expect-equals 5 txt-entries.size
  expect (txt-entries.contains "path=/api")
  expect (txt-entries.contains "ver=2")
  expect (txt-entries.contains "flag")
  expect (txt-entries.contains "empty")

  rec := dns.TxtResource "svc._http._tcp.local" 4500 true txt-entries
  wire := dns-helper.encode-mdns-packet [] [rec] --is-response --is-authoritative
  decoded := dns-helper.parse wire
  expect-equals 1 decoded.resources.size
  decoded-txt := decoded.resources[0] as dns.TxtResource
  expect-equals 5 decoded-txt.text.size
  expect (decoded-txt.text.contains "path=/api")
  expect (decoded-txt.text.contains "ver=2")
  expect (decoded-txt.text.contains "flag")
  expect (decoded-txt.text.contains "empty")
  // Binary (non-UTF-8) values must survive the round-trip byte-exact.
  bin-entry := decoded-txt.text.filter: it is ByteArray
  expect-equals 1 bin-entry.size
  expect-equals ("bin=".to-byte-array + #[0xff, 0x00, 0x41]) bin-entry[0]

  // Long multi-byte values must be rejected instead of silently truncated.
  long-err := catch: sm.build-txt-list_ {"k": "é" * 200}
  expect-not-null long-err

  // Verify truncate-utf8 still clamps without splitting multi-byte runes (used by ConflictManager).
  clamped := dns-helper.truncate-utf8 ("é" * 200) 63
  expect (clamped.size <= 63)
  expect (clamped.to-byte-array.is-valid-string-content)
  print "  PASS"

test-hostname-case-preserved:
  print "Test: Provider preserves hostname case (RFC 6762 §16)..."
  provider := MdnsServiceProvider --port=TEST-PORT + 4
  try:
    provider.handle MdnsService.SET-HOSTNAME-INDEX "MyDevice.local" --client=1 --gid=0
    expect-equals "MyDevice.local"
        provider.handle MdnsService.GET-HOSTNAME-INDEX null --client=1 --gid=0
    // A second client using a different case shares the same manager.
    provider.handle MdnsService.SET-HOSTNAME-INDEX "mydevice.LOCAL" --client=2 --gid=0
    expect-equals 1 provider.managers_.size
    print "  PASS"
  finally:
    provider.close

test-goodbye-evicts-flushed-cache-entry:
  print "Test: Goodbye (TTL=0, flush=false) expires cached flush=true record..."
  cache := MdnsCache
  ip := net.IpAddress.parse "10.0.0.42"
  cache.add (dns.AResource "departing.local" 120 ip --flush)
  expect-equals 1 (cache.lookup "departing.local" dns.RECORD-A).size

  // Peer departs with TTL=0 and flush=false.
  cache.add (dns.AResource "departing.local" 0 ip)
  // Normal lookup must not return goodbye; entry remains in cache for the 1s grace window.
  expect (cache.lookup "departing.local" dns.RECORD-A).is-empty
  expect-equals 1 (cache.lookup "departing.local" dns.RECORD-A --include-goodbye).size

  sleep (Duration --ms=1100)
  expect (cache.lookup "departing.local" dns.RECORD-A --include-goodbye).is-empty
  print "  PASS"

test-conflict-manager-63-octet-and-case:
  print "Test: ConflictManager 63-octet DNS label bound and uppercase .LOCAL..."
  cm := ConflictManager
  expect-equals "MixedHost-2.LOCAL" (cm.resolve-probing-conflict "MixedHost.LOCAL")

  long-label := "a" * 63
  renamed := cm.resolve-probing-conflict "$(long-label).local"
  parts := renamed.split "."
  expect (parts[0].size <= 63)
  expect (parts[0].ends-with "-2")
  print "  PASS"

test-service-reconnect-dedup-after-rename:
  print "Test: Service reconnect deduplication after conflict rename..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  sm := StateManager socket cm "dedup.local" (net.IpAddress.parse "192.168.1.77") --expected-port=TEST-PORT
  sm.start
  try:
    sm.register-service "_http._tcp" 8080 --name="Clock" --txt={"v": "1"}
    expect-equals 1 sm.services-count

    // Simulate a probing conflict renaming "Clock" -> "Clock-2".
    sm.handle-service-conflict_ 0
    expect-equals 1 sm.services-count

    // Re-registering with the original name "Clock" (e.g. after Wi-Fi reconnect)
    // must match original-instance-name and NOT create a duplicate service entry.
    sm.register-service "_http._tcp" 8080 --name="Clock" --txt={"v": "1"}
    expect-equals 1 sm.services-count
    print "  PASS"
  finally:
    sm.stop
    socket.close

test-nsec-negative-response-and-fast-lookup:
  print "Test: NSEC negative response on AAAA query resolves immediately..."
  port := TEST-PORT + 1
  s1 := MdnsServiceProvider --port=port --local-ip=(net.IpAddress.parse "192.168.55.10")
  s1.handle MdnsService.SET-HOSTNAME-INDEX "ipv4only.local" --client=1 --gid=0

  s2 := MdnsServiceProvider --port=port
  s2.handle MdnsService.SET-HOSTNAME-INDEX "querier.local" --client=2 --gid=0

  try:
    sleep (Duration --ms=2200)
    start-us := Time.monotonic-us
    // Query AAAA (IPv6) with a 5-second timeout: NSEC from s1 must terminate
    // the lookup with [] well before the 5s timeout!
    res := s2.lookup "ipv4only.local" --accept-ipv4=false --accept-ipv6=true --timeout-us=5_000_000
    elapsed-ms := (Time.monotonic-us - start-us) / 1000
    expect res.is-empty
    expect (elapsed-ms < 2500)
    print "  PASS (NSEC resolved empty AAAA in $(elapsed-ms)ms)"
  finally:
    s1.close
    s2.close

test-sdk-dns-lookup-and-client-close:
  print "Test: SDK dns.dns-lookup adapter, optional --network, and Client.close..."
  port := TEST-PORT + 2
  provider := MdnsServiceProvider --port=port
  provider.install
  network := net.open
  try:
    responder := Client --hostname="sdk-target.local"
    querier := Client --hostname="sdk-querier.local"
    try:
      sleep (Duration --ms=2000)

      // 1. Direct Client.dns-lookup without --network argument (immediate post-announce!).
      ip1 := querier.dns-lookup "sdk-target.local" --timeout=(Duration --s=3)
      expect-equals network.address ip1

      // 2. SDK dns.dns-lookup-multi passing List<int> to DnsClient.get.
      ips := dns.dns-lookup-multi "sdk-target.local"
          --network=network
          --client=querier.dns-client
          --timeout=(Duration --s=3)
      expect (not ips.is-empty)
      expect-equals network.address ips[0]

      // 3. Client.close must release responder's hostname commitment on provider.
      responder.close
      sleep (Duration --ms=200)
      expect (not provider.managers_.contains "sdk-target.local")
      print "  PASS"
    finally:
      responder.close
      querier.close
  finally:
    network.close
    provider.close
    provider.uninstall

test-multi-responder-browse:
  print "Test: Multi-responder PTR browse collects both instances..."
  port := TEST-PORT + 3
  p1 := MdnsServiceProvider --port=port --local-ip=(net.IpAddress.parse "10.10.0.1")
  p1.handle MdnsService.SET-HOSTNAME-INDEX "node-one.local" --client=1 --gid=0
  p1.handle MdnsService.REGISTER-INDEX ["_clock._tcp", 8081, {"id": "1"}, "ClockOne"] --client=1 --gid=0

  p2 := MdnsServiceProvider --port=port --local-ip=(net.IpAddress.parse "10.10.0.2")
  p2.handle MdnsService.SET-HOSTNAME-INDEX "node-two.local" --client=2 --gid=0
  p2.handle MdnsService.REGISTER-INDEX ["_clock._tcp", 8082, {"id": "2"}, "ClockTwo"] --client=2 --gid=0

  browser := MdnsServiceProvider --port=port
  browser.handle MdnsService.SET-HOSTNAME-INDEX "browser-node.local" --client=3 --gid=0
  client := Client --hostname="browser-node.local" --service=browser.connect-locally

  try:
    sleep (Duration --ms=3000)
    instances := client.browse "_clock._tcp" --timeout=(Duration --s=3)
    print "  Discovered instances: $instances"
    expect (instances.contains "ClockOne._clock._tcp.local")
    expect (instances.contains "ClockTwo._clock._tcp.local")
    print "  PASS"
  finally:
    client.close
    p1.close
    p2.close
    browser.close
