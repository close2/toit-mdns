/**
Regression tests for the findings of the 2026-11 audit.

Each case asserts the *correct* behavior. Cases whose fix has not landed yet
  are listed in $KNOWN-FAILING: they are expected to fail (XFAIL). When a
  phase fixes a finding, the case starts passing (XPASS), which fails this
  test until the case is removed from $KNOWN-FAILING.
*/

import net
import net.modules.dns
import mdns.api.mdns-service show MdnsService
import mdns.client show Client
import mdns.net.dns-helper as dns-helper
import mdns.net.mdns-socket show MdnsSocket
import mdns.server.cache show MdnsCache
import mdns.server.conflict-manager show ConflictManager
import mdns.server.state-manager show StateManager
import mdns.service show MdnsServiceProvider

import .e2e-param show TEST-PORT
import .support.capture

/** Case names whose fix has not landed yet, with the phase that fixes them. */
KNOWN-FAILING ::= {
  "c1-aaaa-is-not-a-conflict",           // P3.
  "c2-established-conflict-reprobes",    // P3.
  "c3-packets-fit-mtu",                  // P1.
  "f1-invalid-names-rejected",           // P1.
  "f3-dotted-instance-rejected",         // P1.
  "s1-cache-byte-budget",                // P2.
  "s2-nsec-bitmap-bounded",              // P2.
  "s4-cross-hostname-denied",            // P4.
  "s4-no-hijack-on-shared-hostname",     // P4.
  "f2-services-removed-on-close",        // P4.
  "f5-lookup-throws-dns-exception",      // P6.
}

LOCAL-IP ::= net.IpAddress.parse "127.0.0.1"
PEER-IP ::= net.IpAddress.parse "127.0.0.2"
CASE-TIMEOUT ::= Duration --s=12

next-port_ := TEST-PORT
failures_ := []

main:
  check "c1-aaaa-is-not-a-conflict": test-aaaa-is-not-a-conflict it
  check "c2-established-conflict-reprobes": test-established-conflict-reprobes it
  check "c3-packets-fit-mtu": test-packets-fit-mtu it
  check "f1-invalid-names-rejected": test-invalid-names-rejected it
  check "f3-dotted-instance-rejected": test-dotted-instance-rejected it
  check "s1-cache-byte-budget": test-cache-byte-budget it
  check "s2-nsec-bitmap-bounded": test-nsec-bitmap-bounded it
  check "s4-cross-hostname-denied": test-cross-hostname-denied it
  check "s4-no-hijack-on-shared-hostname": test-no-hijack-on-shared-hostname it
  check "f2-services-removed-on-close": test-services-removed-on-close it
  check "f5-lookup-throws-dns-exception": test-lookup-throws-dns-exception it

  if not failures_.is-empty:
    print "FAILED: $failures_"
    exit 1
  print "All audit regression cases behave as expected."
  exit 0

/**
Runs the case $name with a fresh port, handling expected failures.
*/
check name/string [block] -> none:
  port := next-port_++
  expected-fail := KNOWN-FAILING.contains name
  e := catch --trace=(not expected-fail):
    with-timeout CASE-TIMEOUT: block.call port
  if e and expected-fail:
    print "XFAIL $name ($e)"
  else if e:
    print "FAIL  $name"
    failures_.add name
  else if expected-fail:
    print "XPASS $name: remove it from KNOWN-FAILING"
    failures_.add name
  else:
    print "PASS  $name"

wait-established manager/StateManager -> none:
  deadline := Time.monotonic-us + 5_000_000
  while manager.state_ != StateManager.STATE-ESTABLISHED:
    if Time.monotonic-us > deadline: throw "manager never reached ESTABLISHED"
    sleep --ms=50

with-manager port/int hostname/string [block] -> none:
  capture := PacketCapture --port=port
  socket := MdnsSocket --network=net.open --port=port
  manager := StateManager socket ConflictManager hostname LOCAL-IP --expected-port=port
  try:
    block.call manager capture
  finally:
    manager.stop
    socket.close
    capture.close

with-provider port/int [block] -> none:
  provider := MdnsServiceProvider --port=port --local-ip=LOCAL-IP
  try:
    block.call provider
  finally:
    provider.close

expect-throws [block] -> any:
  e := catch: block.call
  if not e: throw "expected an exception"
  return e

// --- P3: conflict semantics. ---

test-aaaa-is-not-a-conflict port/int:
  with-manager port "aaaa-host.local": | manager/StateManager capture/PacketCapture |
    manager.start
    wait-established manager
    sleep --ms=300  // Let the announcement rate-limit window pass.
    capture.clear
    v6 := net.IpAddress (#[0xfe, 0x80] + (ByteArray 13) + #[1])
    packet := dns-helper.encode-mdns-packet [] [dns.AResource "aaaa-host.local" 120 v6 --flush] --is-response
    manager.process-packet (dns-helper.parse packet) --source=(net.SocketAddress PEER-IP port)
    reaction := capture.wait-for --timeout=(Duration --ms=700): it.mentions "aaaa-host.local"
    assert-null_ reaction
    assert-equals_ "aaaa-host.local" manager.hostname

test-established-conflict-reprobes port/int:
  with-manager port "reprobe-host.local": | manager/StateManager capture/PacketCapture |
    manager.start
    wait-established manager
    capture.clear
    other := net.IpAddress.parse "10.66.66.66"
    packet := dns-helper.encode-mdns-packet [] [dns.AResource "reprobe-host.local" 120 other --flush] --is-response
    manager.process-packet (dns-helper.parse packet) --source=(net.SocketAddress PEER-IP port)
    // RFC 6762 §9: reset to probing, keeping the name.
    probe := capture.wait-for --timeout=(Duration --ms=1500): it.is-probe-for "reprobe-host.local"
    assert-not-null_ probe
    assert-equals_ "reprobe-host.local" manager.hostname

// --- P1: validation and packet size. ---

test-packets-fit-mtu port/int:
  with-manager port "big-host.local": | manager/StateManager capture/PacketCapture |
    10.repeat: | i |
      manager.register-service "_http._tcp" (8000 + i) --name="svc-$i" --txt={"d": "x" * 400}
    manager.start
    wait-established manager
    responses := capture.filter: it.is-response and it.mentions "big-host.local"
    assert-true_ (not responses.is-empty)
    responses.do: | p/CapturedPacket |
      assert-true_ p.data.size <= 1440 --message="packet of $p.data.size bytes exceeds 1440"
    10.repeat: | i |
      seen := responses.any: | p/CapturedPacket | p.mentions "svc-$i._http._tcp.local"
      assert-true_ seen --message="svc-$i never announced"

with-client port/int hostname/string [block] -> none:
  with-provider port: | provider/MdnsServiceProvider |
    client := Client --hostname=hostname --service=provider.connect-locally
    try:
      block.call client provider
    finally:
      client.close

test-invalid-names-rejected port/int:
  with-client port "names-host.local": | client/Client _ |
    expect-throws: client.register-service "_http._tcp" 80 --name=("x" * 64)
    expect-throws: client.register-service "http" 80 --name="ok"
    expect-throws: client.register-service "_waytoolongservicename._tcp" 80 --name="ok"
    expect-throws: client.register-service "_http._tcp" 80 --name="ok" --txt={"a=b": "c"}
    expect-throws: client.register-service "_http._tcp" 80 --name="ok" --txt={"k": "v" * 300}
    expect-throws: client.set-hostname "$("h" * 64).local"

test-dotted-instance-rejected port/int:
  with-client port "dots-host.local": | client/Client _ |
    expect-throws: client.register-service "_http._tcp" 80 --name="Living Room v1.2"

// --- P2: memory. ---

test-cache-byte-budget port/int:
  cache := MdnsCache
  big := "v" * 250
  64.repeat: | k |
    32.repeat: | e |
      cache.add (dns.TxtResource "key$(k).local" 4500 false (List 5: "k$(it)-$(e)=$big"))
  payload := 0
  cache.records_.do: | _ entries/List |
    entries.do: | entry |
      (entry.record as dns.TxtResource).text.do: payload += it.size
  assert-true_ payload <= 16_384 --message="cache retains $payload bytes of TXT payload"

test-nsec-bitmap-bounded port/int:
  rdata := #[0xc0, 12]
  40.repeat: | w |
    rdata += #[w, 32] + (ByteArray 32 --initial=0xff)
  header := #[0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0]
  owner := #[4] + "evil".to-byte-array + #[5] + "local".to-byte-array + #[0]
  fixed := #[0, 47, 0, 1, 0, 0, 0, 120, rdata.size >> 8, rdata.size & 0xff]
  decoded := dns-helper.parse header + owner + fixed + rdata
  nsec := decoded.resources[0] as dns-helper.NsecResource
  assert-true_ nsec.types.size <= 256 --message="NSEC decoded to $nsec.types.size entries"
  assert-true_ (nsec.has-type dns.RECORD-A)

// --- P4: ownership. ---

client-id_ service/any -> int:
  return service.client-id_

test-cross-hostname-denied port/int:
  with-provider port: | provider/MdnsServiceProvider |
    owner := provider.connect-locally
    owner.set-hostname "owner-a.local"
    intruder := provider.connect-locally
    intruder.set-hostname "intruder-b.local"
    e := expect-throws:
      provider.handle MdnsService.REGISTER-INDEX
          ["_http._tcp", 80, null, "Hijack", "owner-a.local"]
          --gid=0
          --client=(client-id_ intruder)
    assert-true_ (e.to-string.contains "PERMISSION_DENIED") --message="unexpected error $e"
    owner.close
    intruder.close

test-no-hijack-on-shared-hostname port/int:
  with-provider port: | provider/MdnsServiceProvider |
    owner := Client --hostname="shared-h.local" --service=provider.connect-locally
    other := Client --hostname="shared-h.local" --service=provider.connect-locally
    try:
      owner.register-service "_http._tcp" 80 --name="Shared"
      expect-throws: other.register-service "_http._tcp" 9999 --name="Shared"
    finally:
      owner.close
      other.close

test-services-removed-on-close port/int:
  with-provider port: | provider/MdnsServiceProvider |
    a := Client --hostname="shared-f2.local" --service=provider.connect-locally
    b := Client --hostname="shared-f2.local" --service=provider.connect-locally
    try:
      a.register-service "_http._tcp" 80 --name="FromA"
      a.close
      manager/StateManager := provider.managers_["shared-f2.local"]
      assert-equals_ 0 manager.services-count
    finally:
      b.close

// --- P6: client API. ---

test-lookup-throws-dns-exception port/int:
  with-client port "lookup-host.local": | client/Client _ |
    e := expect-throws:
      client.dns-lookup "missing-f5.local" --timeout=(Duration --ms=300)
    assert-true_ e is dns.DnsException --message="got $e"

// --- Non-exiting assertions (the `expect` library exits the process). ---

assert-true_ condition/bool --message/string="assertion failed" -> none:
  if not condition: throw "ASSERT: $message"

assert-null_ value -> none:
  if value != null: throw "ASSERT: expected null, got $value"

assert-not-null_ value -> none:
  if value == null: throw "ASSERT: expected a non-null value"

assert-equals_ expected actual -> none:
  if expected != actual: throw "ASSERT: expected $expected, got $actual"
