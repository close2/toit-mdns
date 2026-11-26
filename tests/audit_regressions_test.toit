/**
Regression tests for the findings of the 2026-11 audit.

Each case asserts the *correct* behavior. Cases whose fix has not landed yet
  are listed in $KNOWN-FAILING: they are expected to fail (XFAIL). When a
  phase fixes a finding, the case starts passing (XPASS), which fails this
  test until the case is removed from $KNOWN-FAILING.
*/

import net
import net.modules.dns
import system
import mdns.api.mdns-service show MdnsService
import mdns.client show Client
import mdns.net.dns-helper as dns-helper
import mdns.net.ip-scope as ip-scope
import mdns.net.mdns-socket show MdnsSocket
import mdns.server.cache show MdnsCache
import mdns.server.conflict-manager show ConflictManager
import mdns.server.query-engine show QueryEngine
import mdns.server.state-manager show StateManager
import mdns.service show MdnsServiceProvider

import .e2e-param show TEST-PORT
import .support.capture

/** Case names whose fix has not landed yet, with the phase that fixes them. */
KNOWN-FAILING ::= {
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
  check "c2-two-established-only-one-renames": test-two-established-only-one-renames it
  check "c4-service-tiebreak-defers": test-service-tiebreak-defers it
  check "c7-txt-update-announces-no-probe": test-txt-update-announces-no-probe it
  check "c3-packets-fit-mtu": test-packets-fit-mtu it
  check "c3-ka-query-splits-with-tc": test-ka-query-splits-with-tc it
  check "f1-invalid-names-rejected": test-invalid-names-rejected it
  check "f3-dotted-instance-rejected": test-dotted-instance-rejected it
  check "s1-cache-byte-budget": test-cache-byte-budget it
  check "s1-narrow-caching-drops-unrelated": test-narrow-caching-drops-unrelated it
  check "s2-nsec-bitmap-bounded": test-nsec-bitmap-bounded it
  check "s2-nsec-rejects-non-increasing-windows": test-nsec-rejects-non-increasing-windows it
  check "p2-low-alloc-packet-processing": test-process-packet-low-alloc it
  check "s4-cross-hostname-denied": test-cross-hostname-denied it
  check "s4-no-hijack-on-shared-hostname": test-no-hijack-on-shared-hostname it
  check "s4-service-quota-and-rpc-validation": test-service-quota-and-rpc-validation it
  check "f2-services-removed-on-close": test-services-removed-on-close it
  check "f2-unregister-service-sends-goodbye": test-unregister-service-sends-goodbye it
  check "s3-off-link-filter-and-unicast-ratelimit": test-off-link-filter-and-unicast-ratelimit it
  check "f4-close-closes-network": test-close-closes-network it
  check "p5-ip-refresh-goodbye-and-reprobe": test-ip-refresh-goodbye-and-reprobe it
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

test-two-established-only-one-renames port/int:
  p1 := MdnsServiceProvider --port=port --local-ip=(net.IpAddress.parse "127.0.0.10")
  p2 := MdnsServiceProvider --port=port --local-ip=(net.IpAddress.parse "127.0.0.20")
  try:
    p1.handle MdnsService.SET-HOSTNAME-INDEX "clash.local" --client=1 --gid=0
    p2.handle MdnsService.SET-HOSTNAME-INDEX "clash.local" --client=2 --gid=0
    m1/StateManager := p1.managers_["clash.local"]
    m2/StateManager := p2.managers_["clash.local"]
    deadline := Time.monotonic-us + 6_000_000
    while (m1.state_ != StateManager.STATE-ESTABLISHED or m2.state_ != StateManager.STATE-ESTABLISHED):
      if Time.monotonic-us > deadline: throw "managers did not settle"
      sleep --ms=50
    names := {m1.hostname, m2.hostname}
    assert-true_ (names.contains "clash.local") --message="neither kept clash.local: $names"
    assert-true_ (names.contains "clash-2.local") --message="neither renamed to clash-2.local: $names"
  finally:
    p1.close
    p2.close

test-service-tiebreak-defers port/int:
  with-manager port "tie-svc.local": | manager/StateManager capture/PacketCapture |
    manager.register-service "_http._tcp" 80 --name="MySvc"
    manager.start
    sleep --ms=300  // Ensure probing has started.
    capture.clear
    // Send a probe for the same service with a higher SRV port (wins tiebreak).
    q := [dns.Question "MySvc._http._tcp.local" dns.RECORD-ANY --unicast-ok]
    auth := [
      dns.SrvResource "MySvc._http._tcp.local" dns.RECORD-SRV 120 false "other.local" 0 0 9090,
      dns.TxtResource "MySvc._http._tcp.local" 4500 false [""],
    ]
    probe-pkt := dns-helper.encode-mdns-packet q [] --is-response=false --authorities=auth
    manager.process-packet (dns-helper.parse probe-pkt) --source=(net.SocketAddress PEER-IP port)
    // Must defer (not rename immediately) and re-probe after ~1s with the same name.
    assert-equals_ StateManager.STATE-PROBING manager.state_
    early := capture.wait-for --timeout=(Duration --ms=600): it.is-probe-for "MySvc._http._tcp.local"
    assert-null_ early
    reprobe := capture.wait-for --timeout=(Duration --ms=1200): it.is-probe-for "MySvc._http._tcp.local"
    assert-not-null_ reprobe

test-txt-update-announces-no-probe port/int:
  with-manager port "txt-upd.local": | manager/StateManager capture/PacketCapture |
    manager.register-service "_http._tcp" 80 --name="App" --txt={"v": "1"}
    manager.start
    wait-established manager
    capture.clear
    manager.register-service "_http._tcp" 80 --name="App" --txt={"v": "2"}
    // Must reach ESTABLISHED via 2 announcements without sending any probe.
    sleep --ms=1300
    assert-equals_ StateManager.STATE-ESTABLISHED manager.state_
    probes := capture.filter: it.is-probe
    assert-true_ probes.is-empty --message="TXT update must not probe"
    ann := capture.filter: it.is-response and (it.mentions "App._http._tcp.local")
    assert-true_ ann.size >= 2 --message="expected 2 announcements, got $ann.size"

// --- P1: validation and packet size. ---

test-packets-fit-mtu port/int:
  with-manager port "big-host.local": | manager/StateManager capture/PacketCapture |
    10.repeat: | i |
      manager.register-service "_http._tcp" (8000 + i) --name="svc-$i" --txt={"d1": "x" * 200, "d2": "y" * 200}
    manager.start
    wait-established manager
    probes := capture.filter: it.is-probe
    assert-true_ (not probes.is-empty) --message="no probes captured"
    probes.do: | p/CapturedPacket |
      assert-true_ p.data.size <= 1440 --message="probe packet of $p.data.size bytes exceeds 1440"
    responses := capture.filter: it.is-response
    assert-true_ (not responses.is-empty)
    responses.do: | p/CapturedPacket |
      assert-true_ p.data.size <= 1440 --message="packet of $p.data.size bytes exceeds 1440"
    10.repeat: | i |
      seen := responses.any: | p/CapturedPacket | p.mentions "svc-$(i)._http._tcp.local"
      assert-true_ seen --message="svc-$i never announced"

test-ka-query-splits-with-tc port/int:
  questions := [dns.Question "_http._tcp.local" dns.RECORD-PTR]
  known := List 25: | i |
    dns.StringResource "_http._tcp.local" dns.RECORD-PTR 4500 false "svc-$(i)-with-padding._http._tcp.local"
  packets := dns-helper.encode-mdns-packets questions known --is-response=false --max-size=300
  assert-true_ packets.size >= 2 --message="expected split query packets"
  packets.size.repeat: | i |
    pkt := packets[i] as ByteArray
    assert-true_ pkt.size <= 300 --message="query packet $i is $pkt.size > 300"
    decoded := dns-helper.parse pkt
    is-last := i == packets.size - 1
    assert-equals_ (not is-last) decoded.is-truncated

with-client port/int hostname/string [block] -> none:
  with-provider port: | provider/MdnsServiceProvider |
    client := Client --hostname=hostname --service=provider.connect-locally
    try:
      block.call client provider
    finally:
      client.close

test-invalid-names-rejected port/int:
  with-client port "names-host.local": | client/Client provider/MdnsServiceProvider |
    // Instance name errors.
    expect-throws: client.register-service "_http._tcp" 80 --name=("x" * 64)
    expect-throws: client.register-service "_http._tcp" 80 --name=""
    expect-throws: client.register-service "_http._tcp" 80 --name="bad\nname"
    // Service type errors.
    expect-throws: client.register-service "http" 80 --name="ok"
    expect-throws: client.register-service "_http._tcp.local" 80 --name="ok"
    expect-throws: client.register-service "_waytoolongservicename._tcp" 80 --name="ok"
    expect-throws: client.register-service "_123._tcp" 80 --name="ok"
    expect-throws: client.register-service "_-bad._tcp" 80 --name="ok"
    expect-throws: client.register-service "_bad-._tcp" 80 --name="ok"
    expect-throws: client.register-service "_bad_svc._tcp" 80 --name="ok"
    // TXT errors.
    expect-throws: client.register-service "_http._tcp" 80 --name="ok" --txt={"a=b": "c"}
    expect-throws: client.register-service "_http._tcp" 80 --name="ok" --txt={"": "c"}
    expect-throws: client.register-service "_http._tcp" 80 --name="ok" --txt={"Key": "1", "key": "2"}
    expect-throws: client.register-service "_http._tcp" 80 --name="ok" --txt={"k": "v" * 300}
    big-txt := {:}
    6.repeat: | i | big-txt["k$i"] = "v" * 210
    expect-throws: client.register-service "_http._tcp" 80 --name="ok" --txt=big-txt
    // Hostname errors (both Client and direct RPC).
    expect-throws: client.set-hostname "$("h" * 64).local"
    expect-throws: client.set-hostname "a.b.local"
    expect-throws: client.set-hostname "no-suffix"
    expect-throws:
      provider.handle MdnsService.SET-HOSTNAME-INDEX "bad..local" --client=99 --gid=0
    expect-throws:
      provider.handle MdnsService.REGISTER-INDEX ["badtype", 80, null, "ok", "names-host.local"] --client=99 --gid=0
    // Verify the valid hostname kept working and was not poisoned.
    assert-equals_ "names-host.local" client.hostname
    sleep --ms=2200
    ips := provider.lookup "names-host.local" --accept-ipv4=true --accept-ipv6=false --timeout-us=1_000_000
    assert-true_ (not ips.is-empty)

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
  assert-true_ cache.bytes <= 16_384 --message="cache.bytes $cache.bytes exceeds 16384"

test-narrow-caching-drops-unrelated port/int:
  socket := MdnsSocket --network=net.open --port=port
  cache := MdnsCache
  engine := QueryEngine socket cache
  try:
    t := task::
      engine.lookup "_http._tcp.local" --record-types=dns.RECORD-PTR --timeout-us=1_500_000
    sleep --ms=50  // Wait until lookup is registered in pending_.
    // Packet carries: PTR for _http._tcp.local -> app._http._tcp.local,
    // SRV for app -> app.local, A for app.local, AND unrelated spam.local.
    pkt := dns-helper.encode-mdns-packet [] [
      dns.StringResource "_http._tcp.local" dns.RECORD-PTR 4500 false "app._http._tcp.local",
    ] --is-response --additionals=[
      dns.SrvResource "app._http._tcp.local" dns.RECORD-SRV 120 true "app.local" 0 0 8080,
      dns.AResource "app.local" 120 (net.IpAddress.parse "10.0.0.5") --flush,
      dns.TxtResource "spam.local" 4500 false ["k=" + ("x" * 200)],
      dns.AResource "spam.local" 120 (net.IpAddress.parse "10.0.0.99") --flush,
    ]
    engine.process-packet (dns-helper.parse pkt)
    sleep --ms=450  // Wait for browse aggregation to finish.
    assert-equals_ 1 (cache.lookup "_http._tcp.local" dns.RECORD-PTR).size
    assert-equals_ 1 (cache.lookup "app._http._tcp.local" dns.RECORD-SRV).size
    assert-equals_ 1 (cache.lookup "app.local" dns.RECORD-A).size
    assert-equals_ 0 (cache.lookup "spam.local" dns.RECORD-TXT).size
    assert-equals_ 0 (cache.lookup "spam.local" dns.RECORD-A).size
  finally:
    socket.close

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

test-nsec-rejects-non-increasing-windows port/int:
  // Window 1 followed by window 0 violates RFC 4034 §4.1.2.
  rdata := #[0xc0, 12, 1, 1, 0x80, 0, 1, 0x40]
  header := #[0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0]
  owner := #[4] + "evil".to-byte-array + #[5] + "local".to-byte-array + #[0]
  fixed := #[0, 47, 0, 1, 0, 0, 0, 120, rdata.size >> 8, rdata.size & 0xff]
  expect-throws: dns-helper.parse header + owner + fixed + rdata

test-process-packet-low-alloc port/int:
  with-manager port "alloc-host.local": | manager/StateManager _ |
    3.repeat: | i |
      manager.register-service "_http._tcp" (8000 + i) --name="svc-$i"
    manager.start
    wait-established manager
    pkt := dns-helper.encode-mdns-packet [dns.Question "unrelated-peer.local" dns.RECORD-A] [] --is-response=false
    decoded := dns-helper.parse pkt
    src := net.SocketAddress PEER-IP port
    // Warm up once, then process 1,000 unrelated queries.
    manager.process-packet decoded --source=src
    before := (system.process-stats)[system.STATS-INDEX-BYTES-ALLOCATED-IN-OBJECT-HEAP]
    1000.repeat:
      manager.process-packet decoded --source=src
    after := (system.process-stats)[system.STATS-INDEX-BYTES-ALLOCATED-IN-OBJECT-HEAP]
    delta := after - before
    assert-true_ delta < 64_000 --message="1000 unrelated packets allocated $delta bytes"

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
  capture := PacketCapture --port=port
  provider := MdnsServiceProvider --port=port --local-ip=LOCAL-IP
  a := Client --hostname="shared-f2.local" --service=provider.connect-locally
  b := Client --hostname="shared-f2.local" --service=provider.connect-locally
  try:
    a.register-service "_http._tcp" 80 --name="FromA"
    manager/StateManager := provider.managers_["shared-f2.local"]
    wait-established manager
    capture.clear
    a.close
    assert-equals_ 0 manager.services-count
    goodbye := capture.wait-for --timeout=(Duration --ms=1000): | p/CapturedPacket |
      p.is-response and p.all-records.any: | r/dns.Resource |
        r.ttl == 0 and (dns-helper.name-equals r.name "FromA._http._tcp.local")
    assert-not-null_ goodbye
  finally:
    a.close
    b.close
    provider.close
    capture.close

test-unregister-service-sends-goodbye port/int:
  capture := PacketCapture --port=port
  provider := MdnsServiceProvider --port=port --local-ip=LOCAL-IP
  client := Client --hostname="unreg-f2.local" --service=provider.connect-locally
  try:
    client.register-service "_http._tcp" 8080 --name="TempSvc"
    manager/StateManager := provider.managers_["unreg-f2.local"]
    wait-established manager
    capture.clear
    assert-true_ (client.unregister-service "_http._tcp" --name="tempsvc")
    assert-true_ (not (client.unregister-service "_http._tcp" --name="TempSvc"))
    assert-equals_ 0 manager.services-count
    goodbye := capture.wait-for --timeout=(Duration --ms=1000): | p/CapturedPacket |
      p.is-response and p.all-records.any: | r/dns.Resource |
        r.ttl == 0 and (dns-helper.name-equals r.name "TempSvc._http._tcp.local")
    assert-not-null_ goodbye
  finally:
    client.close
    provider.close
    capture.close

test-service-quota-and-rpc-validation port/int:
  with-client port "quota-host.local": | client/Client provider/MdnsServiceProvider |
    8.repeat: | i |
      client.register-service "_http._tcp" (8000 + i) --name="svc-$i"
    e := expect-throws:
      client.register-service "_http._tcp" 8099 --name="svc-9th"
    assert-true_ (e.to-string.contains "QUOTA_EXCEEDED") --message="unexpected $e"
    // Verify RPC argument validation rejects bad types/sizes/ports.
    expect-throws: provider.handle MdnsService.LOOKUP-INDEX "not-a-list" --client=1 --gid=0
    expect-throws: provider.handle MdnsService.LOOKUP-INDEX ["a.local", "not-bool", false, 100] --client=1 --gid=0
    expect-throws: provider.handle MdnsService.REGISTER-INDEX ["_http._tcp", 70000, null, "badport"] --client=1 --gid=0
    expect-throws: provider.handle MdnsService.UNREGISTER-INDEX [123, null] --client=1 --gid=0

test-off-link-filter-and-unicast-ratelimit port/int:
  local := net.IpAddress.parse "192.168.1.50"
  // Tier A: rejects public IP when local-ip is private, allows private/loopback.
  assert-true_ (not (ip-scope.is-local-source (net.IpAddress.parse "8.8.8.8") local))
  assert-true_ (ip-scope.is-local-source (net.IpAddress.parse "10.99.0.1") local)
  assert-true_ (ip-scope.is-local-source (net.IpAddress.parse "127.0.0.1") local)
  assert-true_ (ip-scope.is-local-source (net.IpAddress.parse "169.254.1.2") local)
  // Tier B: strict /24 prefix rejects 10.99.0.1 and 192.168.2.1, allows 192.168.1.99.
  assert-true_ (not (ip-scope.is-local-source (net.IpAddress.parse "10.99.0.1") local --prefix-length=24))
  assert-true_ (not (ip-scope.is-local-source (net.IpAddress.parse "192.168.2.1") local --prefix-length=24))
  assert-true_ (ip-scope.is-local-source (net.IpAddress.parse "192.168.1.99") local --prefix-length=24)

  // End-to-end on StateManager with Tier B and legacy unicast rate limit (4/sec).
  network := net.open
  real-local := network.address
  off-prefix := net.IpAddress #[real-local.raw[0] ^ 1, 99, 0, 1]
  socket := MdnsSocket --network=network --port=port
  sink := network.udp-open --port=0
  sink-port := sink.local-address.port
  manager := StateManager socket ConflictManager "scope-host.local" real-local
      --expected-port=port
      --local-prefix-length=24
  try:
    manager.start
    wait-established manager
    q := dns-helper.encode-mdns-packet [dns.Question "scope-host.local" dns.RECORD-A] [] --id=0x1111 --is-response=false
    decoded := dns-helper.parse q

    // Off-prefix query is dropped; same-prefix real-local is accepted.
    manager.process-packet decoded --source=(net.SocketAddress off-prefix sink-port)
    replies := 0
    done := false
    reader := task::
      while not done:
        err := catch:
          with-timeout (Duration --ms=400):
            sink.receive
            replies++
        if err: break
    6.repeat:
      manager.process-packet decoded --source=(net.SocketAddress real-local sink-port)
    sleep --ms=500
    done = true
    reader.cancel
    assert-equals_ 4 replies
  finally:
    manager.stop
    catch: sink.close
    socket.close

test-close-closes-network port/int:
  // Owns network = true (default): closing MdnsSocket closes the network handle.
  n1 := net.open
  s1 := MdnsSocket --network=n1 --port=port
  s1.close
  expect-throws: n1.udp-open --port=0

  // Owns network = false: closing MdnsSocket leaves the network handle open.
  n2 := net.open
  s2 := MdnsSocket --network=n2 --port=port --no-owns-network
  s2.close
  u := n2.udp-open --port=0
  u.close
  n2.close

  // Repeated provider open/close cycles do not leak handles or fail.
  20.repeat: | i |
    p := MdnsServiceProvider --port=(port + 50 + i)
    p.handle MdnsService.SET-HOSTNAME-INDEX "churn-$(i).local" --client=1 --gid=0
    p.close

test-ip-refresh-goodbye-and-reprobe port/int:
  capture := PacketCapture --port=port
  socket := MdnsSocket --network=net.open --port=port
  old-ip := net.IpAddress.parse "10.0.0.11"
  new-ip := net.IpAddress.parse "10.0.0.22"
  manager := StateManager socket ConflictManager "ipchange.local" old-ip --expected-port=port
  try:
    manager.start
    wait-established manager
    capture.clear
    manager.update-network socket new-ip
    goodbye := capture.wait-for --timeout=(Duration --ms=1000): | p/CapturedPacket |
      p.is-response and p.all-records.any: | r/dns.Resource |
        r.ttl == 0 and r is dns.AResource and (r as dns.AResource).address == old-ip
    assert-not-null_ goodbye
    reprobe := capture.wait-for --timeout=(Duration --ms=1500): it.is-probe-for "ipchange.local"
    assert-not-null_ reprobe
  finally:
    manager.stop
    socket.close
    capture.close

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
