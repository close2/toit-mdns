/**
Regression tests for Phases 5–7 of the 2026-11 audit.
*/

import net
import net.modules.dns
import mdns.api.mdns-service show MdnsService
import mdns.client show Client LocalMdnsClient
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

LOCAL-IP ::= net.IpAddress.parse "127.0.0.1"
PEER-IP ::= net.IpAddress.parse "127.0.0.2"
CASE-TIMEOUT ::= Duration --s=12

next-port_ := TEST-PORT
failures_ := []

main:
  check "s3-off-link-filter-and-unicast-ratelimit": test-off-link-filter-and-unicast-ratelimit it
  check "f4-close-closes-network": test-close-closes-network it
  check "p5-ip-refresh-goodbye-and-reprobe": test-ip-refresh-goodbye-and-reprobe it
  check "f5-lookup-throws-dns-exception": test-lookup-throws-dns-exception it
  check "f6a-constructor-cleans-up": test-constructor-cleans-up it
  check "f6b-close-wakes-pending-lookup": test-close-wakes-pending-lookup it
  check "f6c-rename-rekeys-managers": test-rename-rekeys-managers it
  check "f6d-non-local-lookup-rejected": test-non-local-lookup-rejected it
  check "f6f-goodbye-not-returned": test-goodbye-not-returned it
  check "f6g-binary-txt-known-answer": test-binary-txt-known-answer it
  check "p7-shared-ptr-delayed": test-shared-ptr-delayed it
  check "p7-duplicate-ptr-suppressed": test-duplicate-ptr-suppressed it
  check "p7-a-includes-nsec-additional": test-a-includes-nsec-additional it

  if not failures_.is-empty:
    print "FAILED: $failures_"
    exit 1
  print "All P5-P7 audit regression cases passed."
  exit 0

check name/string [block] -> none:
  port := next-port_++
  e := catch --trace=true:
    with-timeout CASE-TIMEOUT: block.call port
  if e:
    print "FAIL  $name"
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

with-client port/int hostname/string [block] -> none:
  provider := MdnsServiceProvider --port=port --local-ip=LOCAL-IP
  client := Client --hostname=hostname --service=provider.connect-locally
  try:
    block.call client provider
  finally:
    client.close
    provider.close

expect-throws [block] -> any:
  e := catch: block.call
  if not e: throw "expected an exception"
  return e

test-off-link-filter-and-unicast-ratelimit port/int:
  local := net.IpAddress.parse "192.168.1.50"
  assert-true_ (not (ip-scope.is-local-source (net.IpAddress.parse "8.8.8.8") local))
  assert-true_ (ip-scope.is-local-source (net.IpAddress.parse "10.99.0.1") local)
  assert-true_ (ip-scope.is-local-source (net.IpAddress.parse "127.0.0.1") local)
  assert-true_ (ip-scope.is-local-source (net.IpAddress.parse "169.254.1.2") local)
  assert-true_ (not (ip-scope.is-local-source (net.IpAddress.parse "10.99.0.1") local --prefix-length=24))
  assert-true_ (not (ip-scope.is-local-source (net.IpAddress.parse "192.168.2.1") local --prefix-length=24))
  assert-true_ (ip-scope.is-local-source (net.IpAddress.parse "192.168.1.99") local --prefix-length=24)

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
  n1 := net.open
  s1 := MdnsSocket --network=n1 --port=port
  s1.close
  expect-throws: n1.udp-open --port=0

  n2 := net.open
  s2 := MdnsSocket --network=n2 --port=port --no-owns-network
  s2.close
  u := n2.udp-open --port=0
  u.close
  n2.close

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

test-lookup-throws-dns-exception port/int:
  with-client port "lookup-host.local": | client/Client _ |
    e := expect-throws:
      client.dns-lookup "missing-f5.local" --timeout=(Duration --ms=300)
    assert-true_ e is dns.DnsException --message="got $e"

test-constructor-cleans-up port/int:
  expect-throws: LocalMdnsClient --hostname="invalid-host"
  provider := MdnsServiceProvider --port=port
  provider.install
  try:
    expect-throws: Client --hostname="no-local-suffix"
    assert-true_ provider.managers_.is-empty
  finally:
    provider.close
    provider.uninstall

test-close-wakes-pending-lookup port/int:
  provider := MdnsServiceProvider --port=port --local-ip=LOCAL-IP
  started := Time.monotonic-us
  done-ms := -1
  task::
    provider.lookup "never-answers.local" --accept-ipv4=true --accept-ipv6=false --timeout-us=20_000_000
    done-ms = (Time.monotonic-us - started) / 1000
  sleep --ms=100
  provider.close
  deadline := Time.monotonic-us + 1_000_000
  while done-ms < 0 and Time.monotonic-us < deadline:
    sleep --ms=20
  assert-true_ (0 <= done-ms < 1000) --message="lookup did not wake promptly on close (done-ms=$done-ms)"

test-rename-rekeys-managers port/int:
  provider := MdnsServiceProvider --port=port --local-ip=LOCAL-IP
  c1 := Client --hostname="rekey.local" --service=provider.connect-locally
  try:
    m/StateManager := provider.managers_["rekey.local"]
    sleep --ms=350
    conflict := dns-helper.encode-mdns-packet [] [
      dns.AResource "rekey.local" 120 (net.IpAddress.parse "10.0.0.88") --flush,
    ] --is-response
    m.process-packet (dns-helper.parse conflict) --source=(net.SocketAddress PEER-IP port)
    assert-equals_ "rekey-2.local" c1.hostname
    assert-true_ (not (provider.managers_.contains "rekey.local"))
    assert-true_ (provider.managers_.contains "rekey-2.local")

    c2 := Client --hostname="rekey-2.local" --service=provider.connect-locally
    try:
      assert-equals_ 1 provider.managers_.size
    finally:
      c2.close
  finally:
    c1.close
    provider.close

test-non-local-lookup-rejected port/int:
  with-client port "scope-q.local": | client/Client _ |
    e := expect-throws: client.dns-lookup "example.com" --timeout=(Duration --ms=200)
    assert-true_ e is dns.DnsException
    e2 := expect-throws: client.dns-lookup "example.com" --record-types={dns.RECORD-A} --timeout=(Duration --ms=200)
    assert-true_ e2 is dns.DnsException
    e3 := expect-throws: client.dns-lookup "1.0.0.127.in-addr.arpa" --timeout=(Duration --ms=150)
    assert-true_ e3 is dns.DnsException
    assert-true_ ((e3 as dns.DnsException).text.contains "No name record found")

test-goodbye-not-returned port/int:
  socket := MdnsSocket --network=net.open --port=port
  cache := MdnsCache
  engine := QueryEngine socket cache
  try:
    cache.add (dns.AResource "bye-host.local" 120 (net.IpAddress.parse "10.0.0.42") --flush)
    assert-equals_ 1 (engine.lookup "bye-host.local" --record-types=dns.RECORD-A --timeout-us=200_000).size
    cache.add (dns.AResource "bye-host.local" 0 (net.IpAddress.parse "10.0.0.42"))
    res := engine.lookup "bye-host.local" --record-types=dns.RECORD-A --timeout-us=200_000
    assert-true_ res.is-empty --message="goodbye record was returned as positive answer: $res"
  finally:
    engine.close
    socket.close

test-binary-txt-known-answer port/int:
  socket := MdnsSocket --network=net.open --port=port
  sm := StateManager socket ConflictManager "txt-ka.local" LOCAL-IP --expected-port=port
  try:
    entries := sm.build-txt-list_ {"k": #[0x41, 0x42]}
    our-rec := dns.TxtResource "svc._http._tcp.local" 4500 true entries
    wire := dns-helper.encode-mdns-packet [dns.Question "svc._http._tcp.local" dns.RECORD-TXT] [our-rec] --is-response=false
    decoded := dns-helper.parse wire
    assert-true_ (dns-helper.has-known-answer decoded "svc._http._tcp.local" dns.RECORD-TXT 4500 --record=our-rec)
  finally:
    sm.stop
    socket.close

test-shared-ptr-delayed port/int:
  with-manager port "delay-host.local": | manager/StateManager capture/PacketCapture |
    manager.register-service "_http._tcp" 8080 --name="DelayedSvc"
    manager.start
    wait-established manager
    sleep --ms=1100
    capture.clear
    q := dns-helper.encode-mdns-packet [dns.Question "_http._tcp.local" dns.RECORD-PTR] [] --is-response=false
    sent-us := Time.monotonic-us
    manager.process-packet (dns-helper.parse q) --source=(net.SocketAddress PEER-IP port)
    resp := capture.wait-for --timeout=(Duration --ms=600):
      it.is-response and it.mentions "_http._tcp.local"
    assert-not-null_ resp
    delay-ms := (resp.received-us - sent-us) / 1000
    assert-true_ (delay-ms >= 15) --message="shared PTR answered too fast ($(delay-ms)ms)"
    assert-true_ (resp.decoded.additionals.any: it.type == dns.RECORD-SRV)

test-duplicate-ptr-suppressed port/int:
  with-manager port "dup-ptr.local": | manager/StateManager capture/PacketCapture |
    manager.register-service "_http._tcp" 8080 --name="SharedSvc"
    manager.start
    wait-established manager
    sleep --ms=1100
    capture.clear
    q := dns-helper.encode-mdns-packet [dns.Question "_services._dns-sd._udp.local" dns.RECORD-PTR] [] --is-response=false
    manager.process-packet (dns-helper.parse q) --source=(net.SocketAddress PEER-IP port)
    peer-resp := dns-helper.encode-mdns-packet [] [
      dns.StringResource "_services._dns-sd._udp.local" dns.RECORD-PTR 4500 false "_http._tcp.local",
    ] --is-response
    manager.process-packet (dns-helper.parse peer-resp) --source=(net.SocketAddress PEER-IP port)
    suppressed := capture.wait-for --timeout=(Duration --ms=300):
      it.is-response and it.mentions "_services._dns-sd._udp.local"
    assert-null_ suppressed

test-a-includes-nsec-additional port/int:
  with-manager port "nsec-add.local": | manager/StateManager capture/PacketCapture |
    manager.start
    wait-established manager
    sleep --ms=1100
    capture.clear
    q := dns-helper.encode-mdns-packet [dns.Question "nsec-add.local" dns.RECORD-A] [] --is-response=false
    manager.process-packet (dns-helper.parse q) --source=(net.SocketAddress PEER-IP port)
    resp := capture.wait-for --timeout=(Duration --ms=500):
      it.is-response and it.mentions "nsec-add.local"
    assert-not-null_ resp
    assert-true_ (resp.decoded.resources.any: it.type == dns.RECORD-A)
    assert-true_ (resp.decoded.additionals.any: | r |
      r is dns-helper.NsecResource and (r as dns-helper.NsecResource).has-type dns.RECORD-A)

assert-true_ condition/bool --message/string="assertion failed" -> none:
  if not condition: throw "ASSERT: $message"

assert-null_ value -> none:
  if value != null: throw "ASSERT: expected null, got $value"

assert-not-null_ value -> none:
  if value == null: throw "ASSERT: expected a non-null value"

assert-equals_ expected actual -> none:
  if expected != actual: throw "ASSERT: expected $expected, got $actual"
