import expect show *
import net
import net.udp
import net.modules.dns

import mdns.net.mdns_socket show MdnsSocket
import mdns.server.conflict_manager show ConflictManager
import mdns.server.state_manager show StateManager
import mdns.net.dns_helper as dns-helper
import .e2e_param show TEST-PORT

main:
  test-same-ip-no-conflict
  test-authoritative-response-conflict
  test-tiebreak-we-win
  test-tiebreak-we-lose

/**
When we receive an authoritative response with the SAME IP as ours,
it's not a conflict (could be a proxy or echo). No rename expected.
*/
test-same-ip-no-conflict:
  print "Test: No conflict for same IP..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  hostname := "tiebreak.local"
  local-ip := net.IpAddress.parse "192.168.1.50"

  sm := StateManager socket cm hostname local-ip --expected-port=TEST-PORT
  sm.start
  // Allow probing to start (jitter + first probe).
  sleep (Duration --ms=300)

  // Inject authoritative response with same IP — not a conflict.
  answers := [dns.AResource hostname 120 local-ip --flush=true]
  packet := dns.create-dns-packet [] answers --id=0 --is-response=true --is-authoritative=true
  sm.process-packet packet

  expect-equals hostname sm.hostname
  sm.stop
  socket.close
  print "  PASS"

/**
When we receive an authoritative response with a DIFFERENT IP,
we must rename (standard conflict).
*/
test-authoritative-response-conflict:
  print "Test: Conflict on different IP..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  hostname := "tiebreak.local"
  local-ip := net.IpAddress.parse "192.168.1.50"

  sm := StateManager socket cm hostname local-ip --expected-port=TEST-PORT
  sm.start
  sleep (Duration --ms=300)

  other-ip := net.IpAddress.parse "192.168.1.99"
  answers := [dns.AResource hostname 120 other-ip --flush=true]
  packet := dns.create-dns-packet [] answers --id=0 --is-response=true --is-authoritative=true
  sm.process-packet packet

  expect-equals "tiebreak-2.local" sm.hostname
  sm.stop
  socket.close
  print "  PASS"

/**
Simultaneous probe tiebreaking: our IP is lexicographically LATER
than theirs. We win and should NOT defer.

Our IP:   192.168.1.200 (later)
Their IP: 192.168.1.50  (earlier)
*/
test-tiebreak-we-win:
  print "Test: Tiebreak we win (our IP is higher)..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  hostname := "probe.local"
  local-ip := net.IpAddress.parse "192.168.1.200"

  sm := StateManager socket cm hostname local-ip --expected-port=TEST-PORT
  sm.start
  sleep (Duration --ms=300)

  // Simulate receiving a probe (query with Authority Section) from a
  // host with a LOWER IP. We should ignore it (we win tiebreak).
  their-ip := net.IpAddress.parse "192.168.1.50"
  questions := [dns.Question hostname dns.RECORD-ANY]
  authorities := [dns.AResource hostname 120 their-ip]
  packet := dns.create-dns-packet questions []
      --id=0
      --is-response=false
      --authorities=authorities
  sm.process-packet packet

  // We win — no rename, no deferral.
  expect-equals hostname sm.hostname
  sm.stop
  socket.close
  print "  PASS"

/**
Simultaneous probe tiebreaking: our IP is lexicographically EARLIER
than theirs. We lose and should defer (wait 1s, then re-probe).

Our IP:   192.168.1.50  (earlier — we lose)
Their IP: 192.168.1.200 (later — they win)
*/
test-tiebreak-we-lose:
  print "Test: Tiebreak we lose (our IP is lower)..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  hostname := "probe.local"
  local-ip := net.IpAddress.parse "192.168.1.50"

  sm := StateManager socket cm hostname local-ip --expected-port=TEST-PORT
  sm.start
  sleep (Duration --ms=300)

  // Simulate receiving a probe from a host with a HIGHER IP.
  // We lose the tiebreak — should defer (not rename immediately,
  // but wait 1 second and re-probe, at which point the winner
  // will have claimed the name and we'll see their response).
  their-ip := net.IpAddress.parse "192.168.1.200"
  questions := [dns.Question hostname dns.RECORD-ANY]
  authorities := [dns.AResource hostname 120 their-ip]
  packet := dns.create-dns-packet questions []
      --id=0
      --is-response=false
      --authorities=authorities
  sm.process-packet packet

  // Right after losing a tiebreak, the hostname should NOT have changed yet.
  // The host defers by waiting 1s and re-probing (RFC 6762 Section 8.2).
  // The rename only happens when the re-probe gets a response conflict.
  expect-equals hostname sm.hostname

  sm.stop
  socket.close
  print "  PASS"
