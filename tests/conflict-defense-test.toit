import expect show *
import net
import net.modules.dns
import mdns.private.dns_helper as dns

import mdns.private.mdns_socket show MdnsSocket
import mdns.private.conflict_manager show ConflictManager
import mdns.private.state_manager show StateManager
import .e2e-param show TEST-PORT

main:
  test-reprobe-in-established
  test-reprobe-in-announcing
  test-state-not-clobbered-after-announcing-conflict

test-reprobe-in-established:
  print "Testing RFC 6762 §9 re-probe on conflict in ESTABLISHED state..."

  socket := MdnsSocket --network=net.open --port=TEST-PORT
  conflict-manager := ConflictManager
  hostname := "defend-me.local"
  local-ip := net.IpAddress.parse "127.0.0.1"

  state-manager := StateManager socket conflict-manager hostname local-ip --expected-port=TEST-PORT
  state-manager.start

  sleep (Duration --ms=3000)
  expect-equals StateManager.STATE-ESTABLISHED state-manager.state_

  fake-ip := net.IpAddress.parse "6.6.6.6"
  packet := dns.create-dns-packet [] [dns.AResource hostname 120 fake-ip --flush] --id=0 --is-response --is-authoritative
  state-manager.process-packet (dns.parse packet)

  // RFC 6762 §9: Must immediately reset to probing while keeping the name.
  expect-equals StateManager.STATE-PROBING state-manager.state_
  expect-equals hostname state-manager.hostname

  // A subsequent conflict after the first probe is sent causes a rename.
  sleep (Duration --ms=350)
  state-manager.process-packet (dns.parse packet)
  expect-equals "defend-me-2.local" state-manager.hostname

  state-manager.stop
  socket.close
  print "  PASS"

test-reprobe-in-announcing:
  print "Testing RFC 6762 §9 re-probe on conflict in ANNOUNCING state..."

  socket := MdnsSocket --network=net.open --port=TEST-PORT
  conflict-manager := ConflictManager
  hostname := "announce-defend.local"
  local-ip := net.IpAddress.parse "127.0.0.1"

  state-manager := StateManager socket conflict-manager hostname local-ip --expected-port=TEST-PORT
  state-manager.start

  while state-manager.state_ != StateManager.STATE-ANNOUNCING:
    sleep (Duration --ms=20)

  fake-ip := net.IpAddress.parse "6.6.6.6"
  packet := dns.create-dns-packet [] [dns.AResource hostname 120 fake-ip --flush] --id=0 --is-response --is-authoritative
  state-manager.process-packet (dns.parse packet)

  expect-equals StateManager.STATE-PROBING state-manager.state_
  expect-equals hostname state-manager.hostname

  state-manager.stop
  socket.close
  print "  PASS"

test-state-not-clobbered-after-announcing-conflict:
  // Verify the old enter-announcing_ task does not overwrite STATE-PROBING
  // after a conflict resets the state machine back to probing.
  print "Testing state not clobbered when conflict hits ANNOUNCING..."

  socket := MdnsSocket --network=net.open --port=TEST-PORT
  conflict-manager := ConflictManager
  hostname := "clobber-test.local"
  local-ip := net.IpAddress.parse "127.0.0.1"

  state-manager := StateManager socket conflict-manager hostname local-ip --expected-port=TEST-PORT
  state-manager.start

  while state-manager.state_ != StateManager.STATE-ANNOUNCING:
    sleep (Duration --ms=20)

  fake-ip := net.IpAddress.parse "6.6.6.6"
  packet := dns.create-dns-packet [] [dns.AResource hostname 120 fake-ip --flush] --id=0 --is-response --is-authoritative

  // First conflict resets to PROBING; wait for first probe then send second to rename.
  state-manager.process-packet (dns.parse packet)
  expect-equals StateManager.STATE-PROBING state-manager.state_
  sleep (Duration --ms=350)
  state-manager.process-packet (dns.parse packet)

  // Wait past the old enter-announcing_ 1s sleep window.
  sleep (Duration --ms=1200)

  expect: hostname != state-manager.hostname
  expect: StateManager.STATE-ESTABLISHED != state-manager.state_
  print "  PASS"

  state-manager.stop
  socket.close
