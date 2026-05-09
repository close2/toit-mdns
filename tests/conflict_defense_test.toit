import expect show *
import net
import net.udp
import net.modules.dns 
import mdns.net.dns_helper as dns

import mdns.net.mdns_socket show MdnsSocket
import mdns.server.conflict_manager show ConflictManager
import mdns.server.state_manager show StateManager
import .e2e_param show TEST-PORT

 

main:
  test-defense-in-established
  test-defense-in-announcing
  test-state-not-clobbered-after-announcing-conflict

test-defense-in-established:
  print "Testing defense in ESTABLISHED state..."
  
  // We use a real socket and verify internal state counters
  socket := MdnsSocket --network=net.open --port=TEST-PORT
  conflict-manager := ConflictManager
  hostname := "defend-me.local"
  local-ip := net.IpAddress.parse "127.0.0.1"
  
  state-manager := StateManager socket conflict-manager hostname local-ip --expected-port=TEST-PORT
  
  state-manager.start
  
  // Probing is automatic via task. Wait for it to complete.
  // Jitter (0-250ms) + 3 probes × 250ms + 2 announcements 1s apart = ~2.5s.
  sleep (Duration --ms=3000)
  
  expect-equals StateManager.STATE-ESTABLISHED state-manager.state_
  print "State should be ESTABLISHED now."
  
  // Reset defense count (it might have been used during probing if any conflicts happened, though unlikely in test)
  state-manager.defend-count_ = 0 
  
  // Inject CONFLICT packet
  fake-ip := net.IpAddress.parse "6.6.6.6"
  packet := dns.create-dns-packet [] [dns.AResource hostname 120 fake-ip --flush] --id=0 --is-response --is-authoritative
  
  state-manager.process-packet (dns.parse packet)
  
  // Verify DEFENSE
  expect-equals hostname state-manager.hostname
  
  if state-manager.defend-count_ == 0:
    print "FAILURE: No defense triggered (defend-count_ is 0)!"
    print "The system likely ignored the conflict."
    exit 1
  else:
    print "SUCCESS: Defense triggered (defend-count_: $(state-manager.defend-count_))."

  state-manager.stop

test-defense-in-announcing:
  // Bug: conflicts received during the ANNOUNCING window were silently
  // ignored — only PROBING and ESTABLISHED checked.  RFC 6762 §9 says
  // conflict resolution applies any time after probing succeeds.
  print "Testing defense in ANNOUNCING state..."

  socket := MdnsSocket --network=net.open --port=TEST-PORT
  conflict-manager := ConflictManager
  hostname := "announce-defend.local"
  local-ip := net.IpAddress.parse "127.0.0.1"

  state-manager := StateManager socket conflict-manager hostname local-ip --expected-port=TEST-PORT
  state-manager.start

  // Force the state machine into ANNOUNCING and wait until the probe
  // task is sleeping in the 1-second gap between announcements.  The
  // probe task transitions to ANNOUNCING immediately after the third
  // probe (≈ jitter + 750 ms).
  while state-manager.state_ != StateManager.STATE-ANNOUNCING:
    sleep (Duration --ms=20)

  fake-ip := net.IpAddress.parse "6.6.6.6"
  packet := dns.create-dns-packet [] [dns.AResource hostname 120 fake-ip --flush] --id=0 --is-response --is-authoritative

  state-manager.process-packet (dns.parse packet)

  // The fix routes ANNOUNCING-state conflicts through
  // handle-established-conflict_, which bumps defend-count_.
  expect state-manager.defend-count_ > 0
      --message="ANNOUNCING-state conflict must trigger defense"
  print "  PASS"

  state-manager.stop
  socket.close

test-state-not-clobbered-after-announcing-conflict:
  // Bug: enter-announcing_ unconditionally set state_ = STATE-ESTABLISHED
  // after its 1-second sleep, even if a conflict during the sleep had
  // moved the state machine back to PROBING via a rename.  The
  // overwrite hid the conflict and left two devices believing they
  // owned the same name.
  print "Testing state not clobbered when many conflicts hit ANNOUNCING..."

  socket := MdnsSocket --network=net.open --port=TEST-PORT
  conflict-manager := ConflictManager
  hostname := "clobber-test.local"
  local-ip := net.IpAddress.parse "127.0.0.1"

  state-manager := StateManager socket conflict-manager hostname local-ip --expected-port=TEST-PORT
  state-manager.start

  // Wait for ANNOUNCING.
  while state-manager.state_ != StateManager.STATE-ANNOUNCING:
    sleep (Duration --ms=20)

  fake-ip := net.IpAddress.parse "6.6.6.6"
  packet := dns.create-dns-packet [] [dns.AResource hostname 120 fake-ip --flush] --id=0 --is-response --is-authoritative

  // Push four conflicts: the fourth one exceeds the defense budget and
  // forces a rename, which calls enter-probing_ and sets state_ back
  // to STATE-PROBING.  The old enter-announcing_ task is still asleep;
  // when it wakes it must NOT clobber the new STATE-PROBING.
  4.repeat:
    state-manager.process-packet (dns.parse packet)

  // Now wait long enough for the original enter-announcing_ task to
  // wake from its 1s sleep and (incorrectly, before the fix) write
  // STATE-ESTABLISHED.
  sleep (Duration --ms=1500)

  // After the fix, state_ should NOT be ESTABLISHED — the rename moved
  // us back into a probing/announcing cycle for a different name.
  expect: hostname != state-manager.hostname
  expect: StateManager.STATE-ESTABLISHED != state-manager.state_
  print "  PASS"

  state-manager.stop
  socket.close
