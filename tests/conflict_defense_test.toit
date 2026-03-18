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
  
  state-manager.process-packet packet
  
  // Verify DEFENSE
  expect-equals hostname state-manager.hostname
  
  if state-manager.defend-count_ == 0:
    print "FAILURE: No defense triggered (defend-count_ is 0)!"
    print "The system likely ignored the conflict."
    exit 1
  else:
    print "SUCCESS: Defense triggered (defend-count_: $(state-manager.defend-count_))."

  state-manager.stop
