import expect show *
import net
import net.udp
import net.modules.dns

import ..src.net.mdns_socket
import ..src.server.conflict_manager
import ..src.server.state_manager
import ..src.api.mdns_service
import .e2e_param show TEST-PORT

main:
  test-probing-tiebreaking

test-probing-tiebreaking:
  print "Testing probing tiebreaking (RFC 6762 Section 8.2)..."
  network := net.open

  port := TEST-PORT
  
  // We rely on process-packet injection so the socket receiving stuff doesn't matter much
  // as long as we inject our test packets.
  socket := MdnsSocket --network=network --port=port
  conflict-manager := ConflictManager
  hostname := "tiebreak.local"
  local-ip := net.IpAddress.parse "192.168.1.50"
  
  state-manager := StateManager socket conflict-manager hostname local-ip
  
  // Start - enters probing
  state-manager.start
  
  // 1. Simulate "Simultaneous Probe" / specific tiebreaking case:
  // We receive a response for "tiebreak.local" that HAS THE SAME IP.
  // This should NOT trigger a conflict.
  
  print "Injecting response with SAME IP..."
  questions := []
  answers := [dns.AResource hostname 120 local-ip --flush=true]
  packet-same-ip := dns.create-dns-packet questions answers --id=0 --is-response=true --is-authoritative=true
  
  state-manager.process-packet packet-same-ip
  
  // Verify NO rename
  expect-equals hostname state-manager.hostname
  print "Verified: No rename for same IP."
  
  // 2. Simulate Conflict:
  // Receive response for "tiebreak.local" with DIFFERENT IP.
  // This MUST trigger a conflict.
  
  print "Injecting response with DIFFERENT IP..."
  other-ip := net.IpAddress.parse "192.168.1.99"
  answers-conflict := [dns.AResource hostname 120 other-ip --flush=true]
  packet-conflict := dns.create-dns-packet questions answers-conflict --id=0 --is-response=true --is-authoritative=true
  
  state-manager.process-packet packet-conflict
  
  // Verify rename happened
  expect-not-equals hostname state-manager.hostname
  expect-equals "tiebreak.local (2)" state-manager.hostname
  print "Verified: Rename occurred for different IP."
  
  state-manager.stop
  socket.close
  print "Success."
