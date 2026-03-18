import expect show *
import net
import net.udp
import net.modules.dns
import mdns.api.mdns_service show MdnsService
import mdns.net.mdns_socket show MdnsSocket
import .e2e_param show TEST-PORT
import mdns.server.conflict_manager show ConflictManager
import mdns.server.state_manager show StateManager

main:
  test-conflict-resolution

test-conflict-resolution:
  print "Testing conflict resolution..."
  network := net.open
  
  socket := MdnsSocket --network=network
  conflict-manager := ConflictManager
  hostname := "test.local"
  local-ip := net.IpAddress.parse "127.0.0.1"
  
  state-manager := StateManager socket conflict-manager hostname local-ip --expected-port=TEST-PORT
  
  // Start the state machine (enters probing)
  state-manager.start
  
  // Simulate an incoming authoritative response for "test.local" (Conflict!)
  // This should trigger a rename to "test (2).local"
  
  // Wait for probing to have started (jitter 0-250ms + first probe).
  sleep (Duration --ms=300)
  
  // Construct conflict packet
  questions := []
  fake-ip := net.IpAddress.parse "1.1.1.1"
  answers := [dns.AResource "test.local" 120 fake-ip --flush=true]
  packet := dns.create-dns-packet questions answers --id=0 --is-response=true --is-authoritative=true
  
  // Inject packet into state machine
  state-manager.process-packet packet
  
  // Check if renamed
  // We need to wait a moment for the rename logic (it's synchronous but lets be safe)
  expect-equals "test (2).local" state-manager.hostname
  final-hostname := state-manager.hostname
  print "Conflict resolution: OK (Renamed to $final-hostname)"
  
  // Let it run to established
  // Jitter (0-250ms) + 3 probes × 250ms + 2 announcements 1s apart = ~2.5s max.
  print "Waiting for establishment..."
  sleep (Duration --ms=3000)
  
  // Now it should be established with "test (2).local"
  // Setup: Two providers on the SAME PORT (simulating same network)
  // MdnsSocket uses SO_REUSEPORT, so this is allowed.
  port := TEST-PORT
  
  // 1. Start Server A (First claimer)
  // We can verify this by checking if it responds to queries for "test (2).local"
  
  // NOTE: In a real test we would capture the output or mock the socket sending.
  // For now, checking the internal hostname is a good proxy.
  expect-equals "test (2).local" state-manager.hostname
  
  socket.close
