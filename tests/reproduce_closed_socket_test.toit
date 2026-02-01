import expect show *
import net
import net.udp

import ..src.server.state_manager
import ..src.server.conflict_manager
import ..src.net.mdns_socket
import .e2e_param show TEST-PORT

main:
  test-closed-socket-race

test-closed-socket-race:
  network := net.open
  socket := MdnsSocket --network=net.open --port=TEST-PORT

  conflict-manager := ConflictManager
  local-ip := net.IpAddress.parse "127.0.0.1"
  
  state-manager := StateManager socket conflict-manager "test.local" local-ip
  
  // Start the state manager, which enters the probing phase.
  state-manager.start

  // Allow some time for the probing task to start and potentially send the first probe.
  sleep --ms=10

  // Close the socket to trigger the race condition.
  socket.close

  // Wait long enough for the probing task to attempt another send.
  // The probing interval is 250ms.
  sleep --ms=500
  
  // Clean up
  state-manager.stop
  
  print "Test finished without crash"
