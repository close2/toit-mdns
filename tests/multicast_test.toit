import expect show *
import net
import net.modules.dns

import ..src.net.mdns_socket
import .e2e_param show TEST-PORT

main:
  test-multicast-loopback

test-multicast-loopback:
  print "Testing multicast loopback..."
  network := net.open
  
  // Create MdnsSocket
  socket := MdnsSocket --network=network --port=TEST-PORT
  
  try:
    // Create a simple DNS packet using SDK internal helper
    questions := [dns.Question "test.local" dns.RECORD-A]
    answers := []
    id := 0x1234
    packet := dns.create-dns-packet questions answers --id=id --is-response=false
    
    // We need to send to the multicast group.
    // The socket is bound to the multicast group.
    //    socket := net.open.udp-open
    destination := net.SocketAddress MDNS-MULTICAST-ADDRESS TEST-PORT
    
    socket.send packet destination
    
    // We expect the mdns socket to receive this, because it joins the group.  
    // Receive
    datagram := socket.receive
    
    received := datagram.data
    expect-equals packet.size received.size
    expect-equals packet received
    
    print "Multicast loopback: OK"
    
  finally:
    socket.close
