import expect show *
import net
import net.udp
import net.modules.dns

import ..src.service
import ..lib.client
import ..src.api.mdns_service
import ..src.net.dns_helper as dns
import ..src.net.mdns_socket
import .e2e_param show TEST-PORT

main:
  test-rfc-compliance

test-rfc-compliance:
  print "Testing RFC 6762/6763 Compliance..."
  
  // Start Service
  service := MdnsServiceProvider --port=TEST-PORT
  service.handle MdnsService.SET-HOSTNAME-INDEX "rfc-test.local" --client=0 --gid=0
  
  // Register a service to have some shared/unique records
  service.register "_rfc._tcp" 9999 --name="RFCInstance" --hostname="rfc-test.local"
  
  // Monitor
  network := net.open
  monitor := MdnsSocket --network=network --port=TEST-PORT
  
  try:
    sleep (Duration --s=2)
    
    // 1. Test AA Bit and TTLs
    print "Querying rfc-test.local..."
    q := dns.Question "rfc-test.local" dns.RECORD-A
    query-packet := dns.create-dns-packet [q] [] --is-response=false --id=0
    monitor.send query-packet
    
    // Wait for response
    found-response := false
    deadline := Time.now + (Duration --s=2)
    while Time.now < deadline:
      if found-response: break
      datagram := monitor.receive
      if not datagram: continue
      packet := datagram.data
      if packet.size == 0: continue
      
      parsed := dns.parse packet
      // Check if Authoritative (AA) bit is set?
      flags-high := packet[2]
      is-aa := (flags-high & 0x04) != 0
        
      if dns.is-authoritative-response-for parsed "rfc-test.local":
           print "Received Response for rfc-test.local"
           if is-aa: print "AA Bit OK"
           else: print "AA Bit MISSING"
           expect is-aa
           
           verify-packet parsed --expect-unique=true
           found-response = true
           
    expect found-response
    
    // 2. Test PTR TTL (Shared Record)
    print "Querying _rfc._tcp.local (PTR)..."
    q_ptr := dns.Question "_rfc._tcp.local" dns.RECORD-PTR
    monitor.send (dns.create-dns-packet [q_ptr] [] --is-response=false --id=0)
    
    found-ptr := false
    deadline = Time.now + (Duration --s=2)
    while Time.now < deadline:
      if found-ptr: break
      datagram := monitor.receive
      if not datagram: continue
      packet := datagram.data
      if packet.size == 0: continue
      
      parsed := dns.parse packet
        
      parsed.resources.do: | ans |
            if ans.name == "_rfc._tcp.local" and ans.type == dns.RECORD-PTR:
               print "Received PTR for _rfc._tcp.local"
               print "PTR TTL: $(ans.ttl)"
               expect-equals 4500 ans.ttl
               found-ptr = true
               
    expect found-ptr

    // 3. Test Unicast Response (QU Bit)
    print "Testing Unicast Response (QU)..."
    // Create ephemeral socket
    unicast-socket := network.udp-open --port=0
    local-addr := unicast-socket.local-address
    print "Ephemeral socket on port $(local-addr.port)"
    
    try:
       // Send Query with QU bit set for _rfc._tcp.local
       q_qu := dns.Question "_rfc._tcp.local" dns.RECORD-PTR --unicast-ok=true
       unicast_query_packet := dns.create-dns-packet [q_qu] [] --is-response=false --id=0x1234
       
       // Send to Multicast Group (where Provider listens)
       target := net.SocketAddress (net.IpAddress.parse "224.0.0.251") TEST-PORT
       unicast-socket.send (udp.Datagram unicast_query_packet target)
       
       // Expect response on THIS socket (Unicast)
       // StateManager should reply to local-addr
       
       found-unicast := false
       deadline = Time.now + (Duration --s=2)
       while Time.now < deadline:
         if found-unicast: break
         datagram := unicast-socket.receive
         packet := datagram.data
         parsed := dns.parse packet
         // Verify it's a response
         if parsed.is-response:
           parsed.resources.do: | ans |
              if ans.name == "_rfc._tcp.local" and ans.type == dns.RECORD-PTR:
                 print "Received Unicast Response!"
                 found-unicast = true
                   
       expect found-unicast
       
    finally:
       unicast-socket.close

    print "RFC Compliance Test: OK"

  finally:
    service.close
    monitor.close

verify-packet packet/dns.DecodedPacket --expect-unique/bool:
  packet.resources.do: | ans |
    if ans.type == dns.RECORD-A or ans.type == dns.RECORD-SRV:
      if expect-unique:
        print "Checking TTL for $(ans.name) ($(ans.type)): $(ans.ttl)"
        expect-equals 120 ans.ttl
