import expect show *
import net
import net.udp
import net.modules.dns

import ..src.service
import ..lib.client
import ..src.api.mdns_service
import .e2e_param show TEST-PORT

main:
  test-cache-hit
  test-integration

test-cache-hit:
  print "Testing Cache Hit..."
  // manually instantiate service and cache
  service := MdnsServiceProvider --port=TEST-PORT
  
  // Create record
  ip := net.IpAddress.parse "1.2.3.4"
  record := dns.AResource "foo.local" 120 ip

  // Direct cache injection
  service.ensure-socket_ // Initialize cache_ and socket_
  service.cache_.add record
  
  // Direct add is synchronous and sufficient.
  
  results := service.lookup "foo.local" 
      --accept-ipv4=true 
      --accept-ipv6=false 
      --timeout-us=1_000_000
      
  expect-not-null results
  expect results.size > 0
  
  // Decode result
  type := results[0][0]
  data := results[0][1]
  expect-equals dns.RECORD-A type
  expect-equals ip (net.IpAddress data)
  
  service.close
  print "Cache Hit: OK"
  
test-integration:
  print "Testing Integration (2 Engines)..."
  
  // Server A (Responder)
  server-a := MdnsServiceProvider --port=TEST-PORT
  server-a.handle MdnsService.SET-HOSTNAME-INDEX "server-a.local" --client=1 --gid=0
  
  // Server B (Client)
  server-b := MdnsServiceProvider --port=TEST-PORT
  server-b.handle MdnsService.SET-HOSTNAME-INDEX "client.local" --client=2 --gid=0
  
  try:
    // Wait for probing/startup
    sleep (Duration --ms=1500)
    
    // Now B queries for A
    print "Querying for server-a.local..."
    
    // Using Server B's lookup matching SDK signature (via wrapper helper in service.toit)
    results := server-b.lookup "server-a.local"
        --accept-ipv4=true
        --accept-ipv6=false
        --timeout-us=2_000_000
        
    if results.is-empty:
      print "Lookup failed (Timeout/Empty)"
      expect false
      
    expect-not-null results
    expect results.size > 0
    
    type := results[0][0]
    data := results[0][1]
    
    expect-equals dns.RECORD-A type
    ip := net.IpAddress data
    print "Resolved IP: $ip"
    
    // Should match local IP
    local-ip := net.open.address
    expect-equals local-ip ip
    
    print "Integration Test: OK"
  finally:
    server-a.close
    server-b.close
