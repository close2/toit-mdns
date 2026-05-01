import expect show *
import net
import net.udp
import net.modules.dns

import mdns.service show MdnsServiceProvider
import mdns.client show Client
import mdns.api.mdns_service show MdnsService
import .e2e_param show TEST-PORT

main:
  test-service-discovery

test-service-discovery:
  print "Testing Service Discovery (Register + Browse)..."
  
  // 1. Start Server A (Provider)
  server-a := MdnsServiceProvider --port=TEST-PORT
  server-a.handle MdnsService.SET-HOSTNAME-INDEX "server-inc.local" --client=1 --gid=0
  
  // 2. Start Server B (Browsing Client)
  server-b := MdnsServiceProvider --port=TEST-PORT
  server-b.handle MdnsService.SET-HOSTNAME-INDEX "client-browser.local" --client=2 --gid=0
  
  try:
    // 3. Register a service on Server A
    // Type: _http._tcp
    // Port: 8080
    // TXT: path=/
    txt := {"path": "/"}
    // Use RPC handle to register using the committed hostname for client 1
    server-a.handle MdnsService.REGISTER-INDEX ["_http._tcp", 8080, txt, "MyWebServer"] --client=1 --gid=0
    
    // Allow probing/announcing to happen
    sleep (Duration --s=2)
    
    // 4. Client B browses for _http._tcp
    // 4. Client B browses for _http._tcp
    // Perform lookup directly on server-b instance.
    
    // We want to browse: look for PTR records for _http._tcp.local
    ptr-name := "_http._tcp.local"
    
    print "Browsing for $ptr-name..."
    results := server-b.lookup ptr-name 
        --record-types=dns.RECORD-PTR 
        --timeout-us=2_000_000
    
    if results.is-empty:
      print "Browse failed (No PTR found)"
      expect false
    
    // Verify PTR
    ptr-data := null
    results.do: | res |
      // [type, data]
      if res[0] == dns.RECORD-PTR:
        ptr-data = res[1] // StringResource value is the domain
    
    expect-not-null ptr-data
    print "Found Service Instance: $ptr-data"
    expect-equals "MyWebServer._http._tcp.local" ptr-data
    
    // 5. Resolve the Instance
    print "Resolving Instance $ptr-data..."
    instance-results := server-b.lookup ptr-data
        --record-types=(dns.RECORD-SRV | dns.RECORD-TXT)
        --timeout-us=2_000_000
        
    found-srv := false
    target-host := ""
    
    instance-results.do: | res |
      type := res[0]
      data := res[1]
      if type == dns.RECORD-SRV:
        // [prio, weight, port, target]
        port := data[2]
        target := data[3]
        print "SRV: port=$port target=$target"
        expect-equals 8080 port
        found-srv = true
        target-host = target
      else if type == dns.RECORD-TXT:
        print "TXT: $data"
        if data.contains "path=/": 
           // found-txt = true
           null
           
    if not found-srv: print "Missing SRV Record"
    expect found-srv
    
    // 6. Resolve Target Host
    print "Resolving Target: $target-host"
    expect-not-null target-host
    expect (target-host != "")
    
    // Check if we already have it in cache or need to query
    target-results := server-b.lookup target-host
        --record-types=dns.RECORD-A
        --timeout-us=2_000_000
        
    found-a := false
    target-results.do: | res |
      if res[0] == dns.RECORD-A:
         print "A: $(net.IpAddress res[1])"
         found-a = true
         
    if not found-a: print "Missing A Record for $target-host"
    expect found-a
    
    print "Service Discovery Test: OK"
    
  finally:
    server-a.close
    server-b.close
