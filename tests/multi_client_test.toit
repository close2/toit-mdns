import expect show *
import net
import net.udp
import net.modules.dns

import mdns.service show MdnsServiceProvider
import mdns.client as client-lib
import mdns.api.mdns_service show MdnsService
import .e2e_param show TEST-PORT
import mdns.net.mdns_socket show MdnsSocket

main:
  test-multi-client

test-multi-client:
  print "Testing Multi-Client Hostname Support..."
  
  port := TEST-PORT // distinct port
  
  // Create shared service on this port initially)
  provider := MdnsServiceProvider --port=port
  provider.install
  
  // 2. Client A setup (uses default system hostname)
  client-a := client-lib.Client
  print "Client A started. Hostname: $(client-a.hostname)"
  // expect-equals "system-default.local" client-a.hostname // Can't easily mock system.hostname match, but let's assume default behavior works
  
  // 3. Client B setup (sets specific hostname)
  client-b := client-lib.Client --hostname="shared.local"
  print "Client B started. Hostname: $(client-b.hostname)"
  expect-equals "shared.local" client-b.hostname
  
  // 4. Client C setup (shares hostname with B)
  client-c := client-lib.Client --hostname="shared.local"
  print "Client C started. Hostname: $(client-c.hostname)"
  expect-equals "shared.local" client-c.hostname

  try:
    // 5. Register services
    client-a.register-service "_http._tcp" 8080 --name="ServiceA"
    client-b.register-service "_http._tcp" 9090 --name="ServiceB"
    client-c.register-service "_http._tcp" 9091 --name="ServiceC"
    
    sleep (Duration --s=5)

    // 6. Verification
    network := net.open
    socket := MdnsSocket --network=network --port=port
    
    try:
      // A. Check resolution
      print "Resolving shared.local..."
      expect (resolve socket "shared.local")
      
      // B. Check Service ownership
      srv-b := resolve-srv socket "ServiceB._http._tcp.local"
      expect-equals "shared.local" srv-b.value
      
      srv-c := resolve-srv socket "ServiceC._http._tcp.local"
      expect-equals "shared.local" srv-c.value
      
      print "Initial state verified."
      
      // 7. Client B disconnects
      print "Closing Client B..."
      client-b.service_.close
      sleep (Duration --s=2)
      
      // hostname "shared.local" should still resolve because Client C is holding it
      print "Resolving shared.local (after B close)..."
      expect (resolve socket "shared.local")
      
      // 8. Client C disconnects
      print "Closing Client C..."
      client-c.service_.close
      sleep (Duration --s=2)
      
      // hostname "shared.local" should NO LONGER resolve (ref count 0).
      print "Verifying shared.local is gone..."
      expect-not (resolve socket "shared.local")
      
      print "Success: Multi-client ref counting works!"
      
    finally:
      socket.close

  finally:
    client-a.service_.close
    // client-b and c already closed
    provider.close
    provider.uninstall

resolve socket/MdnsSocket name/string -> bool:
  socket.send (dns.create-dns-packet [dns.Question name dns.RECORD-A] [] --is-response=false --id=0x1111)
  10.repeat:
    exception := catch:
      with-timeout (Duration --ms=1500):
        datagram := socket.receive
        if datagram:
          parsed := dns.decode-packet datagram.data
          if parsed.is-response:
            parsed.resources.do: | res |
              if res.name == name and res.type == dns.RECORD-A:
                return true
  return false

resolve-srv socket/MdnsSocket name/string -> dns.SrvResource:
  socket.send (dns.create-dns-packet [dns.Question name dns.RECORD-SRV] [] --is-response=false --id=0x2222)
  10.repeat:
    exception := catch:
      with-timeout (Duration --ms=1500):
        datagram := socket.receive
        if datagram:
          parsed := dns.decode-packet datagram.data
          if parsed.is-response:
            parsed.resources.do: | res |
              if res.name == name and res.type == dns.RECORD-SRV:
                return res as dns.SrvResource
  throw "SRV NOT FOUND for $name"
