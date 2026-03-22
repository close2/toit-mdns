import expect show *
import net
import net.udp
import net.modules.dns

import mdns.service show MdnsServiceProvider
import mdns.client as client-lib
import mdns.api.mdns_service show MdnsService
import mdns.net.mdns_socket show MdnsSocket
import .e2e_param show TEST-PORT

main:
  test-multi-hostname

test-multi-hostname:
  print "Testing Multiple Hostname Support..."
  
  port := TEST-PORT // distinct port
  
  // 1. Start Provider
  provider := MdnsServiceProvider --port=port
  provider.install
  
  // 2. Client setup
  client1 := client-lib.Client --hostname="host1.local"
  client2 := client-lib.Client --hostname="host2.local"
  
  try:
    // 4. Register services on specific hosts
    print "Registering services..."
    // Service 1 on host1
    client1.register-service "_http._tcp" 8080 
        --name="Service1" 
        --txt={"path": "/app1"}

    // Service 2 on host2
    client2.register-service "_http._tcp" 9090 
        --name="Service2" 
        --txt={"path": "/app2"}
        
    // Wait for probing
    sleep (Duration --s=2)

    
    // 5. Verification with raw socket
    network := net.open
    socket := MdnsSocket --network=network --port=port
    
    try:
      // A. Resolve host1
      print "Resolving host1.local..."
      expect (resolve socket "host1.local")
      
      // B. Resolve host2
      print "Resolving host2.local..."
      expect (resolve socket "host2.local")
      
      // C. Check Service1 SRV -> host1
      print "Checking Service1..."
      srv1 := resolve-srv socket "Service1._http._tcp.local"
      expect-equals "host1.local" srv1.value
      
      // D. Check Service2 SRV -> host2
      print "Checking Service2..."
      srv2 := resolve-srv socket "Service2._http._tcp.local"
      expect-equals "host2.local" srv2.value
      
      print "Success: Multiple hostnames functional!"
      
    finally:
      socket.close

  finally:
    client1.service_.close
    client2.service_.close
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
