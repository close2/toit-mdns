import expect show *
import net
import net.udp
import net.modules.dns

import ..src.service
import ..lib.client as client-lib
import ..src.api.mdns_service
import ..src.net.mdns_socket
import .e2e_param show TEST-PORT

main:
  test-hostname-api

test-hostname-api:
  print "Testing Simple Hostname API..."
  
  port := TEST-PORT
  
  // 1. Start Provider on custom port
  provider := MdnsServiceProvider --port=port
  provider.install
  
  // 2. Use Client to set hostname
  client := client-lib.Client
  
  try:
    print "Setting hostname to 'my-new-device.local'..."
    client.set-hostname "my-new-device.local"
    
    // Give it time to probe/announce
    sleep (Duration --s=2)
    
    // 3. Verify it responds to 'my-new-device.local'
    // We use a raw socket on the same port to query
    network := net.open
    socket := MdnsSocket --network=network --port=port
    
    try:
      print "Querying my-new-device.local on port $port..."
      query := dns.Question "my-new-device.local" dns.RECORD-A
      packet := dns.create-dns-packet [query] [] --is-response=false --id=0xabcd
      socket.send packet
      
      found := false
      for i := 0; i < 10; i++:
        if found: break
        datagram := socket.receive
        if datagram:
          parsed := dns.decode-packet datagram.data
          if parsed.is-response:
            parsed.resources.do: | res |
              if res.name == "my-new-device.local" and res.type == dns.RECORD-A:
                print "Success: Received A record for new hostname!"
                found = true
      
      expect found
      
    finally:
      socket.close

    print "Setting hostname to 'already.local' (no-append test)..."
    client.set-hostname "already.local"
    sleep (Duration --s=2)
    
    // Quick verify
    socket2 := MdnsSocket --network=network --port=port
    try:
      socket2.send (dns.create-dns-packet [dns.Question "already.local" dns.RECORD-A] [] --is-response=false --id=0x1234)
      found := false
      for i := 0; i < 10; i++:
        if found: break
        datagram := socket2.receive
        if datagram and (dns.decode-packet datagram.data).is-response:
           found = true
      expect found
      print "Success: Received response for 'already.local'"
    finally:
      socket2.close

  finally:
    client.service_.close
    provider.close
    provider.uninstall

  print "Hostname API Test: OK"
