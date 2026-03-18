import expect show *
import net
import net.modules.dns

import mdns.service show MdnsServiceProvider
import mdns.client show Client MdnsServiceClient
import mdns.api.mdns_service show MdnsService

main:
  // 1. Install Service
  service := MdnsServiceProvider
  service.install
  
  try:
    // Verify RPC round-trip
    client := MdnsServiceClient
    client.open
    
    // Set hostname for this client
    client.set-hostname "rpc-client.local"
    
    // Get it back
    hostname := client.get-hostname
    print "RPC Hostname: $hostname"
    expect-equals "rpc-client.local" hostname
    
    client.close
    
    // Cleanup internal logic
    service.close
  finally:
    // Remove from system service registry
    service.uninstall
