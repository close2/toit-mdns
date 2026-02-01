import expect show *
import net
import net.modules.dns

import ..src.service
import ..lib.client
import ..src.api.mdns_service

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
