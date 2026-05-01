import expect show *
import net
import mdns.client show Client
import mdns.api.mdns_service show MdnsService
import mdns.service show MdnsServiceProvider
import .e2e_param show TEST-PORT

main:
  test-hostname-conflict

test-hostname-conflict:
  print "Testing Hostname Conflict Resolution..."
  port := TEST-PORT
  
  // 1. Start two providers
  s1 := MdnsServiceProvider --port=port
  s1.install
  s1.handle MdnsService.SET-HOSTNAME-INDEX "device.local" --client=1 --gid=0
  
  s2 := MdnsServiceProvider --port=port --local-ip=(net.IpAddress.parse "1.2.3.4")
  s2.install
  s2.handle MdnsService.SET-HOSTNAME-INDEX "other.local" --client=2 --gid=0
  
  try:
    // Allow initial established state.
    // Probing (jitter+3×250ms) + announcing (2×1s) = ~2.5s per provider.
    sleep (Duration --s=5)
    print "S1 Hostname: $(s1.hostname)"
    print "S2 Hostname: $(s2.hostname)"
    
    expect-equals "device.local" s1.hostname
    expect-equals "other.local" s2.hostname
    
    print "Triggering conflict: Setting s2 instance to 'device.local'..."
    // Verify S2 renamed
    // Trigger conflict by setting S2 to the same name as S1
    s2.handle MdnsService.SET-HOSTNAME-INDEX "device.local" --client=2 --gid=0
    
    // Probing takes ~1s + announcing ~1s + extra margin.
    print "Waiting for conflict resolution..."
    sleep (Duration --s=6)
    
    print "Final S1 Hostname: $(s1.hostname)"
    print "Final S2 Hostname: $(s2.hostname)"
    
    // S1 should have defended and kept its name
    expect-equals "device.local" s1.hostname
    
    // S2 should have detected conflict and renamed itself
    expect (s2.hostname != "device.local")
    expect (s2.hostname.contains "device")
    print "Success: S2 renamed to $(s2.hostname)"
    
  finally:
    s1.close
    s2.close
    s1.uninstall
    s2.uninstall

  print "Hostname Conflict Test: OK"
