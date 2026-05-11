import expect show *
import net
import net.modules.dns
import mdns.client show Client
import mdns.api.mdns_service show MdnsService
import mdns.service show MdnsServiceProvider
import .e2e_param show TEST-PORT

/**
Verifies that two providers registering the same DNS-SD service
instance name end up with distinct names (RFC 6762 §8 / §9).
*/
main:
  test-service-instance-conflict

test-service-instance-conflict:
  print "Testing Service-Instance Conflict Resolution..."
  port := TEST-PORT

  // Two providers with DIFFERENT hostnames so the only conflict is the
  // shared service instance name "Web._http._tcp.local".
  s1 := MdnsServiceProvider --port=port
  s1.handle MdnsService.SET-HOSTNAME-INDEX "alpha.local" --client=1 --gid=0

  s2 := MdnsServiceProvider --port=port --local-ip=(net.IpAddress.parse "1.2.3.4")
  s2.handle MdnsService.SET-HOSTNAME-INDEX "bravo.local" --client=2 --gid=0

  try:
    txt := {"path": "/"}
    s1.handle MdnsService.REGISTER-INDEX ["_http._tcp", 8080, txt, "Web"] --client=1 --gid=0
    sleep (Duration --s=3)
    s2.handle MdnsService.REGISTER-INDEX ["_http._tcp", 8080, txt, "Web"] --client=2 --gid=0

    // Probing + announcing + extra margin.
    sleep (Duration --s=10)

    // s1 keeps the original instance; s2 must have renamed.
    web-from-s1 := s1.lookup "Web._http._tcp.local"
        --record-types=dns.RECORD-SRV
        --timeout-us=2_000_000
    expect (not web-from-s1.is-empty)
    web-target := null
    web-from-s1.do: | res |
      if res[0] == dns.RECORD-SRV: web-target = res[1][3]
    print "Web target: $web-target"
    expect-equals "alpha.local" web-target

    // s2 should now own "Web-2._http._tcp.local" pointing at bravo.local.
    renamed := s2.lookup "Web-2._http._tcp.local"
        --record-types=dns.RECORD-SRV
        --timeout-us=2_000_000
    expect (not renamed.is-empty)
    renamed-target := null
    renamed.do: | res |
      if res[0] == dns.RECORD-SRV: renamed-target = res[1][3]
    print "Web-2 target: $renamed-target"
    expect-equals "bravo.local" renamed-target
    print "Service-Instance Conflict Test: OK"
  finally:
    s1.close
    s2.close
