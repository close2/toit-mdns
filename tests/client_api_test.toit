import expect show *
import net
import net.udp
import net.modules.dns
import ..lib.client as client-lib
import ..src.service as service-impl

main:
  test-api-structure

test-api-structure:
  print "Testing API Structure..."
  
  // Test instantiation
  // This will try to open the service client, which might fail if service not present?
  // MdnsServiceClient.open calls ServiceClient.open.
  // We just want to check types.
  
  // To verify signature/structure without running, we rely on compilation.
  // Client constructor opens service, so we need a provider.
  
  provider := service-impl.MdnsServiceProvider
  provider.install

  try:
    client := client-lib.Client
    expect-not-null client

    // Test dns-client getter
    dns-client := client.dns-client
    expect-not-null dns-client
    expect (dns-client is dns.DnsClient)
    
    print "API Structure: OK"
  finally:
    provider.uninstall
