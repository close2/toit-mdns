import expect show *
import mdns.service as service
import mdns.client as client
import mdns.api.mdns_service show MdnsService

main:
  test-connect-locally

test-connect-locally:
  print "Starting local service test..."
  
  // Use the helper to create a client with a local provider
  client := client.LocalMdnsClient
  
  // Set hostname
  client.set-hostname "local-test.local"
  expect-equals "local-test.local" client.hostname
  
  // Register service
  client.register-service "_local_test._tcp" 1234 --txt={"foo": "bar"}
  
  // Clean up
  client.close
  
  print "Local service test passed."
