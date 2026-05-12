import .client_api_test as client_api_test
import .client_test as client_test
import .conflict_test as conflict_test
import .hostname_conflict_test as hostname_conflict_test
import .hostname_test as hostname_test
import .multicast_test as multicast_test
import .conflict_defense_test as conflict_defense_test
import .probing_tiebreaking_test as probing_tiebreaking_test
import .query_engine_wakeup_test as query_engine_wakeup_test
import .rfc_compliance_test as rfc_compliance_test
import .rpc_test as rpc_test
import .service_discovery_test as service_discovery_test
import .service_conflict_test as service_conflict_test
import .lenient_parser_test as lenient_parser_test

main:
  print "RUNNING ALL TESTS..."
  
  print "\n--- client_api_test ---"
  client_api_test.main

  print "\n--- client_test ---"
  client_test.main
  
  print "\n--- conflict_test ---"
  conflict_test.main
  
  print "\n--- hostname_conflict_test ---"
  hostname_conflict_test.main
  
  print "\n--- hostname_test ---"
  hostname_test.main
  
  print "\n--- multicast_test ---"
  multicast_test.main

  print "\n--- conflict_defense_test ---"
  conflict_defense_test.main

  print "\n--- probing_tiebreaking_test ---"
  probing_tiebreaking_test.main

  print "\n--- query_engine_wakeup_test ---"
  query_engine_wakeup_test.main
  
  print "\n--- rfc_compliance_test ---"
  rfc_compliance_test.main
  
  print "\n--- rpc_test ---"
  rpc_test.main
  
  print "\n--- service_discovery_test ---"
  service_discovery_test.main

  print "\n--- service_conflict_test ---"
  service_conflict_test.main

  print "\n--- lenient_parser_test ---"
  lenient_parser_test.main

  print "\nALL TESTS PASSED"
