/**
ESP32 device A: Registers an mDNS service and tries to discover device B.

Run on ESP32 #1:
  build/jag run --device 10.0.100.181 \
      third_party/toit.worktree1/toit-mdns.v4/tests/esp32-mdns-device-a.toit
*/
import mdns.client show LocalMdnsClient

main:
  print "=== Device A starting mDNS ==="
  client := LocalMdnsClient --hostname="device-a.local"

  // Register our service.
  client.register-service "_toittest._tcp" 8080
      --name="DeviceA"
      --txt={"role": "alpha"}
  print "Device A: registered _toittest._tcp service as DeviceA"

  // Give the service time to probe and announce.
  sleep --ms=5000

  // Try to discover device B's service.
  print "Device A: looking for DeviceB..."
  10.repeat: | i |
    exception := catch:
      results := client.browse "_toittest._tcp"
          --network=null
          --timeout=(Duration --s=3)
      print "Device A: browse results ($i): $results"
      results.do: | name/string |
        if name.contains "DeviceB":
          print "*** Device A: FOUND DeviceB! ***"
    if exception:
      print "Device A: browse attempt $i error: $exception"
    sleep --ms=3000

  print "Device A: sleeping 120s (service still advertised)..."
  sleep --ms=120_000
  client.close
  print "Device A: done."
