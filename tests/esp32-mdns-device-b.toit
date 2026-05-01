/**
ESP32 device B: Registers an mDNS service and tries to discover device A.

Run on ESP32 #2:
  build/jag run --device 10.0.100.180 \
      third_party/toit.worktree1/toit-mdns.v4/tests/esp32-mdns-device-b.toit
*/
import mdns.client show LocalMdnsClient

main:
  print "=== Device B starting mDNS ==="
  client := LocalMdnsClient --hostname="device-b.local"

  // Register our service.
  client.register-service "_toittest._tcp" 9090
      --name="DeviceB"
      --txt={"role": "beta"}
  print "Device B: registered _toittest._tcp service as DeviceB"

  // Give the service time to probe and announce.
  sleep --ms=5000

  // Try to discover device A's service.
  print "Device B: looking for DeviceA..."
  10.repeat: | i |
    exception := catch:
      results := client.browse "_toittest._tcp"
          --network=null
          --timeout=(Duration --s=3)
      print "Device B: browse results ($i): $results"
      results.do: | name/string |
        if name.contains "DeviceA":
          print "*** Device B: FOUND DeviceA! ***"
    if exception:
      print "Device B: browse attempt $i error: $exception"
    sleep --ms=3000

  print "Device B: sleeping 120s (service still advertised)..."
  sleep --ms=120_000
  client.close
  print "Device B: done."
