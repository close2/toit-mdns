/**
ESP32-side test: joins the mDNS multicast group and listens for packets.
Also periodically sends multicast packets that Wireshark/tcpdump on the
PC should be able to capture.

Flash and run on ESP32:
  ESPTOOL_PATH=/usr/bin/esptool build/jag run \
      toit-mdns.v4/tests/esp32-receive-multicast-test.toit

Monitor output:
  ESPTOOL_PATH=/usr/bin/esptool build/jag monitor | tee /tmp/esp32-mcast.log

On the PC, run the companion pc-send-multicast-test.toit to generate
traffic that this program should receive.

Also capture ESP32's outgoing packets:
  sudo tcpdump -i <wifi-iface> -n 'udp port 5353' -v
*/
import net
import net.modules.udp as udp-impl
import net.udp as udp

MDNS-GROUP ::= net.IpAddress #[224, 0, 0, 251]
MDNS-PORT ::= 5353

main:
  network := net.open
  print "ESP32 multicast test starting..."
  print "Local IP: $network.address"

  // Create a multicast socket bound to the mDNS group.
  socket := udp-impl.Socket.multicast network
      MDNS-GROUP
      MDNS-PORT
      --reuse-address
      --reuse-port
      --loopback

  print "Joined multicast group 224.0.0.251 on port $MDNS-PORT"
  print "Local address: $socket.local-address"

  // Sender task: send a multicast packet every 2 seconds.
  // The PC's Wireshark/tcpdump should see these.
  task::
    sender-socket := udp-impl.Socket network "0.0.0.0" 0
    print "Sender task started (sending every 2s)..."
    50.repeat: | i |
      payload := "esp32-mcast-$i"
      exception := catch:
        sender-socket.send
            udp.Datagram
                payload.to-byte-array
                net.SocketAddress MDNS-GROUP MDNS-PORT
      if exception:
        print "SEND ERROR [$i]: $exception"
      else:
        print "SENT [$i]: $payload"
      sleep --ms=2000
    sender-socket.close
    print "Sender task done."

  // Receiver: listen for incoming multicast packets (from PC or other ESP32s).
  print "Listening for multicast packets..."
  received := 0
  60.repeat:  // Listen for up to 60 packets, or the program ends.
    datagram/udp.Datagram? := null
    exception := catch:
      with-timeout --ms=5000:
        datagram = socket.receive
    if exception:
      if exception == "DEADLINE_EXCEEDED":
        print "  (no packet in 5s, still listening...)"
      else:
        print "RECEIVE ERROR: $exception"
    else if datagram:
      received++
      print "RECEIVED [$received] from $(datagram.address): $(datagram.data.to-string-non-throwing)"

  socket.close
  print "Test complete. Received $received packets total."
