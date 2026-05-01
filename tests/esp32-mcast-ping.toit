/**
Simple ESP32 multicast ping test.
Sends multicast packets with device identity and prints any received.
Run on both ESP32s to test if they can hear each other.

Usage:
  jag run --device <IP> tests/esp32-mcast-ping.toit
*/
import net
import net.udp

MDNS-GROUP ::= net.IpAddress #[224, 0, 0, 251]
TEST-PORT ::= 5354  // Use a different port to avoid mDNS noise.

main:
  network := net.open
  my-ip := network.address.stringify
  print "Multicast ping test starting on $my-ip"

  // Create a multicast receiver socket.
  rx := network.udp-open-multicast
      --port=TEST-PORT
      --reuse-address
      --reuse-port
      --loopback
  rx.multicast-add-membership MDNS-GROUP
  print "Listening on 224.0.0.251:$TEST-PORT"

  // Create a sender socket (multicast, no group join).
  tx := network.udp-open-multicast --loopback

  // Sender task.
  task::
    20.repeat: | i |
      payload := "ping from $my-ip #$i"
      exception := catch:
        tx.send
            udp.Datagram
                payload.to-byte-array
                net.SocketAddress
                    MDNS-GROUP
                    TEST-PORT
      if exception:
        print "SEND ERROR [$i]: $exception"
      else:
        print "SENT: $payload"
      sleep --ms=2000
    tx.close
    print "Sender done."

  // Receiver loop.
  40.repeat:
    datagram/udp.Datagram? := null
    exception := catch:
      with-timeout --ms=5000:
        datagram = rx.receive
    if exception:
      if exception == "DEADLINE_EXCEEDED":
        print "  (waiting...)"
      else:
        print "RX ERROR: $exception"
    else if datagram:
      msg := datagram.data.to-string-non-throwing
      print "RECEIVED from $(datagram.address): $msg"

  rx.close
  print "Test complete."
