/**
Test both broadcast AND unicast-to-multicast-port between ESP32s.
This helps narrow down whether the issue is multicast-MAC-specific.

Run on both ESP32s:
  build/jag run --device <IP> \
    third_party/toit.worktree1/toit-mdns.v4/tests/esp32-broadcast-test.toit
*/
import net
import net.modules.udp as udp-impl
import net.udp as udp

BCAST-ADDR ::= net.IpAddress #[255, 255, 255, 255]
TEST-PORT ::= 5355

main:
  network := net.open
  my-ip := network.address.stringify
  print "=== Broadcast + unicast test on $my-ip ==="

  // Receiver socket: bound to our test port with broadcast enabled.
  rx := udp-impl.Socket network "0.0.0.0" TEST-PORT
  rx.broadcast = true
  print "Listening on 0.0.0.0:$TEST-PORT"

  // Sender socket.
  tx := udp-impl.Socket network "0.0.0.0" 0
  tx.broadcast = true

  // Determine the other ESP32's address.
  other-ip/net.IpAddress := ?
  if my-ip == "10.0.100.181":
    other-ip = net.IpAddress #[10, 0, 100, 180]
  else:
    other-ip = net.IpAddress #[10, 0, 100, 181]
  print "Other ESP32: $other-ip"

  // Sender task: alternate broadcast and unicast.
  task::
    30.repeat: | i |
      // Even: broadcast, odd: unicast to other ESP32.
      if i % 2 == 0:
        payload := "BCAST from $my-ip #$i"
        exception := catch:
          tx.send
              udp.Datagram
                  payload.to-byte-array
                  net.SocketAddress BCAST-ADDR TEST-PORT
        if exception:
          print "BCAST SEND ERROR [$i]: $exception"
        else:
          print "SENT BCAST: $payload"
      else:
        payload := "UCAST from $my-ip #$i"
        exception := catch:
          tx.send
              udp.Datagram
                  payload.to-byte-array
                  net.SocketAddress other-ip TEST-PORT
        if exception:
          print "UCAST SEND ERROR [$i]: $exception"
        else:
          print "SENT UCAST: $payload"
      sleep --ms=2000
    tx.close
    print "Sender done."

  // Receiver loop.
  50.repeat:
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
      src := datagram.address
      print "RECEIVED from $src: $msg"

  rx.close
  print "Test complete."
