/**
Minimal test: send unicast UDP to a specific PC IP and port.
Also send broadcast. Helps verify ESP32 UDP TX works at all.

Run:
  jag run --device <ESP32-IP> tests/esp32-send-to-pc.toit
*/
import net
import net.udp

PC-IP ::= net.IpAddress #[10, 0, 100, 191]
PC-PORT ::= 7777

main:
  network := net.open
  my-ip := network.address.stringify
  print "=== ESP32 UDP send-to-PC test ==="
  print "My IP: $my-ip"
  print "Target: $PC-IP:$PC-PORT"

  socket := network.udp-open
  socket.broadcast = true
  print "Socket created on port $(socket.local-address.port)"

  // Send 10 unicast packets to PC.
  10.repeat: | i |
    payload := "hello-from-$my-ip-#$i"
    exception := catch:
      socket.send
          udp.Datagram
              payload.to-byte-array
              net.SocketAddress PC-IP PC-PORT
    if exception:
      print "UNICAST SEND ERROR [$i]: $exception"
    else:
      print "UNICAST SENT [$i]: $payload"
    sleep --ms=500

  // Also try broadcast.
  3.repeat: | i |
    payload := "bcast-from-$my-ip-#$i"
    exception := catch:
      socket.send
          udp.Datagram
              payload.to-byte-array
              net.SocketAddress
                  (net.IpAddress #[255, 255, 255, 255])
                  PC-PORT
    if exception:
      print "BCAST SEND ERROR [$i]: $exception"
    else:
      print "BCAST SENT [$i]: $payload"
    sleep --ms=500

  socket.close
  print "=== Done ==="
