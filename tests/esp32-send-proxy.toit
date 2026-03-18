/**
ESP32 UDP send test using the correct network.udp-open API
(proxied through the system service).

Run: build/jag run --device <ESP32-IP> \
       third_party/toit.worktree1/toit-mdns.v4/tests/esp32-send-proxy.toit
*/
import net
import net.udp

PC-IP ::= net.IpAddress #[10, 0, 100, 191]
PC-PORT ::= 7777
BCAST-ADDR ::= net.IpAddress #[255, 255, 255, 255]

main:
  network := net.open
  my-ip := network.address.stringify
  print "=== ESP32 UDP proxy-send test ==="
  print "My IP: $my-ip"
  print "Target: $PC-IP:$PC-PORT"

  // Use network.udp-open (goes through system service proxy on ESP32).
  socket := network.udp-open
  socket.broadcast = true
  print "Socket opened on port $(socket.local-address.port)"

  // Send 10 unicast packets to PC.
  10.repeat: | i |
    payload := "proxy-hello-from-$my-ip-#$i"
    exception := catch:
      socket.send
          udp.Datagram
              payload.to-byte-array
              net.SocketAddress PC-IP PC-PORT
    if exception:
      print "UNICAST ERROR [$i]: $exception"
    else:
      print "UNICAST SENT [$i]: $payload"
    sleep --ms=500

  // 3 broadcast packets.
  3.repeat: | i |
    payload := "proxy-bcast-from-$my-ip-#$i"
    exception := catch:
      socket.send
          udp.Datagram
              payload.to-byte-array
              net.SocketAddress BCAST-ADDR PC-PORT
    if exception:
      print "BCAST ERROR [$i]: $exception"
    else:
      print "BCAST SENT [$i]: $payload"
    sleep --ms=500

  socket.close
  print "=== Done ==="
