/**
PC-side test: sends mDNS multicast packets that an ESP32 on the same
network should be able to receive.

Run on the development PC with:
  build/host/sdk/lib/toit/bin/toit.run \
      toit-mdns.v4/tests/pc-send-multicast-test.toit

While an ESP32 runs the companion esp32-receive-multicast-test.toit,
use `jag monitor` to check if the ESP32 receives these packets.

Also works as a loopback self-test on Linux: the sender task sends
packets, and the receiver task (on the same host) verifies receipt.
*/
import expect show *
import monitor
import net
import net.modules.udp as udp-impl
import net.udp as udp

MDNS-GROUP ::= net.IpAddress #[224, 0, 0, 251]
// Use the standard mDNS port so the ESP32's multicast socket picks it up.
MDNS-PORT ::= 5353
// Also test on a non-standard port for a cleaner two-party test.
TEST-PORT ::= 15353

main:
  network := net.open
  print "PC multicast sender starting..."

  // --- Self-test: multicast loopback on localhost ---
  loopback-test network

  // --- Cross-device test: send packets an ESP32 can receive ---
  cross-device-send network

  network.close
  print "All PC tests done."

/**
Self-contained loopback test: send multicast and receive it on the same host.
This verifies that the Toit UDP multicast primitives work on Linux.
*/
loopback-test network/net.Client:
  print "=== Multicast loopback self-test ==="
  ready := monitor.Channel 1
  done := monitor.Channel 1

  task::
    socket := udp-impl.Socket.multicast network
        MDNS-GROUP
        TEST-PORT
        --reuse-address
        --reuse-port
        --loopback
    ready.send socket.local-address.port
    datagram/udp.Datagram? := null
    with-timeout (Duration --s=5):
      datagram = socket.receive
    if not datagram:
      socket.close
      throw "Loopback receive timed out"
    expect-equals "loopback-ping" datagram.data.to-string
    print "  Loopback received OK from $(datagram.address)"
    socket.close
    done.send true

  actual-port := ready.receive

  sender := udp-impl.Socket network "0.0.0.0" 0
  sender.send
      udp.Datagram
          "loopback-ping".to-byte-array
          net.SocketAddress MDNS-GROUP TEST-PORT
  sender.close

  done.receive
  print "  Loopback self-test PASSED"

/**
Sends 30 multicast packets (one per second) to the mDNS group on the
standard port. An ESP32 running the companion receiver test should
print each packet it gets.
*/
cross-device-send network/net.Client:
  print "=== Sending multicast to mDNS group (224.0.0.251:$MDNS-PORT) ==="
  print "    ESP32 should print received packets.  30 packets, 1/sec."

  sender := udp-impl.Socket network "0.0.0.0" 0
  30.repeat: | i |
    payload := "mcast-probe-$i"
    sender.send
        udp.Datagram
            payload.to-byte-array
            net.SocketAddress MDNS-GROUP MDNS-PORT
    print "  Sent packet $i: $payload"
    sleep --ms=1000

  sender.close
  print "  Cross-device send complete."
