/**
UDP multicast socket wrapper for mDNS.

Encapsulates the platform-specific details of mDNS multicast networking:
- Joins the mDNS multicast group (224.0.0.251)
- Binds to the mDNS port (5353)
- Enables address/port reuse for multiple listeners
- Enables loopback for local testing and self-verification

# Multicast Constants

These follow RFC 6762 requirements for mDNS:
- Multicast address: 224.0.0.251 (IPv4) or ff02::fb (IPv6)
- Port: 5353
*/

import net
import net.udp

/// Standard mDNS multicast address (IPv4).
MDNS-MULTICAST-ADDRESS ::= net.IpAddress #[224, 0, 0, 251]
/// Standard mDNS port.
MDNS-PORT ::= 5353

/**
UDP socket configured for mDNS multicast communication.

Automatically joins the multicast group and caches the target address
for efficient sending.

# Network reference retention

The network passed to the constructor is stored on the instance and
kept alive for the lifetime of the socket.  This is critical: the
Toit network proxy registers a finalizer that closes the proxy on
garbage collection, which decrements the network service's reference
count.  If our mDNS service is the last holder, GC of the network
reference causes the WiFi module to shut down — manifesting as a
silent `WIFI_DISCONNECTED` event and an unrecoverable wedge of any
other tasks using the same interface.  We therefore retain the
reference explicitly until $close is called.
*/
class MdnsSocket:
  network_/net.Client
  socket_/udp.MulticastSocket
  mdns-target_/net.SocketAddress

  constructor
      --network/net.Client
      --group/net.IpAddress=MDNS-MULTICAST-ADDRESS
      --port/int=MDNS-PORT:
    network_ = network
    mdns-target_ = net.SocketAddress group port
    socket_ = network.udp-open-multicast
        --port=port
        --reuse-address
        --reuse-port
        --loopback  // We want to hear our own packets for testing/verification.
    socket_.multicast-add-membership group

  send packet/ByteArray remote/net.SocketAddress=mdns-target_:
    socket_.send (udp.Datagram packet remote)

  receive -> udp.Datagram?:
    return socket_.receive

  close:
    if closed_: return
    closed_ = true
    socket_.close

  local-address -> net.SocketAddress:
    return socket_.local-address

  is-closed -> bool:
    return closed_

  closed_ := false
