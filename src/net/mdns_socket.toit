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
import net.modules.dns


/// Standard mDNS multicast address (IPv4).
MDNS-MULTICAST-ADDRESS ::= net.IpAddress #[224, 0, 0, 251]
/// Standard mDNS port.
MDNS-PORT ::= 5353

/**
UDP socket configured for mDNS multicast communication.

Automatically joins the multicast group and caches the target address
for efficient sending.
*/
class MdnsSocket:
  socket_/udp.Socket
  mdns-target_/net.SocketAddress

  constructor
      --network/net.Client
      --group/net.IpAddress=MDNS-MULTICAST-ADDRESS
      --port/int=MDNS-PORT:
    mdns-target_ = net.SocketAddress group port
    // Use network.udp-open-multicast so the socket is created through the
    // system service proxy on ESP32.  Directly constructing udp_impl.Socket
    // bypasses the proxy and the sends silently fail on ESP32.
    socket_ = network.udp-open-multicast group port
        --reuse-address
        --reuse-port
        --loopback

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
