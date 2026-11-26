/**
UDP multicast socket wrapper for mDNS.

Encapsulates the platform-specific details of mDNS multicast networking:
- Joins the mDNS multicast group (`224.0.0.251`)
- Binds to the mDNS port (`5353`)
- Sets multicast IP TTL to `255` per RFC 6762 §11
- Enables address/port reuse for multiple listeners
- Enables loopback for local testing and self-verification
*/

import net
import net.udp
import .dns-helper as dns

/// Standard mDNS multicast address (IPv4).
MDNS-MULTICAST-ADDRESS ::= net.IpAddress #[224, 0, 0, 251]
/// Standard mDNS port.
MDNS-PORT ::= 5353
/// Recommended mDNS multicast IP hop-limit / TTL (RFC 6762 §11).
MDNS-MULTICAST-TTL ::= 255

/**
UDP socket configured for mDNS multicast communication.

Automatically joins the multicast group and caches the target address
for efficient sending.

# Network reference retention

The network passed to the constructor is stored on the instance and
kept alive for the lifetime of the socket. The Toit network proxy
registers a finalizer that closes the proxy on garbage collection,
decrementing the network service's reference count; retaining $network_
until $close prevents premature Wi-Fi shutdown when mDNS is the last
reference holder.
*/
class MdnsSocket:
  network_/net.Client
  socket_/udp.MulticastSocket
  mdns-target_/net.SocketAddress
  max-payload-size_/int := dns.MAX-MDNS-PACKET-SIZE
  owns-network_/bool
  closed_/bool := false

  constructor
      --network/net.Client
      --group/net.IpAddress=MDNS-MULTICAST-ADDRESS
      --port/int=MDNS-PORT
      --owns-network/bool=true:
    network_ = network
    owns-network_ = owns-network
    mdns-target_ = net.SocketAddress group port
    socket_ = network.udp-open-multicast
        --port=port
        --reuse-address
        --reuse-port
        --loopback
        --ttl=MDNS-MULTICAST-TTL
    socket_.multicast-add-membership group
    catch: max-payload-size_ = min dns.MAX-MDNS-PACKET-SIZE socket_.mtu

  /** Sends $packet to $remote (defaults to the mDNS multicast group). */
  send packet/ByteArray remote/net.SocketAddress=mdns-target_ -> none:
    socket_.send (udp.Datagram packet remote)

  /** Receives the next datagram from the multicast socket. */
  receive -> udp.Datagram?:
    return socket_.receive

  /** Closes the underlying multicast socket (and owned network) idempotently. */
  close -> none:
    if closed_: return
    closed_ = true
    catch: socket_.close
    if owns-network_:
      catch: network_.close

  /** Returns the current interface address of the underlying network. */
  network-address -> net.IpAddress:
    return network_.address

  /** Returns the local socket address. */
  local-address -> net.SocketAddress:
    return socket_.local-address

  /** Returns true if $close has been called. */
  is-closed -> bool:
    return closed_

  /** Returns the maximum UDP payload size for mDNS packets on this socket. */
  max-payload-size -> int:
    return max-payload-size_
