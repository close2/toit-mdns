/**
Packet capture helper for host tests.

Opens a second mDNS socket on the test port and records every datagram it
  receives, so tests can assert on what was actually sent on the wire
  instead of on internal counters.
*/

import net
import net.modules.dns
import mdns.net.dns-helper as dns-helper
import mdns.net.mdns-socket show MdnsSocket

/** A single captured datagram. */
class CapturedPacket:
  data/ByteArray
  source/net.SocketAddress
  decoded/dns.DecodedPacket?
  received-us/int

  constructor .data .source .decoded .received-us:

  /** Whether this packet is a response. */
  is-response -> bool:
    return decoded != null and decoded.is-response

  /** Whether this packet is a probe (a query with a non-empty Authority Section). */
  is-probe -> bool:
    return decoded != null and not decoded.is-response and not decoded.authorities.is-empty

  /** Whether this packet is a probe for $name. */
  is-probe-for name/string -> bool:
    return decoded != null and dns-helper.is-probe-for decoded name

  /** Returns all records of the Answer, Authority, and Additional sections. */
  all-records -> List:
    if not decoded: return []
    return decoded.resources + decoded.authorities + decoded.additionals

  /** Whether any record in this packet is owned by $name. */
  mentions name/string -> bool:
    return all-records.any: | r/dns.Resource | dns-helper.name-equals r.name name

/**
Records all datagrams received on the mDNS group at a given port.
*/
class PacketCapture:
  socket_/MdnsSocket
  packets/List := []  // List of CapturedPacket.
  receiver_/Task? := null

  constructor --port/int:
    socket_ = MdnsSocket --network=net.open --port=port
    receiver_ = task:: receive-loop_

  receive-loop_ -> none:
    while true:
      datagram := null
      e := catch: datagram = socket_.receive
      if e or not datagram: return
      decoded/dns.DecodedPacket? := null
      catch: decoded = dns-helper.parse datagram.data
      packets.add (CapturedPacket datagram.data datagram.address decoded Time.monotonic-us)

  /** Forgets all captured packets. */
  clear -> none:
    packets = []

  /** Returns the captured packets for which $block returns true. */
  filter [block] -> List:
    return packets.filter block

  /**
  Waits until a packet satisfying $block has been captured.

  Returns the packet, or null if $timeout elapses first.
  */
  wait-for --timeout/Duration=(Duration --s=3) [block] -> CapturedPacket?:
    deadline := Time.monotonic-us + timeout.in-us
    seen := 0
    while true:
      while seen < packets.size:
        p := packets[seen++]
        if block.call p: return p
      if Time.monotonic-us >= deadline: return null
      sleep --ms=10

  /** Sends a raw $packet to the mDNS group from the capture socket. */
  send packet/ByteArray -> none:
    socket_.send packet

  /** Closes the capture socket and stops recording. */
  close -> none:
    socket_.close
    if receiver_:
      receiver_.cancel
      receiver_ = null
