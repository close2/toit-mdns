/**
DNS packet parsing and inspection utilities.

Thin wrappers around the SDK's dns module that provide mDNS-specific
packet analysis. These helpers are used by the state manager to detect
conflicts and identify relevant queries.

# Authoritative Response Detection

In mDNS, an "authoritative" response from another device for our
claimed name indicates a conflict. We check both the response flag
and the authoritative flag per RFC 6762 Section 9.

# Simultaneous Probe Tiebreaking (RFC 6762 Section 8.2)

When two hosts probe for the same name simultaneously, tiebreaking is
done by comparing the proposed records in the Authority Section.
The host with lexicographically later rdata wins. The loser defers
by waiting one second, then re-probes.
*/

import net
import net.modules.dns

/** Decodes a raw packet into a DecodedPacket (from SDK). */
parse packet/ByteArray -> dns.DecodedPacket:
  return dns.decode-packet packet --error-name="incoming_packet"

/**
Validates that a decoded packet conforms to mDNS header requirements.

RFC 6762 §18.3: OPCODE MUST be zero; messages with non-zero OPCODE
  MUST be silently ignored.
RFC 6762 §18.11: RCODE MUST be zero; messages with non-zero RCODE
  MUST be silently ignored.

Returns true if the packet is valid and should be processed.
*/
is-valid-mdns-message packet/dns.DecodedPacket -> bool:
  if packet.opcode != 0: return false
  if packet.error-code != 0: return false
  return true

/** Checks if a packet is a query for a specific name. */
is-query-for packet/dns.DecodedPacket name/string -> bool:
  if packet.is-response: return false
  return packet.questions.any: it.name == name

/**
Checks if a query contains known answers that suppress our response.

RFC 6762 §7.1: "A Multicast DNS responder MUST NOT answer a Multicast
  DNS query if the answer it would give is already included in the
  Answer Section with an RR TTL at least half the correct value."

The $type parameter specifies the record type to match (e.g.
  $dns.RECORD-A, $dns.RECORD-PTR).
The optional $data parameter, when provided, additionally matches
  against the string value of PTR/CNAME records to avoid suppressing
  responses for a different service instance sharing the same
  type-domain.

Returns true if the query's Known-Answer Section already contains
  a matching record with ≥ 50% of our TTL, meaning we should suppress.
*/
has-known-answer query/dns.DecodedPacket name/string type/int our-ttl/int --data/string?=null -> bool:
  query.resources.do: | res |
    if res.name == name and res.type == type and res.ttl >= (our-ttl / 2):
      if data == null: return true
      // For PTR/CNAME records, also verify the string data matches
      // our specific instance.
      if (res is dns.StringResource) and (res as dns.StringResource).value == data:
        return true
  return false

/**
Checks if a packet is an authoritative response for a specific name.

Used for conflict detection - if we receive an authoritative response
for our claimed hostname from another device, we must either defend
or rename.
*/
is-authoritative-response-for packet/dns.DecodedPacket name/string -> bool:
  if not packet.is-response: return false
  if not packet.is-authoritative: return false
  // Check answers for the name.
  return packet.resources.any: it.name == name

/**
Checks if a packet is a probe query for a specific name.

A probe is a query (not a response) that has records in the Authority
Section. Per RFC 6762 Section 8.2, probers include their proposed
records in the Authority Section for tiebreaking.
*/
is-probe-for packet/dns.DecodedPacket name/string -> bool:
  if packet.is-response: return false
  if packet.authorities.is-empty: return false
  return packet.questions.any: it.name == name

/**
Extracts A record addresses from the Authority Section for a given name.

Returns the list of $net.IpAddress values proposed in the probe's
Authority Section for tiebreaking comparison.
*/
get-authority-addresses packet/dns.DecodedPacket name/string -> List:
  result := []
  packet.authorities.do: | res |
    if res.name == name and res is dns.AResource:
      result.add (res as dns.AResource).address
  return result

/**
Compares two IP addresses lexicographically by raw bytes.

Returns:
  - A positive number if $a is lexicographically later (a wins).
  - A negative number if $b is lexicographically later (b wins).
  - 0 if they are identical.

Per RFC 6762 Section 8.2, bytes are compared as unsigned 8-bit values.
*/
compare-addresses a/net.IpAddress b/net.IpAddress -> int:
  a-bytes := a.raw
  b-bytes := b.raw
  // Compare raw bytes pairwise as unsigned values, then by length.
  // When one address is IPv4 (4 bytes) and the other is IPv6 (16 bytes),
  // the shorter one is considered "earlier" after the shared prefix.
  min-len := min a-bytes.size b-bytes.size
  for i := 0; i < min-len; i++:
    diff := a-bytes[i] - b-bytes[i]
    if diff != 0: return diff
  return a-bytes.size - b-bytes.size