/**
DNS packet parsing and inspection utilities.

Thin wrappers around the SDK's dns module that provide mDNS-specific
packet analysis. These helpers are used by the state manager to detect
conflicts and identify relevant queries.

# Authoritative Response Detection

In mDNS, an "authoritative" response from another device for our
claimed name indicates a conflict. We check both the response flag
and the authoritative flag per RFC 6762 Section 9.
*/

import net.modules.dns

/** Decodes a raw packet into a DecodedPacket (from SDK). */
parse packet/ByteArray -> dns.DecodedPacket:
  return dns.decode-packet packet --error-name="incoming_packet"

/** Checks if a packet is a query for a specific name. */
is-query-for packet/dns.DecodedPacket name/string -> bool:
  if packet.is-response: return false
  return packet.questions.any: it.name == name

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