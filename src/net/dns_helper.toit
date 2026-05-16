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

import io
import net
import net.modules.dns

/**
Decodes a raw packet into a $dns.DecodedPacket.

Uses a lenient mDNS decoder that tolerates records whose CLASS is
not IN. Such records (OPT pseudo-records that carry a UDP payload
size in the class field, IXFR/AXFR variants, etc.) are silently
skipped instead of failing the whole packet, which would otherwise
hide legitimate IN-class records — including the very conflict
responses we rely on for hostname defense.
*/
parse packet/ByteArray -> dns.DecodedPacket:
  reader := io.Reader packet
  received-id    := reader.big-endian.read-uint16
  status-bits    := reader.big-endian.read-uint16
  queries        := reader.big-endian.read-uint16
  response-count := reader.big-endian.read-uint16
  auth-count     := reader.big-endian.read-uint16
  add-count      := reader.big-endian.read-uint16

  // RFC 6762 §18.4 / §18.5 / §18.6 / §18.7 / §18.10 / §18.12: The AA, TC,
  // RD, RA, Z, AD, and CD header bits MUST be ignored on reception in
  // mDNS messages. The SDK's DecodedPacket constructor, however, treats
  // any of these reserved bits (mask 0x6070 — Z, AD, CD plus a reserved
  // bit) as a protocol error, which silently drops otherwise-valid
  // queries. Android NSD, for example, sets the AD bit (0x0020) on
  // every multicast query (flags 0x0120), which makes the SDK reject
  // those packets and prevents the device from answering nebenuhr.local
  // lookups from Android. Pre-mask these reserved bits so the lenient
  // mDNS parser conforms to RFC 6762 §18 instead of inheriting the
  // SDK's strict unicast-DNS validation.
  sanitized-bits := status-bits & ~0x6070

  result := dns.DecodedPacket --id=received-id --status-bits=sanitized-bits

  queries.repeat:
    question := decode-question_ reader packet
    if question: result.questions.add question

  response-count.repeat:
    resource := decode-resource_ reader packet
    if resource: result.resources.add resource

  auth-count.repeat:
    resource := decode-resource_ reader packet
    if resource: result.authorities.add resource

  add-count.repeat:
    resource := decode-resource_ reader packet
    if resource: result.additionals.add resource

  return result

decode-question_ reader/io.Reader packet/ByteArray -> dns.Question?:
  q-name := dns.decode-name reader packet
  q-type := reader.big-endian.read-uint16
  q-class := reader.big-endian.read-uint16
  unicast-ok := q-class & 0x8000 != 0
  // mDNS uses CLASS-ANY (255) for cache-flush queries and OPT-style
  // questions can have non-IN class. Skip unsupported classes
  // silently instead of throwing.
  if q-class & 0x7fff != dns.CLASS-INTERNET and q-class & 0x7fff != 0xff:
    return null
  return dns.Question q-name q-type --unicast-ok=unicast-ok

decode-resource_ reader/io.Reader packet/ByteArray -> dns.Resource?:
  r-name := dns.decode-name reader packet
  type := reader.big-endian.read-uint16
  clas := reader.big-endian.read-uint16
  ttl := reader.big-endian.read-int32
  rd-length := reader.big-endian.read-uint16

  flush := clas & 0x8000 != 0
  // Skip records with unexpected class (e.g. OPT records carry
  // requestor's UDP payload size in the class field). The rest of
  // the packet must still parse.
  if clas & 0x7fff != dns.CLASS-INTERNET:
    reader.skip rd-length
    return null

  read-before := reader.processed
  result/dns.Resource? := null
  if type == dns.RECORD-A or type == dns.RECORD-AAAA:
    length := type == dns.RECORD-A ? 4 : 16
    if rd-length == length:
      result = dns.AResource r-name type ttl flush
          net.IpAddress (reader.read-bytes length)
  else if type == dns.RECORD-PTR or type == dns.RECORD-CNAME:
    result = dns.StringResource r-name type ttl flush
        dns.decode-name reader packet
  else if type == dns.RECORD-TXT:
    value := ""
    if rd-length > 0:
      length := reader.read-byte
      if rd-length >= length + 1:
        value = reader.read-string length
    result = dns.StringResource r-name type ttl flush value
  else if type == dns.RECORD-SRV:
    priority := reader.big-endian.read-uint16
    weight := reader.big-endian.read-uint16
    port := reader.big-endian.read-uint16
    value := dns.decode-name reader packet
    result = dns.SrvResource r-name type ttl flush value priority weight port

  read-after := reader.processed
  to-skip := rd-length - (read-after - read-before)
  if to-skip < 0:
    // Record reader over-consumed; corrupt record. Skip rest of packet.
    return null
  reader.skip to-skip
  return result

/**
Case-insensitive comparison of DNS names per RFC 6762 §16.

ASCII letters in `a..z` (0x61..0x7A) match their uppercase equivalents
in `A..Z` (0x41..0x5A). All other bytes (including UTF-8 multi-byte
sequences) are compared by binary equality.

This is used everywhere the implementation compares DNS names, since
`MyHost.local`, `myhost.local`, and `MYHOST.LOCAL` must all be treated
as the same name.
*/
name-equals a/string b/string -> bool:
  if identical a b: return true
  if a.size != b.size: return false
  size := a.size
  for i := 0; i < size; i++:
    ca := a.at --raw i
    cb := b.at --raw i
    if ca == cb: continue
    // Lowercase ASCII letters; leave everything else as-is.
    if 'A' <= ca <= 'Z': ca += 'a' - 'A'
    if 'A' <= cb <= 'Z': cb += 'a' - 'A'
    if ca != cb: return false
  return true

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
  return packet.questions.any: name-equals it.name name

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
has-known-answer query/dns.DecodedPacket name/string type/int our-ttl/int
    --data/string?=null
    --record/dns.Resource?=null -> bool:
  query.resources.do: | res |
    if (name-equals res.name name) and res.type == type and res.ttl >= (our-ttl / 2):
      if record:
        if resource-data-matches_ res record: return true
        continue.do
      if data == null: return true
      // For PTR/CNAME records, also verify the string data matches
      // our specific instance.
      if (res is dns.StringResource) and
          name-equals (res as dns.StringResource).value data:
        return true
  return false

resource-data-matches_ actual/dns.Resource expected/dns.Resource -> bool:
  if actual.type != expected.type: return false
  if not name-equals actual.name expected.name: return false
  if actual is dns.AResource and expected is dns.AResource:
    return (actual as dns.AResource).address == (expected as dns.AResource).address
  if actual is dns.SrvResource and expected is dns.SrvResource:
    actual-srv := actual as dns.SrvResource
    expected-srv := expected as dns.SrvResource
    return actual-srv.priority == expected-srv.priority and
      actual-srv.weight == expected-srv.weight and
      actual-srv.port == expected-srv.port and
      (name-equals actual-srv.value expected-srv.value)
  if actual is dns.StringResource and expected is dns.StringResource:
    return name-equals (actual as dns.StringResource).value (expected as dns.StringResource).value
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
  return packet.resources.any: name-equals it.name name

/**
Checks if a packet is a probe query for a specific name.

A probe is a query (not a response) that has records in the Authority
Section. Per RFC 6762 Section 8.2, probers include their proposed
records in the Authority Section for tiebreaking.
*/
is-probe-for packet/dns.DecodedPacket name/string -> bool:
  if packet.is-response: return false
  if packet.authorities.is-empty: return false
  return packet.questions.any: name-equals it.name name

/**
Extracts A record addresses from the Authority Section for a given name.

Returns the list of $net.IpAddress values proposed in the probe's
Authority Section for tiebreaking comparison.
*/
get-authority-addresses packet/dns.DecodedPacket name/string -> List:
  result := []
  packet.authorities.do: | res |
    if (name-equals res.name name) and res is dns.AResource:
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
