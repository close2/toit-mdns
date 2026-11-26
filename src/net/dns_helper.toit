/**
DNS packet parsing, serialization, and mDNS inspection utilities.

Provides a hardened, bounded mDNS wire parser and encoder on top of the
SDK's `dns` types:
- Enforces RFC 1035 / RFC 9267 compression-pointer safety (strictly
  backward pointers, max hop limit, 63-octet label limit, 255-octet wire
  name limit, per-packet memoization, and section record caps) so crafted
  packets cannot trigger stack overflow or OOM on ESP32 heaps.
- Masks reserved header bits (`Z`, `AD`, `CD`) per RFC 6762 §18 while
  preserving all non-zero `OPCODE` (`1..15`) and `RCODE` values for
  validation.
- Decodes and encodes multi-string / binary-safe `TXT` records and
  restricted-form `NSEC` negative responses (RFC 6762 §6.1).
- Implements RFC 6762 §8.2 pairwise lexicographic probe tiebreaking and
  §9 conflict detection across Answer, Authority, and Additional sections.
*/

import io
import net
import net.modules.dns

/// DNSSEC / mDNS NSEC record type (RFC 4034 / RFC 6762 §6.1).
RECORD-NSEC ::= 47

/// Maximum uncompressed wire domain-name length in octets (RFC 1035 §2.3.4).
MAX-NAME-LENGTH_ ::= 255
/// Maximum compression-pointer jumps permitted while decoding one name.
MAX-POINTER-HOPS_ ::= 16
/// Upper bound on questions per packet to reject compression-bomb DoS packets.
MAX-QUESTIONS_ ::= 64
/// Upper bound on resource records per packet on constrained ESP32 heaps.
MAX-RECORDS_ ::= 128
/// Default multicast mDNS UDP payload limit (1500 MTU minus IP/UDP overhead with margin).
MAX-MDNS-PACKET-SIZE ::= 1440
/// Hard RFC 6762 §17 packet limit including IP and UDP headers.
HARD-MAX-MDNS-PACKET-SIZE_ ::= 9000

/**
Restricted-form mDNS NSEC resource record (RFC 6762 §6.1).

Asserts which record types (in Window Block 0, `0..255`) exist for $name
and that no other record types exist for that unique domain name.
*/
class NsecResource extends dns.Resource:
  next-domain/string
  bitmap/ByteArray

  constructor name/string ttl/int flush/bool .next-domain types/List:
    bitmap = build-bitmap_ types
    super name RECORD-NSEC ttl flush

  constructor.from-bitmap name/string ttl/int flush/bool .next-domain raw-bitmap/ByteArray:
    bitmap = normalize-bitmap_ raw-bitmap
    super name RECORD-NSEC ttl flush

  /** Returns true if $rr-type is marked present in the NSEC bitmap. */
  has-type rr-type/int -> bool:
    if rr-type < 0 or rr-type >= 256: return false
    byte-idx := rr-type >> 3
    if byte-idx >= bitmap.size: return false
    return (bitmap[byte-idx] & (0x80 >> (rr-type & 7))) != 0

  /** Returns the list of RR type codes marked present in Window Block 0. */
  types -> List:
    out := []
    bitmap.size.repeat: | byte-idx |
      b := bitmap[byte-idx]
      if b != 0:
        8.repeat: | bit |
          if (b & (0x80 >> bit)) != 0:
            out.add ((byte-idx << 3) | bit)
    return out

  static build-bitmap_ types/List -> ByteArray:
    max-type := 0
    types.do: | t/int |
      if 0 <= t < 256 and t > max-type: max-type = t
    bm-len := (max-type >> 3) + 1
    out := ByteArray bm-len
    types.do: | t/int |
      if 0 <= t < 256:
        out[t >> 3] |= 0x80 >> (t & 7)
    return normalize-bitmap_ out

  static normalize-bitmap_ raw/ByteArray -> ByteArray:
    limit := min raw.size 32
    last-nz := -1
    limit.repeat: | i |
      if raw[i] != 0: last-nz = i
    if last-nz < 0: return #[0]
    if last-nz + 1 == raw.size: return raw
    return raw[..last-nz + 1]

/**
Fast zero-allocation check on a raw UDP payload before full parsing.

Returns false if $packet is shorter than the 12-byte DNS header or has a
non-zero `OPCODE` (RFC 6762 §18.3) or `RCODE` (RFC 6762 §18.11).
*/
is-valid-raw-mdns-header packet/ByteArray -> bool:
  if packet.size < 12: return false
  opcode := (packet[2] >> 3) & 0x0f
  if opcode != 0: return false
  rcode := packet[3] & 0x0f
  if rcode != 0: return false
  return true

/**
Decodes a raw packet into a $dns.DecodedPacket.

Uses a hardened lenient mDNS decoder that:
- Tolerates records whose CLASS is not IN (e.g. EDNS0 OPT pseudo-records).
- Masks reserved header bits (`Z`, `AD`, `CD`) per RFC 6762 §18 while
  preserving non-zero `OPCODE` values (`1..15`) so $is-valid-mdns-message
  rejects all non-zero opcodes (including `NOTIFY` = 4).
- Bounds name compression pointers, wire lengths, and record counts.
*/
parse packet/ByteArray -> dns.DecodedPacket:
  if packet.size < 12: throw "TRUNCATED_DNS_PACKET"
  reader := io.Reader packet
  received-id    := reader.big-endian.read-uint16
  status-bits    := reader.big-endian.read-uint16
  queries        := reader.big-endian.read-uint16
  response-count := reader.big-endian.read-uint16
  auth-count     := reader.big-endian.read-uint16
  add-count      := reader.big-endian.read-uint16

  if queries > MAX-QUESTIONS_ or (response-count + auth-count + add-count) > MAX-RECORDS_:
    throw "DNS_PACKET_TOO_MANY_RECORDS"

  // RFC 6762 §18: Reserved bits Z, AD, CD (0x0070) MUST be ignored on
  // reception (Android NSD sets AD=1 on multicast queries).
  // However, SDK's DecodedPacket throws if opcode > 2 (upper opcode bits
  // 0x6000). Preserve any non-zero opcode (1..15) as opcode=1 so
  // DecodedPacket constructs cleanly and is-valid-mdns-message returns false.
  raw-opcode := (status-bits & 0x7800) >> 11
  sanitized-bits := status-bits & ~0x0070
  if raw-opcode != 0:
    sanitized-bits = (sanitized-bits & ~0x7800) | 0x0800

  result := dns.DecodedPacket --id=received-id --status-bits=sanitized-bits
  name-cache := {:}

  queries.repeat:
    question := decode-question_ reader packet name-cache
    if question: result.questions.add question

  response-count.repeat:
    resource := decode-resource_ reader packet name-cache
    if resource: result.resources.add resource

  auth-count.repeat:
    resource := decode-resource_ reader packet name-cache
    if resource: result.authorities.add resource

  add-count.repeat:
    resource := decode-resource_ reader packet name-cache
    if resource: result.additionals.add resource

  return result

decode-question_ reader/io.Reader packet/ByteArray name-cache/Map -> dns.Question?:
  q-name := decode-name_ reader packet name-cache
  if reader.processed + 4 > packet.size: throw "TRUNCATED_DNS_QUESTION"
  q-type := reader.big-endian.read-uint16
  q-class := reader.big-endian.read-uint16
  unicast-ok := q-class & 0x8000 != 0
  // mDNS uses CLASS-INTERNET (1) or CLASS-ANY (255). Skip unsupported classes.
  masked-class := q-class & 0x7fff
  if masked-class != dns.CLASS-INTERNET and masked-class != 0xff:
    return null
  return dns.Question q-name q-type --unicast-ok=unicast-ok

decode-resource_ reader/io.Reader packet/ByteArray name-cache/Map -> dns.Resource?:
  r-name := decode-name_ reader packet name-cache
  if reader.processed + 10 > packet.size: throw "TRUNCATED_DNS_RECORD"
  type := reader.big-endian.read-uint16
  clas := reader.big-endian.read-uint16
  ttl := reader.big-endian.read-int32
  // RFC 2181 §8: TTL values with the MSB set (negative int32) are treated as 0.
  if ttl < 0: ttl = 0
  rd-length := reader.big-endian.read-uint16

  if reader.processed + rd-length > packet.size:
    throw "TRUNCATED_DNS_RDATA"

  flush := clas & 0x8000 != 0
  // Skip records with non-IN class (e.g. EDNS0 OPT pseudo-records).
  if clas & 0x7fff != dns.CLASS-INTERNET:
    reader.skip rd-length
    return null

  read-before := reader.processed
  result/dns.Resource? := null
  if type == dns.RECORD-A or type == dns.RECORD-AAAA:
    length := type == dns.RECORD-A ? 4 : 16
    if rd-length != length: throw "CORRUPT_ADDRESS_RECORD"
    result = dns.AResource r-name type ttl flush
        net.IpAddress (reader.read-bytes length)
  else if type == dns.RECORD-PTR or type == dns.RECORD-CNAME:
    result = dns.StringResource r-name type ttl flush
        decode-name_ reader packet name-cache
  else if type == dns.RECORD-TXT:
    strings := []
    remaining := rd-length
    while remaining > 0:
      str-len := reader.read-byte
      remaining--
      if str-len > remaining: throw "CORRUPT_TXT_RECORD"
      // RFC 6763 §6.5: TXT values may contain arbitrary binary data. Keep
      // valid UTF-8 as `string` and preserve anything else as raw `ByteArray`.
      bytes := reader.read-bytes str-len
      strings.add (bytes.is-valid-string-content ? bytes.to-string : bytes)
      remaining -= str-len
    result = dns.TxtResource r-name ttl flush strings
  else if type == dns.RECORD-SRV:
    if rd-length < 7: throw "CORRUPT_SRV_RECORD"
    priority := reader.big-endian.read-uint16
    weight := reader.big-endian.read-uint16
    port := reader.big-endian.read-uint16
    value := decode-name_ reader packet name-cache
    result = dns.SrvResource r-name type ttl flush value priority weight port
  else if type == RECORD-NSEC:
    if rd-length > MAX-MDNS-PACKET-SIZE: throw "CORRUPT_NSEC_RECORD"
    next-domain := decode-name_ reader packet name-cache
    prev-window := -1
    bitmap := #[0]
    while (reader.processed - read-before) < rd-length:
      if (rd-length - (reader.processed - read-before)) < 2:
        throw "CORRUPT_NSEC_RECORD"
      window := reader.read-byte
      bm-len := reader.read-byte
      if bm-len < 1 or bm-len > 32: throw "CORRUPT_NSEC_RECORD"
      if window <= prev-window: throw "CORRUPT_NSEC_RECORD"
      prev-window = window
      if (reader.processed - read-before) + bm-len > rd-length:
        throw "CORRUPT_NSEC_RECORD"
      if window == 0:
        bitmap = reader.read-bytes bm-len
      else:
        reader.skip bm-len
    result = NsecResource.from-bitmap r-name ttl flush next-domain bitmap

  read-after := reader.processed
  to-skip := rd-length - (read-after - read-before)
  if to-skip < 0:
    throw "CORRUPT_DNS_RECORD"
  reader.skip to-skip
  return result

/**
Bounded, non-recursive DNS domain-name decoder.

Enforces:
- Strictly backward compression pointers (`12 <= target < current_offset`),
  preventing self-loops and mutual pointer cycles in O(1) space.
- Maximum $MAX-POINTER-HOPS_ pointer jumps.
- Label length `<= 63` octets and total uncompressed wire name `<= 255` octets.
- Per-packet pointer target memoization via $name-cache so repeated
  compressed references reuse the same immutable string instance.
*/
decode-name_ reader/io.Reader packet/ByteArray name-cache/Map?=null -> string:
  start-pos := reader.processed
  packet-size := packet.size
  if start-pos >= packet-size: throw "TRUNCATED_DNS_NAME"

  first-byte := packet[start-pos]
  if (first-byte & 0xc0) == 0xc0:
    if start-pos + 1 >= packet-size: throw "TRUNCATED_DNS_POINTER"
    target := ((first-byte & 0x3f) << 8) | packet[start-pos + 1]
    if target < 12 or target >= start-pos: throw "INVALID_DNS_POINTER"
    if name-cache and name-cache.contains target:
      reader.skip 2
      return name-cache[target]

  parts := []
  pos := start-pos
  end-pos := -1
  hops := 0
  wire-len := 0

  while true:
    if pos >= packet-size: throw "TRUNCATED_DNS_NAME"
    len := packet[pos]
    if len == 0:
      wire-len += 1
      if wire-len > MAX-NAME-LENGTH_: throw "DNS_NAME_TOO_LONG"
      if end-pos == -1: end-pos = pos + 1
      break
    if (len & 0xc0) == 0xc0:
      if pos + 1 >= packet-size: throw "TRUNCATED_DNS_POINTER"
      target := ((len & 0x3f) << 8) | packet[pos + 1]
      if target < 12 or target >= pos: throw "INVALID_DNS_POINTER"
      if end-pos == -1: end-pos = pos + 2
      hops++
      if hops > MAX-POINTER-HOPS_: throw "DNS_POINTER_LOOP"
      if name-cache and name-cache.contains target:
        cached-suffix/string := name-cache[target]
        if not cached-suffix.is-empty:
          wire-len += cached-suffix.size + 2
          if wire-len > MAX-NAME-LENGTH_: throw "DNS_NAME_TOO_LONG"
          parts.add cached-suffix
        else:
          wire-len += 1
          if wire-len > MAX-NAME-LENGTH_: throw "DNS_NAME_TOO_LONG"
        break
      pos = target
      continue
    if len > 63:
      throw "INVALID_DNS_LABEL"
    if pos + 1 + len > packet-size: throw "TRUNCATED_DNS_LABEL"
    wire-len += 1 + len
    if wire-len > MAX-NAME-LENGTH_: throw "DNS_NAME_TOO_LONG"
    label := packet[pos + 1 .. pos + 1 + len].to-string-non-throwing
    if label == "\0": throw "INVALID_DNS_LABEL"
    parts.add label
    pos += 1 + len

  reader.skip (end-pos - start-pos)
  result := parts.join "."
  if name-cache and start-pos >= 12 and not result.is-empty:
    name-cache[start-pos] = result
  return result

/**
Serializes an mDNS/DNS packet into wire format, supporting standard SDK
$dns.Resource subclasses as well as $NsecResource and binary/multi-string
$dns.TxtResource entries.
*/
encode-mdns-packet queries/List records/List -> ByteArray
    --id/int=0
    --is-response/bool
    --is-authoritative/bool=false
    --authorities/List=[]
    --additionals/List=[]:
  locations := {:}
  result := io.Buffer
  status-bits := is-response ? 0x8000 : 0x0000
  if is-authoritative: status-bits |= 0x0400

  be := result.big-endian
  be.write-int16 id
  be.write-int16 status-bits
  be.write-int16 queries.size
  be.write-int16 records.size
  be.write-int16 authorities.size
  be.write-int16 additionals.size

  queries.do: | query/dns.Question |
    write-name_ query.name --locations=locations --buffer=result
    be.write-int16 query.type
    clas := dns.CLASS-INTERNET | (query.unicast-ok ? 0x8000 : 0)
    be.write-int16 clas

  records.do: | record/dns.Resource |
    write-resource_ record --locations=locations --buffer=result
  authorities.do: | record/dns.Resource |
    write-resource_ record --locations=locations --buffer=result
  additionals.do: | record/dns.Resource |
    write-resource_ record --locations=locations --buffer=result

  return result.bytes

/**
Serializes an mDNS message into one or more wire packets, each at most
$max-size octets (RFC 6762 §17).

Packs $queries, $records, and $authorities in order, splitting across
additional packets on overflow. For outgoing queries with Known-Answers,
sets the `TC` bit on every non-final packet per RFC 6762 §7.2. Optional
$additionals are added opportunistically to the final packet and dropped if
they do not fit. Throws `"DNS_RECORD_EXCEEDS_MAX_PACKET_SIZE"` if a single
question or record exceeds $max-size on its own.
*/
encode-mdns-packets queries/List records/List -> List
    --id/int=0
    --is-response/bool
    --is-authoritative/bool=false
    --authorities/List=[]
    --additionals/List=[]
    --max-size/int=MAX-MDNS-PACKET-SIZE:
  effective-max := min max-size HARD-MAX-MDNS-PACKET-SIZE_
  status-bits := is-response ? 0x8000 : 0x0000
  if is-authoritative: status-bits |= 0x0400

  packets := []
  builder := PacketBuilder_ id status-bits effective-max

  queries.do: | q/dns.Question |
    if not builder.try-add-question q:
      if builder.is-empty: throw "DNS_RECORD_EXCEEDS_MAX_PACKET_SIZE"
      packets.add (builder.build --no-truncated)
      builder = PacketBuilder_ id status-bits effective-max
      if not builder.try-add-question q:
        throw "DNS_RECORD_EXCEEDS_MAX_PACKET_SIZE"

  records.do: | r/dns.Resource |
    if not builder.try-add-record r 1:
      if builder.is-empty: throw "DNS_RECORD_EXCEEDS_MAX_PACKET_SIZE"
      // RFC 6762 §7.2: Set TC on non-final query packets carrying Known-Answers.
      is-ka-split := not is-response and authorities.is-empty
      packets.add (builder.build --truncated=is-ka-split)
      builder = PacketBuilder_ id status-bits effective-max
      if not builder.try-add-record r 1:
        throw "DNS_RECORD_EXCEEDS_MAX_PACKET_SIZE"

  authorities.do: | r/dns.Resource |
    if not builder.try-add-record r 2:
      if builder.is-empty: throw "DNS_RECORD_EXCEEDS_MAX_PACKET_SIZE"
      packets.add (builder.build --no-truncated)
      builder = PacketBuilder_ id status-bits effective-max
      if not builder.try-add-record r 2:
        throw "DNS_RECORD_EXCEEDS_MAX_PACKET_SIZE"

  // Additionals are opportunistic: keep what fits in the last packet and drop the rest.
  additionals.do: | r/dns.Resource |
    builder.try-add-record r 3

  if not builder.is-empty or packets.is-empty:
    packets.add (builder.build --no-truncated)

  return packets

class PacketBuilder_:
  id_/int
  status-bits_/int
  max-size_/int
  buffer_/io.Buffer := io.Buffer
  locations_/Map := {:}
  qd-count_/int := 0
  an-count_/int := 0
  ns-count_/int := 0
  ar-count_/int := 0

  constructor .id_ .status-bits_ .max-size_:
    12.repeat: buffer_.write-byte 0

  is-empty -> bool:
    return qd-count_ == 0 and an-count_ == 0 and ns-count_ == 0 and ar-count_ == 0

  try-add-question q/dns.Question -> bool:
    saved-size := buffer_.size
    write-name_ q.name --locations=locations_ --buffer=buffer_
    be := buffer_.big-endian
    be.write-int16 q.type
    be.write-int16 (dns.CLASS-INTERNET | (q.unicast-ok ? 0x8000 : 0))
    if buffer_.size > max-size_:
      rollback_ saved-size
      return false
    qd-count_++
    return true

  try-add-record rec/dns.Resource section/int -> bool:
    saved-size := buffer_.size
    write-resource_ rec --locations=locations_ --buffer=buffer_
    if buffer_.size > max-size_:
      rollback_ saved-size
      return false
    if section == 1: an-count_++
    else if section == 2: ns-count_++
    else: ar-count_++
    return true

  rollback_ saved-size/int -> none:
    buffer_.resize saved-size
    locations_.filter --in-place: | _ loc/int | loc < saved-size

  build --truncated/bool=false -> ByteArray:
    bytes := buffer_.bytes
    bits := truncated ? (status-bits_ | 0x0200) : status-bits_
    io.BIG-ENDIAN.put-uint16 bytes 0 id_
    io.BIG-ENDIAN.put-uint16 bytes 2 bits
    io.BIG-ENDIAN.put-uint16 bytes 4 qd-count_
    io.BIG-ENDIAN.put-uint16 bytes 6 an-count_
    io.BIG-ENDIAN.put-uint16 bytes 8 ns-count_
    io.BIG-ENDIAN.put-uint16 bytes 10 ar-count_
    return bytes

write-resource_ record/dns.Resource --locations/Map? --buffer/io.Buffer -> none:
  write-name_ record.name --locations=locations --buffer=buffer
  be := buffer.big-endian
  type := record.type
  be.write-int16 type
  clas := dns.CLASS-INTERNET | (record.flush ? 0x8000 : 0)
  be.write-int16 clas
  be.write-int32 record.ttl

  if record is dns.AResource:
    bytes := (record as dns.AResource).address.raw
    be.write-int16 bytes.size
    buffer.write bytes
  else if type == dns.RECORD-CNAME or type == dns.RECORD-PTR:
    str := (record as dns.StringResource).value
    length := write-name_ str --locations=locations --buffer=null
    be.write-int16 length
    write-name_ str --locations=locations --buffer=buffer
  else if type == dns.RECORD-TXT:
    if record is dns.TxtResource:
      txt := record as dns.TxtResource
      entries := txt.text.is-empty ? [""] : txt.text
      total-len := 0
      entries.do: | s |
        sz := s.size
        if sz > 255: throw "TXT character-string exceeds 255 octets"
        total-len += sz + 1
      be.write-int16 total-len
      entries.do: | s |
        buffer.write-byte s.size
        buffer.write s
    else:
      str := (record as dns.StringResource).value
      if str.size > 255: throw "TXT character-string exceeds 255 octets"
      be.write-int16 (str.size + 1)
      buffer.write-byte str.size
      buffer.write str
  else if record is dns.SrvResource:
    srv := record as dns.SrvResource
    // RFC 6762 §18.14: SRV target MAY be compressed in mDNS, or uncompressed.
    name-length := write-name_ srv.value --locations=locations --buffer=null
    be.write-int16 (6 + name-length)
    be.write-int16 srv.priority
    be.write-int16 srv.weight
    be.write-int16 srv.port
    write-name_ srv.value --locations=locations --buffer=buffer
  else if record is NsecResource:
    nsec := record as NsecResource
    // Write uncompressed next-domain (valid in both multicast mDNS and legacy unicast).
    name-length := write-name_ nsec.next-domain --locations=null --buffer=null
    bm := encode-nsec-bitmap_ nsec.bitmap
    be.write-int16 (name-length + bm.size)
    write-name_ nsec.next-domain --locations=null --buffer=buffer
    buffer.write bm
  else:
    throw "Unsupported DNS resource type: $type"

encode-nsec-bitmap_ bitmap/ByteArray -> ByteArray:
  bm-len := bitmap.size
  out := ByteArray (2 + bm-len)
  out[0] = 0  // Window Block 0.
  out[1] = bm-len
  out.replace 2 bitmap
  return out

write-name_ name/string --locations/Map? --buffer/io.Buffer? -> int:
  if name.is-empty:
    if buffer: buffer.write-byte 0
    return 1
  parts := name.split "."
  length := 0
  pos := 0
  parts.do: | part/string |
    if part.size > 63: throw "DNS label exceeds 63 octets: $name"
    if part.size < 1: throw "Empty DNS label in: $name"
    tail := name[pos..]
    tail-key := tail.to-ascii-lower
    pos += part.size + 1
    if locations:
      locations.get tail-key --if-present=: | location/int |
        if location < 0x3fff:
          if buffer: buffer.big-endian.write-int16 (location | 0xc000)
          length += 2
          if length > MAX-NAME-LENGTH_: throw "DNS name exceeds 255 octets: $name"
          return length
    if buffer:
      if locations and buffer.size < 0x3fff:
        locations[tail-key] = buffer.size
      buffer.write-byte part.size
      buffer.write part
    length += part.size + 1
    if length >= MAX-NAME-LENGTH_: throw "DNS name exceeds 255 octets: $name"
  if buffer: buffer.write-byte 0
  return length + 1

/**
Case-insensitive comparison of DNS names per RFC 6762 §16.

ASCII letters in `a..z` match their uppercase equivalents in `A..Z`.
All other bytes (including UTF-8 multi-byte sequences) are compared by
binary equality without heap allocation.
*/
name-equals a/string b/string -> bool:
  if identical a b: return true
  if a.size != b.size: return false
  size := a.size
  for i := 0; i < size; i++:
    ca := a.at --raw i
    cb := b.at --raw i
    if ca == cb: continue
    if 'A' <= ca <= 'Z': ca += 'a' - 'A'
    if 'A' <= cb <= 'Z': cb += 'a' - 'A'
    if ca != cb: return false
  return true

/**
Truncates $s to at most $max-bytes octets without splitting a UTF-8 rune.
*/
truncate-utf8 s/string max-bytes/int -> string:
  if s.size <= max-bytes: return s
  end := max-bytes
  // Step back over UTF-8 continuation bytes (0b10xxxxxx) so we never split a rune.
  while end > 0 and ((s.at --raw end) & 0xc0) == 0x80:
    end--
  return s[..end]

/**
Returns true if $name ends with $suffix (matched ASCII case-insensitively)
with a non-empty prefix, without allocating.
*/
name-ends-with_ name/string suffix/string -> bool:
  if name.size <= suffix.size: return false
  offset := name.size - suffix.size
  suffix.size.repeat: | i |
    ca := name.at --raw (offset + i)
    cb := suffix.at --raw i
    if 'A' <= ca <= 'Z': ca += 'a' - 'A'
    if 'A' <= cb <= 'Z': cb += 'a' - 'A'
    if ca != cb: return false
  return true

/**
Returns true if $name has a non-empty prefix followed by `.local`
(matched case-insensitively per RFC 6762 §16).
*/
has-local-suffix name/string -> bool:
  return name-ends-with_ name ".local"

/**
Returns true if $name is valid for multicast DNS lookup (`.local`,
`.in-addr.arpa`, or `.ip6.arpa`, matched case-insensitively per RFC 6762 §4).
*/
is-mdns-lookup-name name/string -> bool:
  return (has-local-suffix name) or
      (name-ends-with_ name ".in-addr.arpa") or
      (name-ends-with_ name ".ip6.arpa")

/**
Validates that a decoded packet conforms to mDNS header requirements
(RFC 6762 §18.3 `OPCODE == 0` and §18.11 `RCODE == 0`).
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
Checks if two resources represent the same `(name, type, rdata)` tuple,
ignoring `ttl` and `flush` bits.

DNS domain names (`owner`, `PTR`/`CNAME`/`SRV`/`NSEC` targets) are compared
case-insensitively per RFC 6762 §16; `TXT` character-strings are compared
case-sensitively per RFC 6763 §6.4.
*/
resource-equals a/dns.Resource b/dns.Resource -> bool:
  if a.type != b.type: return false
  if not name-equals a.name b.name: return false
  return resource-rdata-matches_ a b

resource-rdata-matches_ actual/dns.Resource expected/dns.Resource -> bool:
  if actual is dns.AResource and expected is dns.AResource:
    return (actual as dns.AResource).address == (expected as dns.AResource).address
  if actual is dns.SrvResource and expected is dns.SrvResource:
    actual-srv := actual as dns.SrvResource
    expected-srv := expected as dns.SrvResource
    return actual-srv.priority == expected-srv.priority and
        actual-srv.weight == expected-srv.weight and
        actual-srv.port == expected-srv.port and
        (name-equals actual-srv.value expected-srv.value)
  if actual is dns.TxtResource and expected is dns.TxtResource:
    ta := (actual as dns.TxtResource).text
    tb := (expected as dns.TxtResource).text
    if ta.size != tb.size: return false
    ta.size.repeat: | i |
      if ta[i] != tb[i]: return false
    return true
  if actual is dns.StringResource and expected is dns.StringResource:
    sa := (actual as dns.StringResource).value
    sb := (expected as dns.StringResource).value
    if actual.type == dns.RECORD-TXT:
      return sa == sb
    return name-equals sa sb
  if actual is NsecResource and expected is NsecResource:
    na := actual as NsecResource
    nb := expected as NsecResource
    if not name-equals na.next-domain nb.next-domain: return false
    return na.bitmap == nb.bitmap
  return false

/**
Checks if a query contains known answers that suppress our response
(RFC 6762 §7.1: suppress when matching RR has TTL >= 50% of $our-ttl).
*/
has-known-answer query/dns.DecodedPacket name/string type/int our-ttl/int
    --data/string?=null
    --record/dns.Resource?=null -> bool:
  half-ttl := our-ttl / 2
  query.resources.do: | res/dns.Resource |
    if (name-equals res.name name) and res.type == type and res.ttl >= half-ttl:
      if record:
        if resource-rdata-matches_ res record: return true
        continue.do
      if data == null: return true
      if (res is dns.StringResource) and
          name-equals (res as dns.StringResource).value data:
        return true
  return false

/**
Checks if a packet is a positive response carrying records for $name.

Per RFC 6762 §18.4, the `AA` header bit MUST be ignored on reception.
Per RFC 6762 §9, conflicting records may appear in any response section
(Answer, Authority, or Additional). Goodbye records (`TTL == 0`) release
ownership rather than claiming it and are excluded.
*/
is-authoritative-response-for packet/dns.DecodedPacket name/string -> bool:
  if not packet.is-response: return false
  if packet.resources.any (: | r/dns.Resource | r.ttl > 0 and (name-equals r.name name)):
    return true
  if packet.additionals.any (: | r/dns.Resource | r.ttl > 0 and (name-equals r.name name)):
    return true
  return packet.authorities.any: | r/dns.Resource | r.ttl > 0 and (name-equals r.name name)

/**
Iterates all positive (`TTL > 0`) records matching $name across the Answer,
Additional, and Authority sections of a response $packet.
*/
do-response-records-for packet/dns.DecodedPacket name/string [block] -> none:
  if not packet.is-response: return
  packet.resources.do: | r/dns.Resource |
    if r.ttl > 0 and (name-equals r.name name): block.call r
  packet.additionals.do: | r/dns.Resource |
    if r.ttl > 0 and (name-equals r.name name): block.call r
  packet.authorities.do: | r/dns.Resource |
    if r.ttl > 0 and (name-equals r.name name): block.call r

/**
Checks if a packet is a probe query for a specific name (RFC 6762 §8.2).
*/
is-probe-for packet/dns.DecodedPacket name/string -> bool:
  if packet.is-response: return false
  if packet.authorities.is-empty: return false
  return packet.questions.any: name-equals it.name name

/**
Extracts A/AAAA record addresses from the Authority Section for $name.
*/
get-authority-addresses packet/dns.DecodedPacket name/string -> List:
  result := []
  packet.authorities.do: | res |
    if (name-equals res.name name) and res is dns.AResource:
      result.add (res as dns.AResource).address
  return result

/**
Compares two IP addresses lexicographically by raw unsigned bytes (RFC 6762 §8.2).
*/
compare-addresses a/net.IpAddress b/net.IpAddress -> int:
  return compare-bytes_ a.raw b.raw

/**
Performs RFC 6762 §8.2.1 simultaneous-probe tiebreaking for $name.

Compares $our-records against the records for $name in $authority-records
after sorting both sets by `(rrclass, rrtype, canonical_uncompressed_rdata)`.

Returns:
- `null` if $authority-records contains no records for $name.
- A positive integer if we win (`our > their`).
- A negative integer if we lose (`our < their`).
- `0` if both record sets are identical (e.g. multicast loopback of our own probe).
*/
compare-probe-tiebreak our-records/List authority-records/List name/string -> int?:
  their-encoded := []
  authority-records.do: | res/dns.Resource |
    if name-equals res.name name:
      their-encoded.add (canonical-tiebreak-entry_ res)
  if their-encoded.is-empty: return null

  our-encoded := our-records.map: | res/dns.Resource | canonical-tiebreak-entry_ res
  our-encoded.sort --in-place: | a b | compare-tiebreak-entry_ a b
  their-encoded.sort --in-place: | a b | compare-tiebreak-entry_ a b

  pair-count := min our-encoded.size their-encoded.size
  pair-count.repeat: | i |
    diff := compare-tiebreak-entry_ our-encoded[i] their-encoded[i]
    if diff != 0: return diff
  return our-encoded.size - their-encoded.size

canonical-tiebreak-entry_ res/dns.Resource -> List:
  buf := io.Buffer
  be := buf.big-endian
  if res is dns.AResource:
    buf.write (res as dns.AResource).address.raw
  else if res is dns.SrvResource:
    srv := res as dns.SrvResource
    be.write-int16 srv.priority
    be.write-int16 srv.weight
    be.write-int16 srv.port
    write-name_ srv.value.to-ascii-lower --locations=null --buffer=buf
  else if res is dns.TxtResource:
    txt := res as dns.TxtResource
    entries := txt.text.is-empty ? [""] : txt.text
    entries.do: | s |
      buf.write-byte s.size
      buf.write s
  else if res is dns.StringResource:
    str := (res as dns.StringResource).value
    if res.type == dns.RECORD-PTR or res.type == dns.RECORD-CNAME:
      write-name_ str.to-ascii-lower --locations=null --buffer=buf
    else:
      buf.write-byte str.size
      buf.write str
  else if res is NsecResource:
    nsec := res as NsecResource
    write-name_ nsec.next-domain.to-ascii-lower --locations=null --buffer=buf
    buf.write (encode-nsec-bitmap_ nsec.bitmap)
  return [dns.CLASS-INTERNET, res.type, buf.bytes]

compare-tiebreak-entry_ a/List b/List -> int:
  class-diff := (a[0] as int) - (b[0] as int)
  if class-diff != 0: return class-diff
  type-diff := (a[1] as int) - (b[1] as int)
  if type-diff != 0: return type-diff
  return compare-bytes_ (a[2] as ByteArray) (b[2] as ByteArray)

compare-bytes_ a/ByteArray b/ByteArray -> int:
  min-len := min a.size b.size
  for i := 0; i < min-len; i++:
    diff := a[i] - b[i]
    if diff != 0: return diff
  return a.size - b.size
