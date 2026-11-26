/**
Validation helpers for mDNS hostnames, DNS-SD service types, instance names,
and TXT record maps (RFC 6762 / RFC 6763).
*/

import .dns-helper as dns-helper

/// Maximum octets in a single DNS label per RFC 1035 §2.3.4.
MAX-DNS-LABEL-OCTETS ::= 63
/// Maximum octets in an uncompressed DNS wire name per RFC 1035 §2.3.4.
MAX-DNS-NAME-OCTETS ::= 255
/// Maximum octets in a single TXT `<character-string>` per RFC 6763 §6.1.
MAX-TXT-ENTRY-OCTETS ::= 255
/// Maximum total TXT RDATA octets so a service probe fits inside Toit's UDP MTU.
MAX-TXT-RDATA-OCTETS ::= 1200

/**
Validates that $name is a single-label `.local` hostname.

Throws `"INVALID_HOSTNAME: ..."` if $name does not end with `.local`
(case-insensitive), has zero or multiple labels before `.local`, exceeds
63 octets in its label or 255 octets on the wire, or contains control
characters. Returns true when valid.
*/
validate-hostname name/string -> bool:
  if not dns-helper.has-local-suffix name:
    throw "INVALID_HOSTNAME: must end with .local: $name"
  prefix := name[..name.size - 6]
  if prefix.is-empty or prefix.size > MAX-DNS-LABEL-OCTETS:
    throw "INVALID_HOSTNAME: label must be 1..63 octets: $name"
  if prefix.contains ".":
    throw "INVALID_HOSTNAME: expected a single label before .local: $name"
  if (prefix.size + 8) > MAX-DNS-NAME-OCTETS:
    throw "INVALID_HOSTNAME: name exceeds 255 octets: $name"
  prefix.size.repeat: | i |
    b := prefix.at --raw i
    if b < 0x20 or b == 0x7f:
      throw "INVALID_HOSTNAME: control characters are not allowed: $name"
  return true

/**
Validates a DNS-SD service $type per RFC 6763 §7 (`_<name>._tcp` or `_<name>._udp`).

Throws `"INVALID_SERVICE_TYPE: ..."` if $type includes `.local`, lacks a valid
transport protocol, or has a service label outside 1–15 `[A-Za-z0-9-]`
characters with at least one letter and no leading or trailing hyphen.
Returns true when valid.
*/
validate-service-type type/string -> bool:
  if dns-helper.has-local-suffix type:
    throw "INVALID_SERVICE_TYPE: must not include .local: $type"
  parts := type.split "."
  if parts.size != 2:
    throw "INVALID_SERVICE_TYPE: expected '_name._tcp' or '_name._udp': $type"
  svc := parts[0]
  proto := parts[1]
  if not (dns-helper.name-equals proto "_tcp") and not (dns-helper.name-equals proto "_udp"):
    throw "INVALID_SERVICE_TYPE: protocol must be _tcp or _udp: $type"
  if svc.size < 2 or svc.size > 16 or (svc.at --raw 0) != '_':
    throw "INVALID_SERVICE_TYPE: service name must be '_' plus 1..15 characters: $type"
  label := svc[1..]
  if (label.at --raw 0) == '-' or (label.at --raw label.size - 1) == '-':
    throw "INVALID_SERVICE_TYPE: service name must not begin or end with '-': $type"
  has-letter := false
  label.size.repeat: | i |
    b := label.at --raw i
    if ('a' <= b <= 'z') or ('A' <= b <= 'Z'):
      has-letter = true
    else if not ('0' <= b <= '9') and b != '-':
      throw "INVALID_SERVICE_TYPE: invalid character in service name: $type"
  if not has-letter:
    throw "INVALID_SERVICE_TYPE: service name must contain at least one letter: $type"
  return true

/**
Validates a DNS-SD service instance $name per RFC 6763 §4.1.1.

Throws `"INVALID_INSTANCE_NAME: ..."` if $name is empty, exceeds 63 octets,
contains control characters, or contains `.` (escaped dots are not yet
supported). Returns true when valid.
*/
validate-instance-name name/string -> bool:
  if name.is-empty or name.size > MAX-DNS-LABEL-OCTETS:
    throw "INVALID_INSTANCE_NAME: must be 1..63 octets: $name"
  if name.contains ".":
    throw "INVALID_INSTANCE_NAME: dots not supported: $name"
  name.size.repeat: | i |
    b := name.at --raw i
    if b < 0x20 or b == 0x7f:
      throw "INVALID_INSTANCE_NAME: control characters are not allowed"
  return true

/**
Validates a DNS-SD $txt record map per RFC 6763 §6.

Throws `"INVALID_TXT: ..."` if any key contains invalid characters or `=`,
if duplicate keys differ only by ASCII case, if any encoded `<character-string>`
exceeds 255 octets, or if the total RDATA exceeds $MAX-TXT-RDATA-OCTETS.
Returns true when valid.
*/
validate-txt txt/Map? -> bool:
  if not txt or txt.is-empty: return true
  seen := {}
  total-rdata := 0
  txt.do: | k v |
    key-str := "$k"
    if key-str.is-empty or key-str.size > MAX-TXT-ENTRY-OCTETS:
      throw "INVALID_TXT: invalid key length for '$key-str'"
    key-str.size.repeat: | i |
      b := key-str.at --raw i
      if b < 0x20 or b > 0x7e or b == '=':
        throw "INVALID_TXT: invalid character in key '$key-str'"
    key-lower := key-str.to-ascii-lower
    if seen.contains key-lower:
      throw "INVALID_TXT: duplicate key '$key-str'"
    seen.add key-lower
    if v == false: continue.do
    entry-size := 0
    if v == null or v == true:
      entry-size = key-str.size
    else if v is ByteArray:
      entry-size = key-str.size + 1 + (v as ByteArray).size
    else:
      entry-size = key-str.size + 1 + "$v".size
    if entry-size > MAX-TXT-ENTRY-OCTETS:
      throw "INVALID_TXT: entry for '$key-str' exceeds $MAX-TXT-ENTRY-OCTETS octets"
    total-rdata += 1 + entry-size
  if total-rdata > MAX-TXT-RDATA-OCTETS:
    throw "INVALID_TXT: total TXT RDATA ($total-rdata) exceeds $MAX-TXT-RDATA-OCTETS octets"
  return true
