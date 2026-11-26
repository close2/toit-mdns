/**
IP address scope and local-link filtering helpers (RFC 6762 §11).
*/

import net

/** Returns true if $addr is a loopback address (`127.0.0.0/8` or `::1`). */
is-loopback addr/net.IpAddress -> bool:
  raw := addr.raw
  if addr.is-ipv6:
    15.repeat: | i |
      if raw[i] != 0: return false
    return raw[15] == 1
  return raw[0] == 127

/** Returns true if $addr is a link-local address (`169.254.0.0/16` or `fe80::/10`). */
is-link-local addr/net.IpAddress -> bool:
  raw := addr.raw
  if addr.is-ipv6:
    return raw[0] == 0xfe and (raw[1] & 0xc0) == 0x80
  return raw[0] == 169 and raw[1] == 254

/**
Returns true if $addr belongs to a private, CGNAT, loopback, or link-local
address range.
*/
is-private-or-local addr/net.IpAddress -> bool:
  if (is-loopback addr) or (is-link-local addr): return true
  raw := addr.raw
  if addr.is-ipv6:
    return (raw[0] & 0xfe) == 0xfc  // ULA fc00::/7.
  b0 := raw[0]
  b1 := raw[1]
  if b0 == 10: return true                         // 10.0.0.0/8.
  if b0 == 172 and (b1 & 0xf0) == 16: return true  // 172.16.0.0/12.
  if b0 == 192 and b1 == 168: return true          // 192.168.0.0/16.
  if b0 == 100 and (b1 & 0xc0) == 64: return true  // 100.64.0.0/10 (CGNAT).
  if b0 == 0: return true                          // 0.0.0.0/8.
  return false

/** Returns true if $a and $b share the first $prefix-length bits. */
same-prefix a/net.IpAddress b/net.IpAddress prefix-length/int -> bool:
  if a.is-ipv6 != b.is-ipv6: return false
  ra := a.raw
  rb := b.raw
  bits := min (max 0 prefix-length) (ra.size * 8)
  full-bytes := bits >> 3
  full-bytes.repeat: | i |
    if ra[i] != rb[i]: return false
  rem := bits & 7
  if rem > 0:
    mask := (0xff << (8 - rem)) & 0xff
    if (ra[full-bytes] & mask) != (rb[full-bytes] & mask): return false
  return true

/**
Checks whether $source is acceptable as a local-link mDNS peer relative to
$local-ip.

Always allows loopback, link-local, and our own $local-ip. When
$prefix-length is provided (Tier B), requires a matching network prefix.
Otherwise (Tier A), rejects publicly routable $source addresses whenever
$local-ip is private or local.
*/
is-local-source
    source/net.IpAddress
    local-ip/net.IpAddress?
    --prefix-length/int?=null -> bool:
  if (is-loopback source) or (is-link-local source): return true
  if local-ip and source == local-ip: return true
  if prefix-length != null and local-ip:
    return same-prefix source local-ip prefix-length
  if local-ip and (is-private-or-local local-ip) and not (is-private-or-local source):
    return false
  return true
