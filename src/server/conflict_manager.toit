/**
Hostname and service-instance conflict resolution.

Generates valid RFC 1035 DNS labels by appending or incrementing a `-N`
numeric suffix (`"name"` -> `"name-2"` -> `"name-3"`), preserving any
`.local` suffix case-insensitively and bounding labels to 63 octets.
*/

import log
import ..net.dns-helper as dns-helper

/// Maximum octets in a single DNS label per RFC 1035 §2.3.4.
MAX-DNS-LABEL-OCTETS_ ::= 63

/**
Generates new hostnames or service-instance names when conflicts occur.
*/
class ConflictManager:
  /** Resolves a conflict detected during the probing phase. */
  resolve-probing-conflict name/string -> string:
    log.warn "Probing conflict detected. Renaming..." --tags={"old_name": name}
    return next-name_ name

  /** Resolves a persistent conflict detected while established. */
  resolve-established-conflict name/string -> string:
    log.warn "Established conflict detected. Renaming..." --tags={"old_name": name}
    return next-name_ name

  next-name_ name/string -> string:
    suffix := ""
    base := name
    if dns-helper.has-local-suffix name:
      suffix = name[name.size - 6..]
      base = name[..name.size - 6]

    base-name := base
    next-number := 2

    dash := base.index-of "-" --last
    if dash > 0 and dash + 1 < base.size:
      number-part := base[dash + 1..]
      first-char := number-part[0]
      if '0' <= first-char <= '9':
        number := int.parse number-part --if-error=: null
        if number != null and number >= 1:
          base-name = base[..dash]
          next-number = number + 1

    num-suffix := "-$next-number"
    max-base-len := MAX-DNS-LABEL-OCTETS_ - num-suffix.size
    if base-name.size > max-base-len:
      base-name = truncate-utf8_ base-name max-base-len

    return "$base-name$num-suffix$suffix"

  static truncate-utf8_ s/string max-bytes/int -> string:
    if s.size <= max-bytes: return s
    end := max-bytes
    // Step back over UTF-8 continuation bytes (0b10xxxxxx) so we never split a rune.
    while end > 0 and ((s.at --raw end) & 0xc0) == 0x80:
      end--
    return s[..end]
