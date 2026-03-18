/**
Hostname conflict resolution.

When mDNS name conflicts occur (another device claims our name), this
component generates a new unique name. The strategy appends an incrementing
suffix: "name" → "name (2)" → "name (3)", etc.

Both probing-phase and established-phase conflicts are handled. The
distinction allows for different strategies if needed (e.g., more aggressive
renaming during probing vs. defensive posture when established).
*/

import log

/**
Generates new hostnames when conflicts are detected.

Uses a simple (N) suffix strategy that's human-readable and easy to identify
on the network.
*/
class ConflictManager:
  
  resolve-probing-conflict name/string -> string:
    log.warn "Probing conflict detected. Renaming..." --tags={"old_name": name}
    return next-name_ name

  resolve-established-conflict name/string -> string:
    log.warn "Established conflict detected. Renaming..." --tags={"old_name": name}
    return next-name_ name

  next-name_ name/string -> string:
    // Regex would be nice, but manual parsing is fine.
    // "Name.local" -> "Name (2).local"
    // "Name (2).local" -> "Name (3).local"
    // Also works without .local suffix.

    // Strip .local suffix if present so the (N) goes before it.
    suffix := ""
    base := name
    if name.ends-with ".local":
      suffix = ".local"
      base = name[..name.size - 6]

    if base.ends-with ")":
      open-paren := base.index-of "(" --last
      if open-paren != -1:
        number-part := base[open-paren + 1 .. base.size - 1]
        try:
          number := int.parse number-part
          base-name := base[..open-paren - 1]
          return "$base-name ($(number + 1))$suffix"
        finally:
          // If parse fails, fall through to append (2)

    return "$base (2)$suffix"
