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
    // "Name (2)" -> "Name (3)"
    // "Name" -> "Name (2)"
    
    if name.ends-with ")":
      open-paren := name.index-of "(" --last
      if open-paren != -1:
        number-part := name[open-paren + 1 .. name.size - 1]
        try:
          number := int.parse number-part
          base-name := name[..open-paren - 1]
          return "$base-name ($(number + 1))"
        finally:
          // If parse fails, fall through to append (2)
    
    return "$name (2)"
