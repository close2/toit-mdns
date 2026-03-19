/**
Hostname conflict resolution.

When mDNS name conflicts occur (another device claims our name), this
component generates a new unique name. The strategy appends an incrementing
dash-suffix: "name" → "name-2" → "name-3", etc.

Both probing-phase and established-phase conflicts are handled. The
distinction allows for different strategies if needed (e.g., more aggressive
renaming during probing vs. defensive posture when established).
*/

import log

/**
Generates new hostnames when conflicts are detected.

Uses a -N suffix strategy that produces valid DNS labels and is easy to
identify on the network.
*/
class ConflictManager:
  
  resolve-probing-conflict name/string -> string:
    log.warn "Probing conflict detected. Renaming..." --tags={"old_name": name}
    return next-name_ name

  resolve-established-conflict name/string -> string:
    log.warn "Established conflict detected. Renaming..." --tags={"old_name": name}
    return next-name_ name

  next-name_ name/string -> string:
    // "Name.local" -> "Name-2.local"
    // "Name-2.local" -> "Name-3.local"
    // Also works without .local suffix.

    // Strip .local suffix if present so the -N goes before it.
    suffix := ""
    base := name
    if name.ends-with ".local":
      suffix = ".local"
      base = name[..name.size - 6]

    // Check if base already ends with -<number>.
    dash := base.index-of "-" --last
    if dash != -1:
      number-part := base[dash + 1..]
      number := int.parse number-part --if-error=: null
      if number:
        base-name := base[..dash]
        return "$base-name-$(number + 1)$suffix"

    return "$(base)-2$suffix"
