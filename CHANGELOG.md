# Changelog

## v2.0.0

### Breaking Changes
- **`Client.dns-lookup` error type**: Throws `dns.DnsException` (`"No name record found"` / `"Not a .local name"`) instead of the `"HOST_NOT_FOUND"` string, matching `net.modules.dns.DnsClient`.
- **Service authorization**: Removed `--hostname` from `Client.register-service` and `MdnsService.register` (bumped `MdnsService.SELECTOR` minor version to `2`). Clients can only register services on their own committed hostname and cannot overwrite or unregister services owned by another client.
- **Strict input validation**: `set-hostname`, `register-service`, and `build-txt-list_` validate single-label `.local` hostnames, RFC 6763 §7 service types, 1–63 octet instance names (dots rejected), and RFC 6763 §6 TXT keys/lengths instead of truncating or failing silently during packet encoding.
- **Internal modules moved**: Moved `mdns.net.*` and `mdns.server.*` to `src/private/` (`mdns.private.*`), and moved `src/main.toit` to `examples/provider.toit`.
- **`MdnsServiceProvider.hostname`**: Returns `string?` (`null` instead of `"no-active-check"` when no hostname is active).

### Security & Memory Hardening
- Enforced a 16 KB default byte budget (`--cache-max-bytes`) on `MdnsCache` with sorted earliest-expiry eviction and 2-hop DNS-SD relevance filtering in `QueryEngine`.
- Replaced `NsecResource` type lists with a bounded 32-byte Window 0 `ByteArray` bitmap.
- Added Tier A public-source filtering (and opt-in `--local-prefix-length`) plus per-source legacy unicast rate limiting (4/s).
- Added per-client quotas (8 services, 4 concurrent lookups), per-hostname quota (16 services), and RPC argument/port/timeout validation.
- Fixed `MdnsSocket.close` to close its owned `net.Client` handle.

### RFC 6762 / 6763 Compliance & Bug Fixes
- Added `unregister-service` API and automatic goodbye/cleanup on client close or hostname change.
- Split oversized mDNS messages across packets within UDP MTU (§17), setting `TC` on split Known-Answer queries (§7.2).
- Ignored AAAA records in IPv4-only hostname conflict checks (§9), reset established conflicts to probing instead of defending-then-renaming (§9), deferred lost service tiebreaks (§8.2), and re-announced port/TXT updates without probing (§8.4).
- Delayed shared `PTR` responses by 20–120 ms (§6), attached `NSEC` additionals to positive `A` responses (§6.1), and cancelled deferred `PTR` responses on matching peer replies (§7.4).
- Prevented constructor resource leaks, woke pending lookups on provider close, re-keyed provider managers on rename, skipped goodbye cache entries on lookup, normalized valid UTF-8 `ByteArray` TXT values, and added periodic local IP refresh.
