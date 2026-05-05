/**
mDNS response cache.

Caches DNS resource records learned from multicast responses.  The
cache is **opt-in** — records are only stored for names actively
being looked up.  This avoids the unbounded growth that comes from
passively absorbing every multicast packet on a busy LAN (each
record's TTL is typically 4500 s, so passive caching is effectively
a slow leak).

# Cache Key Design

Records are keyed by (name, type, class) tuple. Multiple records can exist
for the same key (e.g., multiple A records for a host, or multiple PTR
records for a service type).

# TTL Handling

Each cached record carries an expiry timestamp based on its TTL. The cache
periodically prunes expired entries. Identical records (same name, type,
and data) have their TTL refreshed rather than creating duplicates.

# Cleanup

Expired entries are pruned lazily on lookup (no background task; that
would consume one Toit task per cleanup pass on a tiny ESP32 heap).
The pass is throttled to once per second.
*/

import net
import net.modules.dns

/**
Single cache entry with expiration tracking.
*/
class CacheEntry:
  record/dns.Resource
  expiry/int // Monotonic microsecond timestamp

  constructor .record .expiry:

/**
mDNS response cache.

Stores DNS resource records indexed by (name, type, class) key. Each key
can have multiple records (e.g., a host with multiple IP addresses).

Records are automatically expired based on their TTL, with cleanup
throttled to avoid excessive CPU usage during high-traffic periods.
*/
class MdnsCache:
  // Map from Key(name, type, class) -> List<CacheEntry>
  records_/Map := {:}

  // Cleanup throttling: Only cleanup once per second (1_000_000 microseconds)
  static CLEANUP-INTERVAL-US_ ::= 1_000_000
  // Hard cap on the number of distinct (name,type,class) keys.  When
  // we hit it the oldest expiring entries are dropped.  64 keys is
  // ample for a slave-clock controller (we look up at most a handful
  // of hostnames at a time) and keeps the worst-case cache footprint
  // well under 4 kB.
  static MAX-KEYS_ ::= 64
  last-cleanup-us_/int := 0

  add record/dns.Resource:
    key := build-key_ record.name record.type 1 // Class IN
    list := records_.get key --init=(: [])

    now := Time.monotonic-us
    expiry := now + (record.ttl * 1_000_000)

    // If an identical record is already cached, just refresh its TTL
    // in place.  Stop scanning as soon as we find the match.
    list.size.repeat: | i |
      entry/CacheEntry := list[i]
      if equal_ entry.record record:
        list[i] = CacheEntry record expiry
        return

    list.add (CacheEntry record expiry)
    if records_.size > MAX-KEYS_: evict-one_

  lookup name/string type/int -> List:
    cleanup_
    key := build-key_ name type 1
    list := records_.get key --if-absent=(: return [])
    return list.map: it.record

  // Remove expired records.  Synchronous: we run inside whatever task
  // happened to call us.  The throttle keeps the cost amortised.
  cleanup_:
    now := Time.monotonic-us
    if now - last-cleanup-us_ < CLEANUP-INTERVAL-US_: return
    last-cleanup-us_ = now

    records_.filter --in-place: | _ list |
      list.filter --in-place: | entry/CacheEntry |
        entry.expiry > now
      not list.is-empty

  /**
  Drops the key whose entries expire soonest.  Called when the cache
  exceeds $MAX-KEYS_; this is a coarse but cheap LRU-like policy that
  prevents unbounded growth on networks with lots of mDNS chatter.
  */
  evict-one_ -> none:
    earliest-key/string? := null
    earliest-expiry/int := int.MAX
    records_.do: | key list/List |
      list.do: | entry/CacheEntry |
        if entry.expiry < earliest-expiry:
          earliest-expiry = entry.expiry
          earliest-key = key
    if earliest-key: records_.remove earliest-key

  build-key_ name/string type/int klass/int -> string:
    return "$name:$type:$klass"

  /**
  Checks if two resources are equal, ignoring the TTL.

  We can't implement and use `operator==` or `hash-code` on the resources because those
  should include the TTL. Here we want to identify if the record data has
  changed, regardless of the TTL.
  */
  equal_ a/dns.Resource b/dns.Resource -> bool:
    if a.name != b.name or a.type != b.type or a.flush != b.flush: return false
    // Deep equality check used for updating TTLs of identical records.
    // SrvResource extends StringResource, so check SrvResource first.
    if a is dns.SrvResource and b is dns.SrvResource:
      srv-a := a as dns.SrvResource
      srv-b := b as dns.SrvResource
      return srv-a.priority == srv-b.priority and
        srv-a.weight == srv-b.weight and
        srv-a.port == srv-b.port and
        srv-a.value == srv-b.value  // Target hostname
    if a is dns.AResource and b is dns.AResource:
      return (a as dns.AResource).address == (b as dns.AResource).address
    if a is dns.StringResource and b is dns.StringResource:
      // Covers PTR, CNAME, and TXT records
      return (a as dns.StringResource).value == (b as dns.StringResource).value
    return false
