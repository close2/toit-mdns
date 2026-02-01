/**
mDNS response cache.

Caches DNS resource records learned from multicast responses. This serves
two purposes:
1. Avoid redundant network queries for recently-seen records
2. Enable passive learning from other devices' mDNS traffic

# Cache Key Design

Records are keyed by (name, type, class) tuple. Multiple records can exist
for the same key (e.g., multiple A records for a host, or multiple PTR
records for a service type).

# TTL Handling

Each cached record carries an expiry timestamp based on its TTL. The cache
periodically prunes expired entries. Identical records (same name, type,
and data) have their TTL refreshed rather than creating duplicates.

# Cleanup Throttling

To avoid excessive CPU usage, cleanup runs at most once per second.
Expired records are lazily removed during cache operations.
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
  last-cleanup-us_/int := 0

  add record/dns.Resource:
    key := build-key_ record.name record.type 1 // Class IN
    list := records_.get key --init=(: [])
    
    now := Time.monotonic-us
    expiry := now + (record.ttl * 1_000_000)

    // Check if we should update an existing entry
    updated := false
    list.map --in-place: | entry/CacheEntry |
      if equal_ entry.record record:
         updated = true
         // Update TTL
         CacheEntry record expiry
      else:
        entry
    
    if not updated:
      list.add (CacheEntry record expiry)

  lookup name/string type/int -> List:
    cleanup_
    key := build-key_ name type 1
    list := records_.get key --if-absent=(: return [])
    return list.map: it.record

  // Remove expired records
  cleanup_:
    now := Time.monotonic-us
    // Only cleanup if enough time has passed since the last cleanup.
    if now - last-cleanup-us_ < CLEANUP-INTERVAL-US_: return
    last-cleanup-us_ = now

    task::
      records_.filter --in-place: | key list |
        list.filter --in-place: | entry |
          entry.expiry > now
        not list.is-empty

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
