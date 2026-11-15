/**
mDNS response cache.

Caches DNS resource records learned from multicast responses for names
actively being queried (plus their DNS-SD additional records). Both key
count and per-key entry lists are bounded so cache memory stays small and
predictable on ESP32 heaps.
*/

import net.modules.dns
import ..net.dns-helper as dns-helper

/**
Single cache entry with creation and expiration timestamps.
*/
class CacheEntry:
  record/dns.Resource
  received-us/int
  expiry/int  // Monotonic microsecond timestamp.

  constructor .record .received-us .expiry:

/**
Bounded mDNS response cache indexed by `(name, type, class)`.
*/
class MdnsCache:
  // Map from Key("name:type:class") -> List<CacheEntry>.
  records_/Map := {:}

  static CLEANUP-INTERVAL-US_ ::= 1_000_000
  static MAX-KEYS_ ::= 64
  static MAX-ENTRIES-PER-KEY_ ::= 32
  static MAX-TTL-S_ ::= 86_400
  last-cleanup-us_/int := 0

  /**
  Adds or refreshes $record in the cache.

  - RFC 6762 §10.1: `TTL == 0` is a goodbye; matching entries are retained
    for 1 second and then evicted.
  - RFC 6762 §10.2: `record.flush` evicts same `(name, type, class)` entries
    received more than 1 second ago while preserving entries from the past
    second so multi-packet responses do not invalidate each other.
  */
  add record/dns.Resource -> none:
    key := build-key_ record.name record.type dns.CLASS-INTERNET
    list := records_.get key --init=(: [])

    now := Time.monotonic-us
    effective-ttl := record.ttl > 0 ? (min record.ttl MAX-TTL-S_) : 1
    expiry := now + (effective-ttl * 1_000_000)

    if record.flush:
      flush-cutoff := now - 1_000_000
      list.filter --in-place: | entry/CacheEntry |
        (dns-helper.resource-equals entry.record record) or entry.received-us > flush-cutoff

    list.size.repeat: | i |
      entry/CacheEntry := list[i]
      if dns-helper.resource-equals entry.record record:
        list[i] = CacheEntry record now expiry
        return

    if list.size >= MAX-ENTRIES-PER-KEY_:
      evict-oldest-in-list_ list
    list.add (CacheEntry record now expiry)
    if records_.size > MAX-KEYS_: evict-one_

  /** Returns unexpired $dns.Resource records for $name and $type. */
  lookup name/string type/int -> List:
    cleanup_
    key := build-key_ name type dns.CLASS-INTERNET
    list := records_.get key --if-absent=(: return [])
    now := Time.monotonic-us
    result := []
    list.do: | entry/CacheEntry |
      if entry.expiry > now:
        result.add entry.record
    return result

  /**
  Returns unexpired records cloned with their remaining TTL in whole seconds
  and `flush = false`, suitable for populating a query's Known-Answer section
  per RFC 6762 §7.1.
  */
  lookup-known-answers name/string type/int -> List:
    cleanup_
    key := build-key_ name type dns.CLASS-INTERNET
    list := records_.get key --if-absent=(: return [])
    now := Time.monotonic-us
    result := []
    list.do: | entry/CacheEntry |
      remaining-s := (entry.expiry - now) / 1_000_000
      // Goodbye entries (<= 1s left) must not be placed in Known-Answers.
      if entry.record.ttl > 0 and remaining-s >= 2:
        cloned := clone-with-ttl_ entry.record remaining-s
        if cloned: result.add cloned
    return result

  clone-with-ttl_ res/dns.Resource ttl/int -> dns.Resource?:
    if res is dns.AResource:
      return dns.AResource res.name res.type ttl false (res as dns.AResource).address
    if res is dns.SrvResource:
      srv := res as dns.SrvResource
      return dns.SrvResource srv.name srv.type ttl false srv.value srv.priority srv.weight srv.port
    if res is dns.TxtResource:
      return dns.TxtResource res.name ttl false (res as dns.TxtResource).text
    if res is dns.StringResource:
      return dns.StringResource res.name res.type ttl false (res as dns.StringResource).value
    return null

  cleanup_ -> none:
    now := Time.monotonic-us
    if now - last-cleanup-us_ < CLEANUP-INTERVAL-US_: return
    last-cleanup-us_ = now

    records_.filter --in-place: | _ list/List |
      list.filter --in-place: | entry/CacheEntry |
        entry.expiry > now
      not list.is-empty

  evict-oldest-in-list_ list/List -> none:
    if list.is-empty: return
    oldest-idx := 0
    oldest-expiry := (list[0] as CacheEntry).expiry
    for i := 1; i < list.size; i++:
      exp := (list[i] as CacheEntry).expiry
      if exp < oldest-expiry:
        oldest-expiry = exp
        oldest-idx = i
    list.remove --at=oldest-idx

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
    return "$(name.to-ascii-lower):$type:$klass"
