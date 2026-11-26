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
  size/int
  goodbye/bool

  constructor .record .received-us .expiry .size --.goodbye/bool=false:

/**
Bounded mDNS response cache indexed by `(name, type, class)`.
*/
class MdnsCache:
  // Map from Key("name:type:class") -> List<CacheEntry>.
  records_/Map := {:}

  static CLEANUP-INTERVAL-US_ ::= 1_000_000
  static MAX-KEYS_ ::= 64
  static MAX-ENTRIES-PER-KEY_ ::= 16
  static MAX-TTL-S_ ::= 4500
  static ENTRY-OVERHEAD_ ::= 48
  static DEFAULT-MAX-BYTES ::= 16_384

  max-bytes_/int
  bytes_/int := 0
  last-cleanup-us_/int := 0

  constructor --max-bytes/int=DEFAULT-MAX-BYTES:
    max-bytes_ = max-bytes

  /** Returns the estimated retained memory in bytes. */
  bytes -> int:
    return bytes_

  /**
  Adds or refreshes $record in the cache.

  - RFC 6762 §10.1: `TTL == 0` is a goodbye; matching entries are retained
    for 1 second and then evicted.
  - RFC 6762 §10.2: `record.flush` evicts same `(name, type, class)` entries
    received more than 1 second ago while preserving entries from the past
    second so multi-packet responses do not invalidate each other.
  */
  add record/dns.Resource -> none:
    entry-size := estimate-size_ record
    if entry-size > max-bytes_ / 4: return

    key := build-key_ record.name record.type dns.CLASS-INTERNET
    list := records_.get key --init=(: [])

    now := Time.monotonic-us
    is-goodbye := record.ttl == 0
    effective-ttl := is-goodbye ? 1 : (min record.ttl MAX-TTL-S_)
    expiry := now + (effective-ttl * 1_000_000)

    if record.flush:
      flush-cutoff := now - 1_000_000
      list.filter --in-place: | entry/CacheEntry |
        keep := (dns-helper.resource-equals entry.record record) or entry.received-us > flush-cutoff
        if not keep: bytes_ -= entry.size
        keep

    list.size.repeat: | i |
      entry/CacheEntry := list[i]
      if dns-helper.resource-equals entry.record record:
        bytes_ += entry-size - entry.size
        list[i] = CacheEntry record now expiry entry-size --goodbye=is-goodbye
        if bytes_ > max-bytes_: evict-to-budget_ (max-bytes_ * 3 / 4)
        return

    if list.size >= MAX-ENTRIES-PER-KEY_:
      evict-oldest-in-list_ list
    list.add (CacheEntry record now expiry entry-size --goodbye=is-goodbye)
    bytes_ += entry-size
    if records_.size > MAX-KEYS_: evict-one_
    if bytes_ > max-bytes_: evict-to-budget_ (max-bytes_ * 3 / 4)

  /** Returns unexpired $dns.Resource records for $name and $type. */
  lookup name/string type/int --include-goodbye/bool=false -> List:
    cleanup_
    key := build-key_ name type dns.CLASS-INTERNET
    list := records_.get key --if-absent=(: return [])
    now := Time.monotonic-us
    result := []
    list.do: | entry/CacheEntry |
      if entry.expiry > now and (include-goodbye or not entry.goodbye):
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

    new-bytes := 0
    records_.filter --in-place: | _ list/List |
      list.filter --in-place: | entry/CacheEntry |
        keep := entry.expiry > now
        if keep: new-bytes += entry.size
        keep
      not list.is-empty
    bytes_ = new-bytes

  evict-oldest-in-list_ list/List -> none:
    if list.is-empty: return
    oldest-idx := 0
    oldest-expiry := (list[0] as CacheEntry).expiry
    for i := 1; i < list.size; i++:
      exp := (list[i] as CacheEntry).expiry
      if exp < oldest-expiry:
        oldest-expiry = exp
        oldest-idx = i
    removed := list[oldest-idx] as CacheEntry
    list.remove --at=oldest-idx
    bytes_ -= removed.size

  evict-one_ -> none:
    earliest-key/string? := null
    earliest-expiry/int := int.MAX
    records_.do: | key list/List |
      list.do: | entry/CacheEntry |
        if entry.expiry < earliest-expiry:
          earliest-expiry = entry.expiry
          earliest-key = key
    if earliest-key:
      removed-list := records_[earliest-key] as List
      removed-list.do: | entry/CacheEntry | bytes_ -= entry.size
      records_.remove earliest-key

  evict-to-budget_ target-bytes/int -> none:
    if bytes_ <= target-bytes: return
    candidates := []
    records_.do: | key list/List |
      list.do: | entry/CacheEntry |
        candidates.add [entry.expiry, key, entry]
    candidates.sort --in-place: | a b | (a[0] as int) - (b[0] as int)
    candidates.do: | item |
      if bytes_ <= target-bytes: return
      key := item[1] as string
      entry := item[2] as CacheEntry
      list/List? := records_.get key
      if list:
        list.remove entry
        bytes_ -= entry.size
        if list.is-empty: records_.remove key

  static estimate-size_ record/dns.Resource -> int:
    rdata-size := 0
    if record is dns.AResource:
      rdata-size = (record as dns.AResource).address.raw.size
    else if record is dns.SrvResource:
      rdata-size = 6 + (record as dns.SrvResource).value.size
    else if record is dns.TxtResource:
      txt := (record as dns.TxtResource).text
      rdata-size = txt.size
      txt.do: rdata-size += it.size
    else if record is dns.StringResource:
      rdata-size = (record as dns.StringResource).value.size
    else if record is dns-helper.NsecResource:
      nsec := record as dns-helper.NsecResource
      rdata-size = nsec.next-domain.size + nsec.bitmap.size
    return ENTRY-OVERHEAD_ + record.name.size + rdata-size

  build-key_ name/string type/int klass/int -> string:
    return "$(name.to-ascii-lower):$type:$klass"
