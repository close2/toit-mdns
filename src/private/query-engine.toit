/**
mDNS query engine and response processor.

Coordinates lookups, manages the response cache, and processes incoming
mDNS responses:
- Cache-first resolution for unique records (`A`, `AAAA`, `SRV`, `TXT`),
  including instant negative resolution via cached `NSEC` records (RFC 6762 §6.1).
- Multi-responder collection window and Known-Answer population for shared
  `PTR` service browsing (RFC 6762 §7.1, RFC 6763 §11).
- Exponential query retransmission (`1s, 2s, 4s, ...` per RFC 6762 §5.2) and
  in-flight query coalescing so concurrent callers do not burst duplicate
  multicast queries within 1 second.
*/

import log
import monitor show Latch
import net.modules.dns
import .dns-helper as dns-helper
import .mdns-socket
import .cache

class QueryEngine:
  /// Aggregation window after first PTR answer so multiple responders (including
  /// peers offset by RFC 6762 §8.1's 250ms probe jitter or §6.2's 120ms shared
  /// response delay) can reply before browse returns.
  static BROWSE-AGGREGATION-US_ ::= 350_000
  /// Initial retransmission interval per RFC 6762 §5.2 (1 second).
  static INITIAL-RETRY-INTERVAL-US_ ::= 1_000_000
  /// Minimum interval between identical multicast queries (RFC 6762 §6).
  static MIN-QUERY-INTERVAL-US_ ::= 900_000
  /// Maximum Known-Answer records attached to a single outgoing query packet.
  static MAX-KNOWN-ANSWERS_ ::= 16

  socket_/MdnsSocket := ?
  cache_/MdnsCache
  pending_/Map := {:}          // lowercased name -> List<PendingQuery_>
  last-query-sent_/Map := {:}  // "name:mask" -> monotonic-us
  closed_/bool := false

  constructor .socket_ .cache_:

  /** Replaces the underlying multicast socket after a network reset. */
  update-socket socket/MdnsSocket -> none:
    socket_ = socket

  /** Closes the query engine and wakes all pending lookups immediately. */
  close -> none:
    if closed_: return
    closed_ = true
    pending_.do: | _ listeners/List |
      listeners.do: | query/PendingQuery_ |
        if not query.latch.has-value:
          query.latch.set []

  /** Returns true if one or more lookups are currently awaiting responses. */
  has-pending -> bool:
    return not pending_.is-empty

  lookup name/string -> List
      --record-types/int
      --timeout-us/int:
    name = name.to-ascii-lower
    if closed_ or record-types == 0 or timeout-us <= 0: return []

    is-ptr-browse := record-types == dns.RECORD-PTR

    // 1. For unique record lookups, return immediately on positive or NSEC cache hit.
    if not is-ptr-browse:
      answers := search-cache_ name record-types
      if not answers.is-empty: return answers
      if is-negatively-cached_ name record-types: return []

    // 2. Register in-flight pending query so process-packet caches relevant packets.
    query := PendingQuery_ record-types --shared=is-ptr-browse
    listeners := pending_.get name --init=(: [])
    listeners.add query

    deadline := Time.monotonic-us + timeout-us
    retry-interval-us := INITIAL-RETRY-INTERVAL-US_
    // If browsing PTR with pre-existing cached instances, send one Known-Answer
    // query and cap the wait if no additional responder answers quickly.
    cached-ptr := is-ptr-browse ? (search-cache_ name record-types) : []
    if is-ptr-browse and not cached-ptr.is-empty:
      deadline = min deadline (Time.monotonic-us + (min timeout-us 250_000))

    try:
      while true:
        now := Time.monotonic-us
        remaining-us := deadline - now
        if remaining-us <= 0: break

        maybe-send-query_ name record-types now
        wait-us := min retry-interval-us remaining-us

        catch --unwind=(: it != "DEADLINE_EXCEEDED"):
          with-timeout (Duration --us=wait-us):
            first := query.latch.get
            if closed_: return []
            if is-ptr-browse:
              // Brief aggregation window so additional LAN responders can answer.
              extra-us := min BROWSE-AGGREGATION-US_ (deadline - Time.monotonic-us)
              if extra-us > 0:
                sleep (Duration --us=extra-us)
              return closed_ ? [] : (search-cache_ name record-types)
            return first
        if closed_: return []
        if query.latch.has-value:
          return is-ptr-browse ? (search-cache_ name record-types) : query.latch.get

        retry-interval-us *= 2
    finally:
      listeners.remove query
      if listeners.is-empty: pending_.remove name
      prune-query-timestamps_

    return search-cache_ name record-types

  /**
  Processes a validated mDNS response packet from the socket receive loop.
  */
  process-packet packet/dns.DecodedPacket -> none:
    if pending_.is-empty: return

    if not (cache-relevant-records_ packet): return

    pending_.do: | name/string listeners/List |
      listeners.do: | query/PendingQuery_ |
        if not query.latch.has-value:
          results := search-cache_ name query.record-types
          if not results.is-empty:
            query.latch.set results
          else if not query.shared and (is-negatively-cached_ name query.record-types):
            query.latch.set []

  cache-relevant-records_ packet/dns.DecodedPacket -> bool:
    level1 := []
    any-relevant := false
    do-packet-resources_ packet: | res/dns.Resource |
      if is-pending-name_ res.name:
        any-relevant = true
        target := target-of-link_ res
        if target and not (name-in-list_ level1 target):
          level1.add target
    if not any-relevant: return false

    level2 := []
    if not level1.is-empty:
      do-packet-resources_ packet: | res/dns.Resource |
        if name-in-list_ level1 res.name:
          target := target-of-link_ res
          if target and not (name-in-list_ level2 target):
            level2.add target

    do-packet-resources_ packet: | res/dns.Resource |
      if (is-pending-name_ res.name) or (name-in-list_ level1 res.name) or (name-in-list_ level2 res.name):
        cache_.add res
    return true

  do-packet-resources_ packet/dns.DecodedPacket [block] -> none:
    packet.resources.do block
    packet.additionals.do block
    packet.authorities.do block

  is-pending-name_ name/string -> bool:
    pending_.do: | pending-name/string _ |
      if dns-helper.name-equals pending-name name: return true
    return false

  static name-in-list_ names/List target/string -> bool:
    names.do: | item/string |
      if dns-helper.name-equals item target: return true
    return false

  static target-of-link_ res/dns.Resource -> string?:
    if res is dns.SrvResource:
      return (res as dns.SrvResource).value
    if (res.type == dns.RECORD-PTR or res.type == dns.RECORD-CNAME) and res is dns.StringResource:
      return (res as dns.StringResource).value
    return null

  maybe-send-query_ name/string record-types/int now/int -> none:
    if socket_.is-closed: return
    key := "$name:$record-types"
    last := last-query-sent_.get key
    if last and (now - last) < MIN-QUERY-INTERVAL-US_: return

    questions := []
    known-answers := []
    add-type := : | rr-type/int |
      if record-types & rr-type != 0:
        questions.add (dns.Question name rr-type)
        if known-answers.size < MAX-KNOWN-ANSWERS_:
          ka := cache_.lookup-known-answers name rr-type
          ka.do:
            if known-answers.size < MAX-KNOWN-ANSWERS_:
              known-answers.add it

    add-type.call dns.RECORD-A
    add-type.call dns.RECORD-AAAA
    add-type.call dns.RECORD-TXT
    add-type.call dns.RECORD-SRV
    add-type.call dns.RECORD-PTR

    if questions.is-empty: return

    last-query-sent_[key] = now
    packets/List? := null
    encode-err := catch:
      packets = dns-helper.encode-mdns-packets questions known-answers
          --id=0
          --no-is-response
          --max-size=socket_.max-payload-size
    if encode-err or not packets:
      log.error "mDNS query encode failed" --tags={"error": encode-err, "name": name}
      return
    packets.do: | packet/ByteArray |
      send-err := catch:
        socket_.send packet
      if send-err:
        log.debug "mDNS query send skipped" --tags={"error": send-err}

  prune-query-timestamps_ -> none:
    if last-query-sent_.size <= 32: return
    cutoff := Time.monotonic-us - 10_000_000
    last-query-sent_.filter --in-place: | _ ts/int | ts > cutoff

  is-negatively-cached_ name/string record-types/int -> bool:
    nsecs := cache_.lookup name dns-helper.RECORD-NSEC
    if nsecs.is-empty: return false
    nsec := nsecs[0] as dns-helper.NsecResource
    if record-types & dns.RECORD-A != 0 and (nsec.has-type dns.RECORD-A): return false
    if record-types & dns.RECORD-AAAA != 0 and (nsec.has-type dns.RECORD-AAAA): return false
    if record-types & dns.RECORD-TXT != 0 and (nsec.has-type dns.RECORD-TXT): return false
    if record-types & dns.RECORD-SRV != 0 and (nsec.has-type dns.RECORD-SRV): return false
    if record-types & dns.RECORD-PTR != 0 and (nsec.has-type dns.RECORD-PTR): return false
    return true

  search-cache_ name/string record-types/int -> List:
    results := []
    if record-types & dns.RECORD-A != 0:
      results.add-all (cache_.lookup name dns.RECORD-A)
    if record-types & dns.RECORD-AAAA != 0:
      results.add-all (cache_.lookup name dns.RECORD-AAAA)
    if record-types & dns.RECORD-TXT != 0:
      results.add-all (cache_.lookup name dns.RECORD-TXT)
    if record-types & dns.RECORD-SRV != 0:
      results.add-all (cache_.lookup name dns.RECORD-SRV)
    if record-types & dns.RECORD-PTR != 0:
      results.add-all (cache_.lookup name dns.RECORD-PTR)

    return serialize-results_ results

  serialize-results_ resources/List -> List:
    return resources.map: | res/dns.Resource |
      data := null
      if res is dns.AResource:
        data = (res as dns.AResource).address.to-byte-array
      else if res is dns.SrvResource:
        srv := res as dns.SrvResource
        data = [srv.priority, srv.weight, srv.port, srv.value]
      else if res is dns.TxtResource:
        data = (res as dns.TxtResource).text
      else if res is dns.StringResource:
        data = (res as dns.StringResource).value

      [res.type, data]

class PendingQuery_:
  latch/Latch := Latch
  record-types/int
  shared/bool

  constructor .record-types --.shared/bool=false:
