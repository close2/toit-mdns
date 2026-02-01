/**
mDNS query engine and response processor.

Provides the core lookup functionality with cache-first semantics:
1. Check cache for existing records
2. If not cached, send multicast query and wait for responses
3. Cache all received answers for future queries

# Pending Query Coordination

When multiple tasks query for the same name simultaneously, they share
a single pending query via a $Latch. This avoids flooding the network
with duplicate queries - only one packet is sent, and all waiters are
notified when the response arrives.

# Record Type Handling

Queries support multiple record types via bitmask (e.g., A | AAAA).
The engine expands this bitmask into appropriate DNS questions and
collates responses from the cache.
*/

import net
import net.modules.dns
import monitor show Latch
import ..net.mdns-socket
import .cache

/**
mDNS query engine.

Coordinates lookups, manages the cache, and processes incoming responses.
Uses cache-first semantics to minimize network traffic.
*/
class QueryEngine:
  socket_/MdnsSocket
  cache_/MdnsCache
  pending_/Map := {:} // name -> List<PendingQuery_>

  constructor .socket_ .cache_:

  lookup name/string -> List
      --record-types/int
      --timeout-us/int:
    // 1. Check Cache
    answers := search-cache_ name record-types
    if not answers.is-empty: return answers

    // 2. Query - use a Latch to coordinate waiting
    query := PendingQuery_ record-types
    listeners := pending_.get name --init=(: [])
    listeners.add query

    // Send query packet
    send-query_ name record-types

    // 3. Wait with timeout
    try:
      // Use catch to handle timeout exception and return empty list
      catch --unwind=(: it != "DEADLINE_EXCEEDED"):
        with-timeout (Duration --us=timeout-us):
          return query.latch.get
    finally:
      // Cleanup
      listeners.remove query
      if listeners.is-empty: pending_.remove name

    // Timeout reached.
    return []


  /**
  Called from the service for every packet.
  */
  process-packet packet/dns.DecodedPacket:
    // Update cache with all answers
    packet.resources.do: cache_.add it
    packet.additionals.do: cache_.add it
    packet.authorities.do: cache_.add it

    // Notify pending queries if we have answers for them
    // Broad strategy: Check if packet contains answers for any pending name
    names-in-packet := {}
    packet.resources.do: names-in-packet.add it.name
    packet.additionals.do: names-in-packet.add it.name
    packet.authorities.do: names-in-packet.add it.name
    
    names-in-packet.do: | name |
      listeners := pending_.get name
      if listeners:
        listeners.do: | query/PendingQuery_ |
          // Check if we found what this query was looking for
          results := search-cache_ name query.record-types
          if not results.is-empty and not query.latch.has-value:
            query.latch.set results


  send-query_ name/string record-types/int:
    questions := []
    // Expand record-types bitmask to Questions
    // Common types
    if record-types & dns.RECORD-A != 0:
      questions.add (dns.Question name dns.RECORD-A --unicast-ok)
    if record-types & dns.RECORD-AAAA != 0:
      questions.add (dns.Question name dns.RECORD-AAAA --unicast-ok)
    if record-types & dns.RECORD-TXT != 0:
      questions.add (dns.Question name dns.RECORD-TXT --unicast-ok)
    if record-types & dns.RECORD-SRV != 0:
      questions.add (dns.Question name dns.RECORD-SRV --unicast-ok)
    if record-types & dns.RECORD-PTR != 0:
      questions.add (dns.Question name dns.RECORD-PTR --unicast-ok)
      
    if questions.is-empty: return

    // Create packet
    packet := dns.create-dns-packet questions [] 
        --id=0
        --no-is-response 

    // Send via socket to multicast group
    // The MdnsSocket caches the multicast target.
    socket_.send packet

  search-cache_ name/string record-types/int -> List:
    results := []
    // Iterate types in bitmask
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
      
    // Serialize returns
    return serialize-results_ results

  serialize-results_ resources/List -> List:
    // Format: [type, data]
    return resources.map: | res/dns.Resource |
      data := null
      if res is dns.AResource:
        data = (res as dns.AResource).address.to-byte-array
      else if res is dns.SrvResource:
        srv := res as dns.SrvResource
        // SrvResource extends StringResource, value is target.
        target := srv.value 
        data = [srv.priority, srv.weight, srv.port, target]
      else if res is dns.StringResource:
        data = (res as dns.StringResource).value
      
      [res.type, data]

class PendingQuery_:
  latch/Latch := Latch
  record-types/int

  constructor .record-types:
