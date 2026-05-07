/**
Regression tests for the mDNS cache.

Covers RFC 6762 cache-coherency behaviors that are easy to get wrong:

- §10.1: A goodbye record (TTL=0) MUST be kept for one second so other
  listeners notice the departure, and only then evicted.
- §10.2: Records received with the cache-flush bit set MUST evict any
  earlier entries with the same (name, type, class) that are more than
  one second old.
- §16: DNS names are case-insensitive for ASCII letters, so cache
  lookups must hit regardless of the casing the responder used.
*/

import expect show *
import net
import net.modules.dns

import mdns.server.cache show MdnsCache

main:
  test-goodbye-keeps-record-briefly
  test-goodbye-expires-after-one-second
  test-cache-flush-evicts-old-record
  test-cache-flush-keeps-recent-records
  test-case-insensitive-lookup
  print "All cache tests passed!"

test-goodbye-keeps-record-briefly:
  print "Test: Goodbye (TTL=0) keeps record for ~1s..."
  cache := MdnsCache
  goodbye := dns.AResource "alpha.local" 0 (net.IpAddress.parse "10.0.0.1")
  cache.add goodbye

  // Immediately after add the record must still be visible: RFC 6762
  // §10.1 says listeners get one second of grace.
  results := cache.lookup "alpha.local" dns.RECORD-A
  expect-equals 1 results.size
  print "  PASS"

test-goodbye-expires-after-one-second:
  print "Test: Goodbye record expires after one second..."
  cache := MdnsCache
  goodbye := dns.AResource "beta.local" 0 (net.IpAddress.parse "10.0.0.2")
  cache.add goodbye

  sleep (Duration --ms=1100)

  results := cache.lookup "beta.local" dns.RECORD-A
  expect results.is-empty
  print "  PASS"

test-cache-flush-evicts-old-record:
  print "Test: Cache-flush bit evicts older same-name/type records..."
  cache := MdnsCache
  // Old record without flush bit (e.g. previously cached).
  old := dns.AResource "gamma.local" 120 (net.IpAddress.parse "10.0.0.3")
  cache.add old

  // Wait long enough that the old record is no longer "fresh" (i.e.
  // older than one second per RFC 6762 §10.2).
  sleep (Duration --ms=1100)

  // New record arrives with cache-flush bit set, but with a different
  // address. The old record must be evicted.
  refreshed := dns.AResource "gamma.local" 120 (net.IpAddress.parse "10.0.0.30") --flush
  cache.add refreshed

  results := cache.lookup "gamma.local" dns.RECORD-A
  expect-equals 1 results.size
  expect-equals (net.IpAddress.parse "10.0.0.30")
      (results[0] as dns.AResource).address
  print "  PASS"

test-cache-flush-keeps-recent-records:
  print "Test: Cache-flush bit preserves records seen in the last 1s..."
  cache := MdnsCache
  // Two records arriving back-to-back as part of a multi-packet
  // response. RFC 6762 §10.2 explicitly requires that records seen in
  // the past second NOT be flushed, so multi-packet replies don't
  // accidentally invalidate each other.
  first := dns.AResource "delta.local" 120 (net.IpAddress.parse "10.0.0.10") --flush
  cache.add first
  second := dns.AResource "delta.local" 120 (net.IpAddress.parse "10.0.0.11") --flush
  cache.add second

  results := cache.lookup "delta.local" dns.RECORD-A
  // Both addresses must still be cached.
  addresses := results.map: (it as dns.AResource).address
  expect (addresses.contains (net.IpAddress.parse "10.0.0.10"))
  expect (addresses.contains (net.IpAddress.parse "10.0.0.11"))
  print "  PASS"

test-case-insensitive-lookup:
  print "Test: Cache lookups are case-insensitive (RFC 6762 §16)..."
  cache := MdnsCache
  rec := dns.AResource "Epsilon.Local" 120 (net.IpAddress.parse "10.0.0.99")
  cache.add rec

  expect-equals 1 (cache.lookup "epsilon.local" dns.RECORD-A).size
  expect-equals 1 (cache.lookup "EPSILON.LOCAL" dns.RECORD-A).size
  expect-equals 1 (cache.lookup "Epsilon.Local" dns.RECORD-A).size

  // Adding the same record with different casing must refresh in
  // place rather than create a duplicate entry.
  again := dns.AResource "EPSILON.LOCAL" 120 (net.IpAddress.parse "10.0.0.99")
  cache.add again
  expect-equals 1 (cache.lookup "epsilon.local" dns.RECORD-A).size
  print "  PASS"
