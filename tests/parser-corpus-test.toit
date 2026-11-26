import encoding.hex
import expect show *
import mdns.private.dns-helper as dns

import .corpus.packets show CORPUS

/** Mutations per valid corpus entry (8 valid entries * 1250 = 10,000 packets). */
MUTATIONS-PER-ENTRY ::= 1250
/** Maximum time for parsing a single mutated packet. */
MAX-PARSE-US ::= 20_000
/** Maximum average parse time across the fuzz run. */
MAX-AVG-PARSE-US ::= 5_000

main:
  test-corpus-expectations
  test-mutations-never-crash

test-corpus-expectations:
  CORPUS.do: | entry/List |
    name/string := entry[0]
    should-parse/bool := entry[1]
    bytes := hex.decode entry[2]
    e := catch: dns.parse bytes
    if should-parse:
      expect e == null --message="$name should parse, got $e"
    else:
      expect e != null --message="$name should be rejected"
      expect e is string --message="$name must fail with a string error, got $e"

/**
Applies deterministic byte flips, truncations, and count inflations to every
  valid corpus packet. The parser must either succeed or throw a string, and
  must stay fast.
*/
test-mutations-never-crash:
  rng := Lcg_ 0x5eed
  total := 0
  total-us := 0
  CORPUS.do: | entry/List |
    if not entry[1]: continue.do
    original := hex.decode entry[2]
    MUTATIONS-PER-ENTRY.repeat:
      mutated := original.copy
      kind := rng.next 3
      if kind == 0:
        (1 + (rng.next 4)).repeat:
          mutated[rng.next mutated.size] = rng.next 256
      else if kind == 1:
        mutated = mutated[..rng.next mutated.size]
      else:
        // Inflate one of the four section counts.
        offset := 4 + 2 * (rng.next 4)
        mutated[offset + 1] = rng.next 256
      start := Time.monotonic-us
      e := catch: dns.parse mutated
      elapsed := Time.monotonic-us - start
      total-us += elapsed
      if e: expect e is string --message="non-string error $e for $(hex.encode mutated)"
      expect elapsed < MAX-PARSE-US --message="parse took $(elapsed)us for $(hex.encode mutated)"
      total++
  expect total >= 10_000
  avg := total-us / total
  expect avg < MAX-AVG-PARSE-US --message="avg parse time $(avg)us exceeds $MAX-AVG-PARSE-US"
  print "Parsed $total mutated packets (avg $(avg)us/pkt)."

/** Small deterministic linear congruential generator. */
class Lcg_:
  state_/int := ?

  constructor .state_:

  next limit/int -> int:
    state_ = (state_ * 1_103_515_245 + 12_345) & 0x7fff_ffff
    return state_ % limit
