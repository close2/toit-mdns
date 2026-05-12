// Verifies that the lenient mDNS packet parser tolerates records
// with a non-IN class (e.g. an OPT pseudo-record whose CLASS field
// encodes a UDP payload size). The SDK's strict decoder rejects
// such packets entirely, which silently dropped legitimate conflict
// defense responses on the wire.

import expect show *
import mdns.net.dns_helper as dns

main:
  test-packet-with-opt-record
  test-pure-mdns-defense-response
  print "All lenient parser tests passed."

// Builds: header + one question + one OPT record (class != IN).
// The lenient parser must return a DecodedPacket with one
// question, and silently skip the OPT record.
test-packet-with-opt-record:
  buf := #[
    0x12, 0x34,             // ID
    0x00, 0x00,             // Flags (query, RD=0)
    0x00, 0x01,             // 1 question
    0x00, 0x00,             // 0 answers
    0x00, 0x00,             // 0 authorities
    0x00, 0x01,             // 1 additional (the OPT)
    // Question: "nebenuhr.local" type ANY class IN
    0x08, 'n', 'e', 'b', 'e', 'n', 'u', 'h', 'r',
    0x05, 'l', 'o', 'c', 'a', 'l',
    0x00,
    0x00, 0xff,             // QTYPE = ANY
    0x00, 0x01,             // QCLASS = IN
    // OPT pseudo-record: name=root, type=41 (OPT), class=4096
    // (UDP payload size, not IN!), ttl=0, rdlength=0.
    0x00,                   // root name
    0x00, 0x29,             // type = OPT (41)
    0x10, 0x00,             // class = 4096 (definitely not IN)
    0x00, 0x00, 0x00, 0x00, // TTL
    0x00, 0x00,             // RDLENGTH
  ]
  packet := dns.parse buf
  expect-equals 1 packet.questions.size
  expect-equals "nebenuhr.local" packet.questions[0].name
  expect-equals 0 packet.additionals.size

// Builds: header + one A-record answer (class IN). The lenient
// parser must produce the same DecodedPacket as the SDK strict
// parser would on the same input.
test-pure-mdns-defense-response:
  buf := #[
    0x00, 0x00,             // ID
    0x84, 0x00,             // Flags (response | authoritative)
    0x00, 0x00,             // 0 questions
    0x00, 0x01,             // 1 answer
    0x00, 0x00,             // 0 authorities
    0x00, 0x00,             // 0 additionals
    // A record: "nebenuhr.local", type=A, class=IN|flush, ttl=120, addr=10.1.244.190
    0x08, 'n', 'e', 'b', 'e', 'n', 'u', 'h', 'r',
    0x05, 'l', 'o', 'c', 'a', 'l',
    0x00,
    0x00, 0x01,                  // TYPE = A
    0x80, 0x01,                  // CLASS = IN with cache-flush bit
    0x00, 0x00, 0x00, 0x78,      // TTL = 120
    0x00, 0x04,                  // RDLENGTH = 4
    0x0a, 0x01, 0xf4, 0xbe,      // 10.1.244.190
  ]
  packet := dns.parse buf
  expect packet.is-response
  expect packet.is-authoritative
  expect-equals 1 packet.resources.size
  resource := packet.resources[0]
  expect-equals "nebenuhr.local" resource.name
