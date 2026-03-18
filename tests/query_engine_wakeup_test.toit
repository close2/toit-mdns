import expect show *
import monitor show Latch
import net
import net.udp
import net.modules.dns
import io
import mdns.server.query_engine show QueryEngine
import mdns.server.cache show MdnsCache
import mdns.net.mdns_socket show MdnsSocket

TEST-PORT ::= 5354
TEST-GROUP ::= net.IpAddress.parse "224.0.0.251"

main:
  test-wakeup-bug

test-wakeup-bug:
  print "Test: QueryEngine wakeup bug with real sockets"
  
  network := net.open
  // Create MdnsSocket on a custom port
  socket := MdnsSocket --network=network --port=TEST-PORT
  cache := MdnsCache
  engine := QueryEngine socket cache

  // Sender socket to inject packets
  sender := network.udp-open
  dest := net.SocketAddress TEST-GROUP TEST-PORT

  // Start a background lookup for A records
  lookup-latch := Latch
  lookup-result := []
  
  task::
    print "  Starting lookup for 'foo.local' (A)"
    // Timeout long enough to not flake
    lookup-result = engine.lookup "foo.local" --record-types=dns.RECORD-A --timeout-us=1_000_000
    print "  Lookup finished. Found $(lookup-result.size) records."
    lookup-latch.set true

  // Start background listener to process incoming packets
  task::
    catch:
      while true:
        datagram := socket.receive
        if datagram:
          print "  Received packet from $(datagram.address)"
          try:
            decoded := dns.decode-packet datagram.data
            engine.process-packet decoded
          finally: | is-exception exception |
            if is-exception: print "  Error processing packet: $exception"

  sleep --ms=100
  
  // 1. Inject a TXT record for "foo.local".
  // This checks if the lookup ignores irrelevant packets (previously a bug caused wakeup).
  print "  Injecting TXT record (should be ignored by A lookup)"
  txt-packet := dns.create-dns-packet [] [
    dns.StringResource "foo.local" dns.RECORD-TXT 120 false "some-text"
  ] --id=0 --is-response=true
  
  sender.send (udp.Datagram txt-packet dest)

  sleep --ms=100
  
  // 2. Inject an A record for "foo.local".
  // If the bug exists, the lookup has already returned empty.
  // If fixed, the lookup is still waiting and will now find this record.
  print "  Injecting A record (should be found)"
  a-packet := dns.create-dns-packet [] [
    dns.AResource "foo.local" 120 (net.IpAddress.parse "1.2.3.4")
  ] --id=0 --is-response=true
  
  sender.send (udp.Datagram a-packet dest)

  // Wait for lookup to finish (or timeout from test perspective if it hangs, but we set timeout in lookup)
  lookup-latch.get

  socket.close
  sender.close

  // Assertions
  if lookup-result.size == 0:
    print "FAILURE: Lookup returned empty list (premature wakeup triggered by TXT record)"
    expect-equals 1 lookup-result.size // Force failure
  else:
    print "SUCCESS: Lookup found the A record"
    expect-equals 1 lookup-result.size
    first-record := lookup-result[0]
    // Result format is [type, data]
    expect-equals dns.RECORD-A first-record[0]
