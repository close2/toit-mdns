// Regression tests for race-condition bugs found in the third audit pass.
//
// All of these exercise interactions between the listener task (which
// processes incoming packets) and the state-machine task (which
// probes/announces).  Toit uses cooperative concurrency, so races only
// arise across yield points — but probing, announcement and unicast
// response sends all yield, so the windows are real and reachable.

import expect show *
import net
import net.modules.dns

import mdns.net.dns_helper as dns-helper
import mdns.net.mdns_socket show MdnsSocket
import mdns.server.conflict_manager show ConflictManager
import mdns.server.state_manager show StateManager
import .e2e_param show TEST-PORT

main:
  test-send-response-tolerates-unroutable-source
  test-register-service-during-probing-restarts
  test-rapid-reprobe-does-not-leak-old-task
  test-register-service-is-idempotent

test-send-response-tolerates-unroutable-source:
  // Bug: send-response_ called socket_.send without a catch wrapper,
  // so a query whose source IP we cannot route to (common on macOS
  // when the kernel returns "No route to host" for an INADDR_ANY
  // socket address) propagated as an exception out of process-packet
  // and aborted the listener task.
  print "Test: send-response tolerates unroutable unicast destinations..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  local-ip := net.IpAddress.parse "192.168.1.50"
  sm := StateManager socket cm "tolerant.local" local-ip --expected-port=TEST-PORT
  sm.start
  try:
    // Wait until ESTABLISHED so process-packet actually tries to
    // answer.
    while sm.state_ != StateManager.STATE-ESTABLISHED:
      sleep (Duration --ms=20)

    // Legacy unicast query: source.port != 5353-equivalent → unicast
    // response path.  240.0.0.0/4 is the IANA-reserved "future use"
    // range — guaranteed unroutable on every platform.
    unroutable := net.SocketAddress (net.IpAddress.parse "240.0.0.1") 12345
    query := dns.create-dns-packet
        [dns.Question "tolerant.local" dns.RECORD-A]
        []
        --id=0x1234
        --is-response=false

    // Must not throw, even though the unicast send to the unroutable
    // address fails at the OS layer.
    sm.process-packet (dns-helper.parse query) --source=unroutable
    print "  PASS"
  finally:
    sm.stop
    socket.close

test-register-service-during-probing-restarts:
  // Bug: register-service called enter-probing_ only when the state
  // manager was NOT already probing.  When invoked mid-probe, the new
  // service inherited the existing probe-count_ — so a service added
  // after probe 2 saw only one probe instead of the three required by
  // RFC 6762 §8.1.  Fix: always re-enter probing so the new service
  // gets a full cycle.
  print "Test: register-service during probing restarts the cycle..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  local-ip := net.IpAddress.parse "192.168.1.50"
  sm := StateManager socket cm "reprobe.local" local-ip --expected-port=TEST-PORT
  sm.start
  try:
    // Wait briefly so the probe loop has issued at least one probe and
    // we are partway through the cycle.
    sleep (Duration --ms=300)
    expect-equals StateManager.STATE-PROBING sm.state_

    generation-before := sm.probe-generation_
    sm.register-service "_http._tcp" 8080 --txt={"path": "/"}
    // After the fix the generation must bump, even though we were
    // already in STATE-PROBING.
    expect sm.probe-generation_ > generation-before
        --message="register-service must restart probing for new services"
    // probe-count_ has just been reset.
    expect-equals 0 sm.probe-count_

    // The new probe cycle should still complete and reach ESTABLISHED.
    deadline := Time.monotonic-us + 5_000_000
    while sm.state_ != StateManager.STATE-ESTABLISHED and Time.monotonic-us < deadline:
      sleep (Duration --ms=50)
    expect-equals StateManager.STATE-ESTABLISHED sm.state_
    print "  PASS"
  finally:
    sm.stop
    socket.close

test-rapid-reprobe-does-not-leak-old-task:
  // Bug: when enter-probing_ was called twice in quick succession, the
  // first probe task was cancelled but its CANCELED-ERROR could not
  // fire until its next yield (sleep).  Between the cancel and that
  // yield it could run another iteration of the probe loop and even
  // call enter-announcing_ for the *previous* generation.  Result:
  // two enter-announcing_ tasks racing to set state_.  The fix is a
  // generation counter checked at every loop iteration and before the
  // ANNOUNCING transition.
  print "Test: rapid re-probing leaves only one active generation..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  local-ip := net.IpAddress.parse "192.168.1.50"
  sm := StateManager socket cm "rapid-reprobe.local" local-ip --expected-port=TEST-PORT
  sm.start
  try:
    // Force several rapid re-probes.  Each one bumps the generation;
    // none must be lost.
    start-generation := sm.probe-generation_
    5.repeat:
      sleep (Duration --ms=30)
      sm.set-hostname "rapid-reprobe-$(it).local"
    expect sm.probe-generation_ >= start-generation + 5
    // Eventually the last cycle must complete normally.
    deadline := Time.monotonic-us + 6_000_000
    while sm.state_ != StateManager.STATE-ESTABLISHED and Time.monotonic-us < deadline:
      sleep (Duration --ms=50)
    expect-equals StateManager.STATE-ESTABLISHED sm.state_
    expect-equals "rapid-reprobe-4.local" sm.hostname
    print "  PASS"
  finally:
    sm.stop
    socket.close

test-register-service-is-idempotent:
  // Bug: register-service unconditionally appended to services_ and
  // restarted probing.  A client that re-registers the same service
  // (typical after a WiFi reconnect) caused the service list to grow
  // without bound and triggered a probing storm.  Fix: dedup by
  // (type, instance-name) and only re-enter probing when the entry
  // actually changes.
  print "Test: register-service is idempotent for identical (type, name)..."
  network := net.open
  socket := MdnsSocket --network=network --port=TEST-PORT
  cm := ConflictManager
  local-ip := net.IpAddress.parse "192.168.1.50"
  sm := StateManager socket cm "idem.local" local-ip --expected-port=TEST-PORT
  sm.start
  try:
    deadline := Time.monotonic-us + 5_000_000
    while sm.state_ != StateManager.STATE-ESTABLISHED and Time.monotonic-us < deadline:
      sleep (Duration --ms=50)
    expect-equals StateManager.STATE-ESTABLISHED sm.state_

    sm.register-service "_http._tcp" 80 --name="App" --txt={"path": "/"}
    expect-equals 1 sm.services-count
    // Probing was triggered for the new service.
    deadline = Time.monotonic-us + 5_000_000
    while sm.state_ != StateManager.STATE-ESTABLISHED and Time.monotonic-us < deadline:
      sleep (Duration --ms=50)
    expect-equals StateManager.STATE-ESTABLISHED sm.state_
    generation-after-first := sm.probe-generation_

    // Re-registering the exact same service is a no-op.
    sm.register-service "_http._tcp" 80 --name="App" --txt={"path": "/"}
    expect-equals 1 sm.services-count
    expect (sm.probe-generation_ == generation-after-first)
        --message="identical re-register must not bump probe-generation"

    // Changing the port replaces the entry and re-probes.
    sm.register-service "_http._tcp" 8080 --name="App" --txt={"path": "/"}
    expect-equals 1 sm.services-count
    expect sm.probe-generation_ > generation-after-first
        --message="changed port must restart probing"

    // A different instance-name adds a new entry.
    sm.register-service "_http._tcp" 80 --name="Other"
    expect-equals 2 sm.services-count
    print "  PASS"
  finally:
    sm.stop
    socket.close
