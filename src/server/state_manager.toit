/**
mDNS state management and RFC 6762 compliant announcement.

Manages the lifecycle of hostname claims and service registrations through
a three-state machine: PROBING → ANNOUNCING → ESTABLISHED.

# Probing Phase (RFC 6762 Section 8.1)

Before claiming a hostname, we send probe queries to detect conflicts.
If no response in 250ms × 3 attempts, we consider the name available.
If another device responds, we rename and restart probing.

# Announcing Phase (RFC 6762 Section 8.3)

After successful probing, we announce our records as authoritative.
The announcement includes A records for our hostname and SRV/TXT/PTR
records for any registered services.

# Conflict Defense (RFC 6762 Section 9)

Once established, if another device claims our name, we defend it by
re-announcing. If conflicts persist (>3 in 10 seconds), we rename to
avoid endless conflicts with a misbehaving device.

# Unicast Response Support

When queries have the QU (Query Unicast) bit set, we respond directly
to the querier's IP address to reduce multicast traffic.
*/

import net
import net.modules.dns
import ..net.mdns_socket
import ..net.dns_helper as dns
import .conflict_manager
import log

/**
  mDNS state machine managing hostname claims and service announcements.
  
  Handles probing, conflict detection/defense, and query responses per
  RFC 6762 requirements.

  # State Diagram
  ```
        [ Start ]
            |
            v
        +---------+
        | PROBING |<--------------------------+
        +---------+                           |
            |                                 |
            | 3 successful probes             |
            v                                 |
        +------------+                        |
        | ANNOUNCING |                        |
        +------------+                        |
            |                                 |
            | Send unsolicited announcement   | Persistent Conflict
            v                                 | (Rename)
       +-------------+                        |
   +---| ESTABLISHED |------------------------+
   |   +-------------+
   |          ^
   | Conflict |
   | (Defend) |
   +----------+
  ```
  */
class StateManager:
  /// Currently probing for name availability.
  static STATE-PROBING ::= 0
  /// Successfully probed, announcing presence.
  static STATE-ANNOUNCING ::= 1
  /// Stable state, responding to queries and defending name.
  static STATE-ESTABLISHED ::= 2

  state_/int := STATE-PROBING
  socket_/MdnsSocket
  conflict-manager_/ConflictManager
  local-ip_/net.IpAddress
  hostname_/string := ? // Mutable
  expected-port_/int  // RFC 6762 §6.10: port we validate responses from.
  
  probe-count_ := 0
  probe-timer_/Task? := null
  first-probe-sent_/bool := false
  stopped_/bool := false
  
  // Conflict defense counters
  defend-count_ := 0
  last-defend-time_ := 0

  // RFC 6762 §8.1: After 15 rapid conflicts, rate-limit probing.
  conflict-count_ := 0
  conflict-window-start_ := 0
  static CONFLICT-RATE-LIMIT-THRESHOLD_ ::= 15
  static CONFLICT-RATE-LIMIT-WINDOW-US_ ::= 10_000_000  // 10 seconds.
  static CONFLICT-RATE-LIMIT-DELAY-MS_ ::= 5_000  // 5 seconds.

  // RFC 6762 §6.16: Response rate limiting.
  // Simplified to a global per-manager cooldown. The RFC requires
  // per-record tracking, but this conservative approach never sends
  // faster than allowed.
  last-multicast-time_ := 0 // Monotonic-us of last multicast response.

  services_/List := [] // List<RegisteredService>

  /**
  Creates a new StateManager.
  The [hostname] must end with ".local".
  The [expected-port] defaults to 5353 per RFC 6762 §6.10.
  */
  constructor .socket_ .conflict-manager_ hostname/string .local-ip_ --expected-port/int=5353:
    assert: hostname.ends-with ".local"
    hostname_ = hostname
    expected-port_ = expected-port
  
  /**
  Registers a service to be announced.
  The [type] should be a service type like "_http._tcp".
  The [port] is the port the service is running on.
  The [txt] map contains TXT record key-value pairs.
  The [name] is the instance name. If null, it defaults to the hostname (without .local).

  # Examples
  ```
  state-manager.register-service "_http._tcp" 8080 --txt={"path": "/"}
  ```
  */
  register-service type/string port/int -> none
      --txt/Map?=null
      --name/string?=null:
    // Default name to hostname (without .local) if null
    instance-name := name or (hostname_.copy 0 hostname_.size - 6)
    service := RegisteredService type instance-name port txt
    services_.add service
    if state_ != STATE-PROBING:
      enter-probing_

  /**
  Starts the state machine. Begins by entering the probing phase.
  */
  start:
    enter-probing_

  /**
  Stops the probing/announcing process and cancels any pending timers.
  */
  stop:
    stopped_ = true
    if probe-timer_: 
      probe-timer_.cancel
      probe-timer_ = null

  /**
  Updates the hostname.
  If the hostname changes, it restarts the probing process for the new name.
  The [new-hostname] must end with ".local".
  */
  set-hostname new-hostname/string -> none:
    assert: new-hostname.ends-with ".local"
    if hostname_ == new-hostname: return
    hostname_ = new-hostname
    // Restart probing for the new name
    enter-probing_

  /**
  Processes an incoming mDNS packet.
  Called from the service for every packet.
  Triggers conflict detection/defense or query responses.
  */
  process-packet decoded/dns.DecodedPacket --source/net.SocketAddress?=null:
    // RFC 6762 §18.3, §18.11: Reject non-zero OPCODE or RCODE.
    if not dns.is-valid-mdns-message decoded: return

    // RFC 6762 §6.10: Reject responses not from the expected mDNS port.
    if decoded.is-response and source:
      if source.port != expected-port_: return

    // --- Simultaneous Probe Tiebreaking (RFC 6762 Section 8.2) ---
    // If we're probing and we see another probe for the same name,
    // compare our proposed rdata with theirs lexicographically.
    if state_ == STATE-PROBING and dns.is-probe-for decoded hostname_:
      their-addrs := dns.get-authority-addresses decoded hostname_
      if not their-addrs.is-empty:
        // Compare our IP against each of their proposed IPs.
        // Per RFC 6762, the lexicographically later rdata wins.
        we-lose := their-addrs.any: | their-ip/net.IpAddress |
          (dns.compare-addresses local-ip_ their-ip) < 0
        if we-lose:
          // We lose the tiebreak. Wait 1 second, then re-probe.
          // (The other host will complete probing and claim the name;
          // when we re-probe, we'll see their response and rename.)
          log.info "Probe tiebreak lost, deferring" --tags={"hostname": hostname_}
          if probe-timer_: probe-timer_.cancel
          probe-timer_ = task::
            try:
              sleep (Duration --s=1)
              enter-probing_
            finally:
              if probe-timer_ == Task.current: probe-timer_ = null
          return

    // --- Conflict detection from authoritative responses ---
    // RFC 6762 §8.5: Responses received *before* the first probe
    // packet is sent MUST be silently ignored.
    if state_ == STATE-PROBING and not first-probe-sent_: return

    if dns.is-authoritative-response-for decoded hostname_:
      // Check if RData is different (RFC 6762 Section 9)
      is-conflict := false
      decoded.resources.do: | res |
        if res.name == hostname_ and res is dns.AResource:
          addr := (res as dns.AResource).address
          if addr != local-ip_:
            is-conflict = true

      if is-conflict:
        if state_ == STATE-PROBING:
          handle-probing-conflict_
        else if state_ == STATE-ESTABLISHED:
          handle-established-conflict_

    if state_ != STATE-ESTABLISHED: return

    if dns.is-query-for decoded hostname_:
      // Respond to query
      send-response_ decoded --source=source

    // Check services
    is-relevant-query := services_.any: | s/RegisteredService |
      dns.is-query-for decoded s.full-name or
        dns.is-query-for decoded s.type-domain or
        dns.is-query-for decoded "_services._dns-sd._udp.local"
    
    if is-relevant-query:
      send-response_ decoded --source=source

  enter-probing_:
    if stopped_: return
    // 1. Critical: Update state synchronously to prevent re-entry
    state_ = STATE-PROBING
    probe-count_ = 0
    first-probe-sent_ = false
    defend-count_ = 0 // Reset defense count

    if probe-timer_: probe-timer_.cancel

    // 2. Start the probing loop in a task
    probe-timer_ = task::
      try:
        // RFC 6762 §8.7: After 15 conflicts in 10 seconds,
        // wait at least 5 seconds before each successive attempt.
        now := Time.monotonic-us
        if now - conflict-window-start_ > CONFLICT-RATE-LIMIT-WINDOW-US_:
          conflict-count_ = 0
          conflict-window-start_ = now
        if conflict-count_ >= CONFLICT-RATE-LIMIT-THRESHOLD_:
          log.warn "Rate limiting: too many conflicts" --tags={"count": conflict-count_}
          sleep (Duration --ms=CONFLICT-RATE-LIMIT-DELAY-MS_)

        // RFC 6762 Section 8.1: Random delay of 0-250ms before first
        // probe to reduce probability of simultaneous probes from
        // devices that power on at the same time.
        jitter-ms := random 251  // 0..250 inclusive
        sleep (Duration --ms=jitter-ms)

        while state_ == STATE-PROBING and probe-count_ < 3:
          probe-count_++
          first-probe-sent_ = true
          send-probe_
          sleep (Duration --ms=250)
        
        if state_ == STATE-PROBING:
          enter-announcing_
      finally:
        // If enter-probing_ was called again (e.g. because of a rename),
        // it cancelled this task and started a new one (updating probe-timer_).
        // We must ensure we don't null out the new timer.
        if probe-timer_ == Task.current: probe-timer_ = null

  handle-probing-conflict_:
    if probe-timer_: probe-timer_.cancel
    conflict-count_++
    // Pick a new name and restart probing
    new-name := conflict-manager_.resolve-probing-conflict hostname_
    hostname_ = new-name
    enter-probing_

  handle-established-conflict_:
    // RFC 6762 Section 9: Defend the name by sending a response.
    // If we see more than a few conflicts in a short period (e.g. 10s), we must back off.
    
    now := Time.monotonic-us
    
    // If it's been more than 10 seconds since last defense, reset counter.
    if now - last-defend-time_ > 10_000_000:
      defend-count_ = 0
    
    if defend-count_ < 3:
      log.warn "Defending name" --tags={"hostname": hostname_}
      defend-count_++
      last-defend-time_ = now
      send-announcement_ // Re-announce to assert authority
    else:
      log.warn "Conflict persistence detected. Renaming..." --tags={"hostname": hostname_}
      new-name := conflict-manager_.resolve-established-conflict hostname_
      hostname_ = new-name
      enter-probing_

  enter-announcing_:
    state_ = STATE-ANNOUNCING
    // RFC 6762 §8.3: "The Multicast DNS responder MUST send at least
    //  two unsolicited responses, one second apart."
    send-announcement_
    sleep (Duration --s=1)
    // Only send the second announcement if we haven't been moved
    // back to probing (e.g. by a conflict during the 1s wait).
    if state_ == STATE-ANNOUNCING:
      send-announcement_
    // Transition to established
    state_ = STATE-ESTABLISHED
    log.info "Service established" --tags={"hostname": hostname_, "ip": local-ip_}

  send-probe_:
    questions := [dns.Question hostname_ dns.RECORD-ANY]
    // Add Questions for Service Instances too
    services_.do: | s/RegisteredService |
      questions.add (dns.Question s.full-name dns.RECORD-ANY)

    // RFC 6762 Section 8.2: Include our proposed A record in the
    // Authority Section so other probers can do tiebreaking.
    authorities := [dns.AResource hostname_ 120 local-ip_]

    answers := []
    packet := dns.create-dns-packet questions answers
        --id=0
        --is-response=false
        --authorities=authorities
    
    // The socket might be closed if the service is shut down while we are
    // in the probing loop. The loop checks state_ at the top, but the
    // socket close happens asynchronously in another task (on stop).
    if socket_.is-closed: return
    socket_.send packet

  send-announcement_:
    questions := []
    // A Record
    answers := [dns.AResource hostname_ 120 local-ip_ --flush]
    
    // Add Service Records
    services_.do: | s/RegisteredService |
      // PTR: _type._tcp.local -> Instance._type._tcp.local
      answers.add (dns.StringResource s.type-domain dns.RECORD-PTR 4500 false s.full-name)
      // SRV: Instance -> hostname:port
      answers.add (dns.SrvResource s.full-name dns.RECORD-SRV 120 true hostname_ 0 0 s.port)
      // TXT: Instance -> txt-data
      txt-list := build-txt-list_ s.txt
      answers.add (dns.TxtResource s.full-name 4500 true txt-list)
       
    packet := dns.create-dns-packet questions answers --id=0 --is-response --is-authoritative
    socket_.send packet

  /**
  Sends a response to a query.
  Checks QU bits in questions to determine unicast vs multicast.
  Applies Known-Answer Suppression per RFC 6762 §7.1.
  */
  send-response_ query/dns.DecodedPacket? --source/net.SocketAddress?=null:
    unicast-answers := []
    multicast-answers := []
    
    // 1. Hostname A Record
    q-host := find-question_ query hostname_
    if q-host:
      // RFC 6762 §7.1: Suppress if already in Known-Answer Section
      // with TTL ≥ 50% of our real TTL.
      if not query or not dns.has-known-answer query hostname_ dns.RECORD-A 120:
        target := q-host.unicast-ok ? unicast-answers : multicast-answers
        target.add (dns.AResource hostname_ 120 local-ip_)
    else if not query:
      // Announcement
      multicast-answers.add (dns.AResource hostname_ 120 local-ip_ --flush)

    // 2. Services
    services_.do: | s/RegisteredService |
      // PTR
      q-ptr := find-question_ query s.type-domain
      q-all := find-question_ query "_services._dns-sd._udp.local"

      if q-ptr or q-all:
        // Known-Answer Suppression for PTR
        if query and dns.has-known-answer query s.type-domain dns.RECORD-PTR 4500 --data=s.full-name:
          continue.do  // Suppress this specific instance

        ptr-unicast := q-ptr ? q-ptr.unicast-ok : false
        all-unicast := q-all ? q-all.unicast-ok : false
        is-unicast := ptr-unicast or all-unicast

        target := is-unicast ? unicast-answers : multicast-answers
        target.add (dns.StringResource s.type-domain dns.RECORD-PTR 4500 false s.full-name)

        // Additionals
        target.add (dns.SrvResource s.full-name dns.RECORD-SRV 120 true hostname_ 0 0 s.port)
        txt-list := build-txt-list_ s.txt
        target.add (dns.TxtResource s.full-name 4500 true txt-list)
        target.add (dns.AResource hostname_ 120 local-ip_)

      // SRV/TXT direct query
      q-srv := find-question_ query s.full-name
      if q-srv:
        target := q-srv.unicast-ok ? unicast-answers : multicast-answers
        target.add (dns.SrvResource s.full-name dns.RECORD-SRV 120 true hostname_ 0 0 s.port)
        txt-list := build-txt-list_ s.txt
        target.add (dns.TxtResource s.full-name 4500 true txt-list)
        target.add (dns.AResource hostname_ 120 local-ip_)

    // Send Unicast
    if not unicast-answers.is-empty and source:
      // For Unicast, ID matches query
      id := query ? query.id : 0
      // RFC 6762 §18.3: ID must match for legacy/unicast responses.
      packet := dns.create-dns-packet [] unicast-answers --id=id --is-response --is-authoritative
      socket_.send packet source
       
    // Send Multicast
    if not multicast-answers.is-empty:
      // RFC 6762 §6.16: Rate limit multicast responses to 1/s/record.
      // Skip rather than sleep to avoid blocking the receive loop.
      now := Time.monotonic-us
      elapsed-us := now - last-multicast-time_
      if last-multicast-time_ != 0 and elapsed-us < 1_000_000:
        return
      last-multicast-time_ = now

      // For Multicast, ID must be 0 (RFC 6762 §18.1)
      packet := dns.create-dns-packet [] multicast-answers --id=0 --is-response --is-authoritative
      socket_.send packet // Uses default multicast target

  find-question_ query/dns.DecodedPacket? name/string -> dns.Question?:
    if not query: return null
    query.questions.do: | q |
       if q.name == name: return q
    return null

  hostname -> string:
    return hostname_

  build-txt-list_ txt/Map? -> List:
    if not txt or txt.is-empty: return [""]
    list := []
    txt.do: | k v |
       list.add "$k=$v"
    return list

class RegisteredService:
  type/string
  instance-name/string
  port/int
  txt/Map?
  
  constructor .type .instance-name .port .txt:

  full-name -> string:
    return "$(instance-name).$(type).local"

  type-domain -> string:
    return "$(type).local"
