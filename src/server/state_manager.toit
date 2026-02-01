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
  
  probe-count_ := 0
  probe-timer_/Task? := null
  
  // Conflict defense counters
  defend-count_ := 0
  last-defend-time_ := 0

  services_/List := [] // List<RegisteredService>

  /**
  Creates a new StateManager.
  The [hostname] must end with ".local".
  */
  constructor .socket_ .conflict-manager_ hostname/string .local-ip_:
    assert: hostname.ends-with ".local"
    hostname_ = hostname
  
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
  Parses the packet and triggers conflict detection/defense or query responses.
  */
  process-packet packet/ByteArray --source/net.SocketAddress?=null:
    decoded := dns.parse packet
    
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
    // 1. Critical: Update state synchronously to prevent re-entry
    state_ = STATE-PROBING
    probe-count_ = 0
    defend-count_ = 0 // Reset defense count

    if probe-timer_: probe-timer_.cancel

    // 2. Start the probing loop in a task
    probe-timer_ = task::
      try:
        while state_ == STATE-PROBING and probe-count_ < 3:
          probe-count_++
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
    // Send unsolicited announcement
    send-announcement_
    // Transition to established
    state_ = STATE-ESTABLISHED
    log.info "Service established" --tags={"hostname": hostname_, "ip": local-ip_}

  send-probe_:
    questions := [dns.Question hostname_ dns.RECORD-ANY]
    // Add Questions for Service Instances too
    services_.do: | s/RegisteredService |
      questions.add (dns.Question s.full-name dns.RECORD-ANY)
       
    answers := [] 
    packet := dns.create-dns-packet questions answers --id=0 --is-response=false
    
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
  */
  send-response_ query/dns.DecodedPacket? --source/net.SocketAddress?=null:
    unicast-answers := []
    multicast-answers := []
    
    // 1. Hostname A Record
    q-host := find-question_ query hostname_
    if q-host:
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
      // RFC 6762 says ID must match.
      packet := dns.create-dns-packet [] unicast-answers --id=id --is-response --is-authoritative
      socket_.send packet source
       
    // Send Multicast
    if not multicast-answers.is-empty:
      // For Multicast, ID must be 0
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
