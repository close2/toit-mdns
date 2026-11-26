/**
mDNS state management and RFC 6762 / RFC 6763 compliant responder.

Manages the lifecycle of hostname claims and service registrations through
a three-state machine: `PROBING -> ANNOUNCING -> ESTABLISHED`.
*/

import log
import net
import net.modules.dns
import ..net.mdns-socket
import ..net.dns-helper as dns
import ..net.names as names
import .conflict-manager

class DeferredRecord_:
  record/dns.Resource
  rate-key/string
  due-us/int

  constructor .record .rate-key .due-us:

/**
mDNS state machine managing hostname claims, service announcements,
conflict defense, restricted-form `NSEC` negative responses, and
rate-limited / deferred multicast transmission.
*/
class StateManager:
  /// Currently probing for name availability.
  static STATE-PROBING ::= 0
  /// Successfully probed, announcing presence.
  static STATE-ANNOUNCING ::= 1
  /// Stable state, responding to queries and defending name.
  static STATE-ESTABLISHED ::= 2

  static CONFLICT-RATE-LIMIT-THRESHOLD_ ::= 15
  static CONFLICT-RATE-LIMIT-WINDOW-US_ ::= 10_000_000  // 10 seconds.
  static CONFLICT-RATE-LIMIT-DELAY-MS_ ::= 5_000        // 5 seconds.

  /// Per-record multicast rate limit (RFC 6762 §6: at most once per second).
  static MULTICAST-RATE-LIMIT-WINDOW-US_ ::= 1_000_000
  /// Probe-defense rate limit exception (RFC 6762 §6: at most once per 250ms).
  static PROBE-DEFENSE-RATE-LIMIT-US_ ::= 250_000
  /// Quarter of longest emitted TTL (4500s / 4), used for RFC 6762 §5.4 QU decisions.
  static MAX-QU-MULTICAST-WINDOW-US_ ::= 4500 * 250_000
  /// Upper bound on queued deferred multicast records.
  static MAX-DEFERRED-RECORDS_ ::= 64

  state_/int := STATE-PROBING
  socket_/MdnsSocket := ?
  conflict-manager_/ConflictManager
  local-ip_/net.IpAddress := ?
  hostname_/string := ?
  expected-port_/int

  probe-count_/int := 0
  probe-timer_/Task? := null
  probe-generation_/int := 0
  first-probe-sent_/bool := false
  stopped_/bool := false

  conflict-count_/int := 0
  conflict-window-start_/int := 0

  last-multicast-times_/Map := {:}  // rate-key -> monotonic-us
  deferred-multicast_/Map := {:}    // rate-key -> DeferredRecord_
  deferred-send-task_/Task? := null
  deferred-wakeup-us_/int := 0

  services_/List := []  // List<RegisteredService>

  host-a-probe_/dns.AResource? := null
  host-a-120_/dns.AResource? := null
  host-a-10_/dns.AResource? := null
  host-goodbye_/dns.AResource? := null
  host-a-rate-key_/string := ""
  host-nsec-rate-key_/string := ""

  /** Number of registered services. Exposed for tests. */
  services-count -> int:
    return services_.size

  /**
  Creates a new $StateManager.
  The $hostname must end with `.local` (case-insensitive).
  */
  constructor .socket_ .conflict-manager_ hostname/string .local-ip_ --expected-port/int=5353:
    assert: names.validate-hostname hostname
    hostname_ = hostname
    expected-port_ = expected-port
    rebuild-host-records_

  rebuild-host-records_ -> none:
    lower := hostname_.to-ascii-lower
    host-a-probe_ = dns.AResource hostname_ 120 local-ip_
    host-a-120_ = dns.AResource hostname_ 120 local-ip_ --flush
    host-a-10_ = dns.AResource hostname_ 10 local-ip_
    host-goodbye_ = dns.AResource hostname_ 0 local-ip_
    host-a-rate-key_ = "$lower:$(dns.RECORD-A)"
    host-nsec-rate-key_ = "$lower:$(dns.RECORD-NSEC)"

  /**
  Updates the socket and local IP after a network interface recovery and
  restarts probing per RFC 6762 §8.1.
  */
  update-network socket/MdnsSocket local-ip/net.IpAddress -> none:
    socket_ = socket
    local-ip_ = local-ip
    rebuild-host-records_
    cancel-deferred-multicast_
    if not stopped_: enter-probing_

  /**
  Registers a DNS-SD service to be probed and announced.
  */
  register-service type/string port/int -> none
      --txt/Map?=null
      --name/string?=null:
    assert: names.validate-service-type type
    if name: assert: names.validate-instance-name name
    assert: names.validate-txt txt
    instance-name := name or (hostname_.copy 0 hostname_.size - 6)
    // Dedup across reconnects: match both original-instance-name and the
    // conflict-renamed instance-name so re-registering after a rename keeps
    // the conflict-resolved name stable without duplicating entries.
    services_.size.repeat: | i |
      existing/RegisteredService := services_[i]
      if (dns.name-equals existing.type type) and
          (existing.original-instance-name == instance-name or existing.instance-name == instance-name):
        if existing.port == port and (txt-equals_ existing.txt txt): return
        services_[i] = RegisteredService type existing.original-instance-name existing.instance-name port txt
        if state_ == STATE-ANNOUNCING or state_ == STATE-ESTABLISHED:
          announce-now_
        else:
          enter-probing_
        return
    services_.add (RegisteredService type instance-name instance-name port txt)
    enter-probing_

  /**
  Unregisters a previously registered service, sending voluntary `TTL=0`
  goodbye records if currently announcing or established.
  */
  unregister-service type/string --name/string?=null -> bool:
    target-name := name or (hostname_.copy 0 hostname_.size - 6)
    services_.size.repeat: | i |
      s/RegisteredService := services_[i]
      if (dns.name-equals s.type type) and
          ((dns.name-equals s.original-instance-name target-name) or
              (dns.name-equals s.instance-name target-name)):
        services_.remove --at=i
        if not stopped_ and (state_ == STATE-ANNOUNCING or state_ == STATE-ESTABLISHED):
          send-service-goodbye_ s
        return true
    return false

  static txt-equals_ a/Map? b/Map? -> bool:
    if identical a b: return true
    if a == null or b == null: return false
    if a.size != b.size: return false
    a.do: | key value |
      if not b.contains key: return false
      if b[key] != value: return false
    return true

  /** Starts the state machine by entering the probing phase. */
  start -> none:
    stopped_ = false
    enter-probing_

  /**
  Stops probing/announcing, cancels background tasks, and sends voluntary
  `TTL=0` goodbye records (RFC 6762 §10.1) if ownership was announced.
  */
  stop -> none:
    if stopped_: return
    was-announced := state_ == STATE-ANNOUNCING or state_ == STATE-ESTABLISHED
    stopped_ = true
    probe-generation_++
    if probe-timer_:
      probe-timer_.cancel
      probe-timer_ = null
    cancel-deferred-multicast_
    if was-announced:
      send-goodbye_

  /**
  Updates the hostname and restarts probing if it changed.
  */
  set-hostname new-hostname/string -> none:
    assert: names.validate-hostname new-hostname
    if dns.name-equals hostname_ new-hostname: return
    if not stopped_ and (state_ == STATE-ANNOUNCING or state_ == STATE-ESTABLISHED):
      send-host-goodbye_ hostname_
    hostname_ = new-hostname
    rebuild-host-records_
    cancel-deferred-multicast_
    enter-probing_

  /**
  Processes an incoming mDNS packet for conflict detection, tiebreaking,
  and query responses.
  */
  process-packet decoded/dns.DecodedPacket --source/net.SocketAddress?=null -> none:
    if stopped_: return
    if not dns.is-valid-mdns-message decoded: return

    // RFC 6762 §6.10: Reject responses not from the expected mDNS port.
    if decoded.is-response and source:
      if source.port != expected-port_: return

    // --- Simultaneous Probe Tiebreaking (RFC 6762 §8.2) ---
    if state_ == STATE-PROBING and dns.is-probe-for decoded hostname_:
      our-host-records := [host-a-probe_]
      cmp := dns.compare-probe-tiebreak our-host-records decoded.authorities hostname_
      if cmp != null and cmp < 0:
        log.info "Probe tiebreak lost, deferring" --tags={"hostname": hostname_}
        defer-probing-one-second_
        return

    // RFC 6762 §8.5: Responses received before the first probe packet is
    // sent MUST be silently ignored.
    if state_ == STATE-PROBING and not first-probe-sent_: return

    // --- Hostname conflict detection across all response sections (RFC 6762 §9) ---
    if dns.is-authoritative-response-for decoded hostname_:
      is-conflict := false
      dns.do-response-records-for decoded hostname_: | res/dns.Resource |
        if res.type == dns.RECORD-A and res is dns.AResource:
          addr := (res as dns.AResource).address
          if addr != local-ip_:
            is-conflict = true

      if is-conflict:
        if state_ == STATE-PROBING:
          handle-probing-conflict_
          return
        else if state_ == STATE-ANNOUNCING or state_ == STATE-ESTABLISHED:
          restart-probing-keeping-name_
          return

    // --- Service-instance tiebreaking & conflict detection (RFC 6762 §8 / §9) ---
    services_.size.repeat: | i |
      s/RegisteredService := services_[i]
      if state_ == STATE-PROBING and dns.is-probe-for decoded s.full-name:
        our-srv-records := [
          dns.SrvResource s.full-name dns.RECORD-SRV 120 false hostname_ 0 0 s.port,
          dns.TxtResource s.full-name 4500 false (build-txt-list_ s.txt),
        ]
        cmp := dns.compare-probe-tiebreak our-srv-records decoded.authorities s.full-name
        if cmp != null and cmp < 0:
          log.info "Service-instance probe tiebreak lost, deferring" --tags={"service": s.full-name}
          defer-probing-one-second_
          return
      if dns.is-authoritative-response-for decoded s.full-name:
        is-srv-conflict := false
        dns.do-response-records-for decoded s.full-name: | res/dns.Resource |
          if res.type == dns.RECORD-SRV and res is dns.SrvResource:
            srv := res as dns.SrvResource
            if not (dns.name-equals srv.value hostname_) or srv.port != s.port:
              is-srv-conflict = true
        if is-srv-conflict:
          if state_ == STATE-PROBING:
            handle-service-conflict_ i
            return
          else if state_ == STATE-ANNOUNCING or state_ == STATE-ESTABLISHED:
            restart-probing-keeping-name_
            return

    if state_ != STATE-ANNOUNCING and state_ != STATE-ESTABLISHED: return

    if not decoded.is-response and (has-relevant-question_ decoded):
      send-response_ decoded --source=source

  defer-probing-one-second_ -> none:
    record-conflict_
    probe-generation_++
    probe-count_ = 0
    first-probe-sent_ = false
    my-generation := probe-generation_
    if probe-timer_: probe-timer_.cancel
    probe-timer_ = task::
      try:
        sleep (Duration --s=1)
        if not stopped_ and probe-generation_ == my-generation:
          enter-probing_
      finally:
        if probe-timer_ == Task.current: probe-timer_ = null

  has-relevant-question_ query/dns.DecodedPacket -> bool:
    if dns.is-query-for query hostname_: return true
    n := services_.size
    n.repeat: | i |
      s/RegisteredService := services_[i]
      if dns.is-query-for query s.full-name: return true
      if dns.is-query-for query s.type-domain: return true
    return dns.is-query-for query "_services._dns-sd._udp.local"

  enter-probing_ -> none:
    if stopped_: return
    state_ = STATE-PROBING
    probe-count_ = 0
    first-probe-sent_ = false
    probe-generation_++
    cancel-deferred-multicast_

    if probe-timer_: probe-timer_.cancel

    my-generation := probe-generation_
    probe-timer_ = task::
      try:
        now := Time.monotonic-us
        if now - conflict-window-start_ > CONFLICT-RATE-LIMIT-WINDOW-US_:
          conflict-count_ = 0
          conflict-window-start_ = now
        if conflict-count_ >= CONFLICT-RATE-LIMIT-THRESHOLD_:
          log.warn "Rate limiting: too many conflicts" --tags={"count": conflict-count_}
          sleep (Duration --ms=CONFLICT-RATE-LIMIT-DELAY-MS_)

        jitter-ms := random 251
        sleep (Duration --ms=jitter-ms)

        while not stopped_
            and probe-generation_ == my-generation
            and state_ == STATE-PROBING
            and probe-count_ < 3:
          probe-count_++
          first-probe-sent_ = true
          send-probe_
          sleep (Duration --ms=250)

        if not stopped_
            and probe-generation_ == my-generation
            and state_ == STATE-PROBING:
          enter-announcing_ my-generation
      finally:
        if probe-timer_ == Task.current: probe-timer_ = null

  handle-probing-conflict_ -> none:
    if probe-timer_: probe-timer_.cancel
    record-conflict_
    hostname_ = conflict-manager_.resolve-probing-conflict hostname_
    rebuild-host-records_
    enter-probing_

  restart-probing-keeping-name_ -> none:
    log.warn "Conflict detected while established; resetting to probing" --tags={"hostname": hostname_}
    record-conflict_
    enter-probing_

  handle-service-conflict_ i/int -> none:
    record-conflict_
    s/RegisteredService := services_[i]
    new-instance := conflict-manager_.resolve-probing-conflict s.instance-name
    services_[i] = RegisteredService s.type s.original-instance-name new-instance s.port s.txt
    log.warn "Service-instance renamed"
        --tags={"old": s.instance-name, "new": new-instance}
    enter-probing_

  announce-now_ -> none:
    if stopped_: return
    probe-generation_++
    cancel-deferred-multicast_
    if probe-timer_: probe-timer_.cancel
    my-generation := probe-generation_
    probe-timer_ = task::
      try:
        enter-announcing_ my-generation
      finally:
        if probe-timer_ == Task.current: probe-timer_ = null

  record-conflict_ -> none:
    now := Time.monotonic-us
    if now - conflict-window-start_ > CONFLICT-RATE-LIMIT-WINDOW-US_:
      conflict-count_ = 0
      conflict-window-start_ = now
    conflict-count_++

  enter-announcing_ generation/int -> none:
    state_ = STATE-ANNOUNCING
    send-announcement_
    sleep (Duration --s=1)
    if stopped_ or probe-generation_ != generation: return
    if state_ == STATE-ANNOUNCING:
      send-announcement_
    if not stopped_ and probe-generation_ == generation and state_ == STATE-ANNOUNCING:
      state_ = STATE-ESTABLISHED
      log.info "Service established" --tags={"hostname": hostname_, "ip": local-ip_}

  send-probe_ -> none:
    if socket_.is-closed: return
    max-size := socket_.max-payload-size
    // Group each name's Question with its Authority records so split probes
    // keep matching Questions and Authorities together per RFC 6762 §8.2.
    groups := [
      [
        [dns.Question hostname_ dns.RECORD-ANY --unicast-ok],
        [host-a-probe_],
      ],
    ]
    services_.do: | s/RegisteredService |
      groups.add [
        [dns.Question s.full-name dns.RECORD-ANY --unicast-ok],
        [
          dns.SrvResource s.full-name dns.RECORD-SRV 120 false hostname_ 0 0 s.port,
          dns.TxtResource s.full-name 4500 false (build-txt-list_ s.txt),
        ],
      ]

    batch-q := []
    batch-auth := []
    groups.do: | group/List |
      gq := group[0] as List
      ga := group[1] as List
      if not batch-q.is-empty:
        cand-q := batch-q.copy
        cand-q.add-all gq
        cand-auth := batch-auth.copy
        cand-auth.add-all ga
        fits := false
        catch:
          pkts := dns.encode-mdns-packets cand-q []
              --is-response=false
              --authorities=cand-auth
              --max-size=max-size
          fits = pkts.size == 1
        if fits:
          batch-q = cand-q
          batch-auth = cand-auth
        else:
          send-raw_ --queries=batch-q --records=[] --no-is-response --authorities=batch-auth
          batch-q = gq.copy
          batch-auth = ga.copy
      else:
        batch-q.add-all gq
        batch-auth.add-all ga
    if not batch-q.is-empty:
      send-raw_ --queries=batch-q --records=[] --no-is-response --authorities=batch-auth

  build-full-announcement-records_ -> List:
    answers := [host-a-120_]
    services_.do: | s/RegisteredService |
      answers.add (dns.StringResource s.type-domain dns.RECORD-PTR 4500 false s.full-name)
      answers.add (dns.SrvResource s.full-name dns.RECORD-SRV 120 true hostname_ 0 0 s.port)
      answers.add (dns.TxtResource s.full-name 4500 true (build-txt-list_ s.txt))
    return answers

  send-announcement_ -> none:
    if socket_.is-closed: return
    answers := build-full-announcement-records_
    now := Time.monotonic-us
    answers.do: | rec/dns.Resource |
      last-multicast-times_[record-rate-key_ rec] = now
    send-raw_ --queries=[] --records=answers --is-response --is-authoritative

  send-goodbye_ -> none:
    if socket_.is-closed: return
    records := [host-goodbye_]
    services_.do: | s/RegisteredService |
      records.add (dns.StringResource s.type-domain dns.RECORD-PTR 0 false s.full-name)
      records.add (dns.SrvResource s.full-name dns.RECORD-SRV 0 false hostname_ 0 0 s.port)
      records.add (dns.TxtResource s.full-name 0 false (build-txt-list_ s.txt))
    send-raw_ --queries=[] --records=records --is-response --is-authoritative

  send-host-goodbye_ old-hostname/string -> none:
    if socket_.is-closed: return
    send-raw_
        --queries=[]
        --records=[dns.AResource old-hostname 0 local-ip_]
        --is-response
        --is-authoritative

  send-service-goodbye_ s/RegisteredService -> none:
    if socket_.is-closed: return
    records := [
      dns.StringResource s.type-domain dns.RECORD-PTR 0 false s.full-name,
      dns.SrvResource s.full-name dns.RECORD-SRV 0 false hostname_ 0 0 s.port,
      dns.TxtResource s.full-name 0 false (build-txt-list_ s.txt),
    ]
    send-raw_ --queries=[] --records=records --is-response --is-authoritative

  was-multicast-within-quarter-ttl_ rec/dns.Resource ttl-s/int now/int -> bool:
    last := last-multicast-times_.get (record-rate-key_ rec)
    if not last: return false
    return (now - last) < (ttl-s * 250_000)

  record-rate-key_ rec/dns.Resource -> string:
    if rec.type == dns.RECORD-A and (dns.name-equals rec.name hostname_):
      return host-a-rate-key_
    if rec.type == dns.RECORD-NSEC and (dns.name-equals rec.name hostname_):
      return host-nsec-rate-key_
    owner := rec.name.to-ascii-lower
    if rec.type == dns.RECORD-PTR and rec is dns.StringResource:
      return "$owner:$(rec.type):$((rec as dns.StringResource).value.to-ascii-lower)"
    return "$owner:$(rec.type)"

  /**
  Sends a response to a query, handling QU/legacy unicast, Known-Answer
  Suppression (RFC 6762 §7.1), restricted-form `NSEC` negative answers
  (RFC 6762 §6.1), and rate-limited / deferred multicast transmission.
  */
  send-response_ query/dns.DecodedPacket? --source/net.SocketAddress?=null -> none:
    if socket_.is-closed: return
    unicast-answers := []
    unicast-additionals := []
    multicast-answers := []
    multicast-additionals := []
    legacy-query := source != null and source.port != expected-port_
    is-probe-query := query != null and not query.authorities.is-empty
    now := Time.monotonic-us

    // 1. Hostname A record + restricted-form NSEC for unsupported types (e.g. AAAA).
    q-host := find-question_ query hostname_ dns.RECORD-A
    if q-host:
      host-answer := legacy-query ? host-a-10_ : host-a-120_
      if not query or not dns.has-known-answer query hostname_ dns.RECORD-A 120 --record=host-answer:
        // Probe defenses are always multicast so co-hosted SO_REUSEPORT sockets
        // and LAN peers reliably observe the defense (RFC 6762 §6 / §8).
        use-unicast := legacy-query or
            (not is-probe-query and source != null and q-host.unicast-ok and
                (was-multicast-within-quarter-ttl_ host-answer 120 now))
        add-unique-record_ (use-unicast ? unicast-answers : multicast-answers) host-answer
    else if not query:
      add-unique-record_ multicast-answers host-a-120_

    q-host-neg := find-negative-question_ query hostname_ [dns.RECORD-A]
    if q-host-neg:
      nsec-ttl := legacy-query ? 10 : 120
      nsec := dns.NsecResource hostname_ nsec-ttl (not legacy-query) hostname_ [dns.RECORD-A]
      if not dns.has-known-answer query hostname_ dns.RECORD-NSEC 120 --record=nsec:
        use-unicast := legacy-query or
            (not is-probe-query and source != null and q-host-neg.unicast-ok and
                (was-multicast-within-quarter-ttl_ nsec 120 now))
        add-unique-record_ (use-unicast ? unicast-answers : multicast-answers) nsec

    // 2. Registered Services.
    services-snapshot-size := services_.size
    services-snapshot-size.repeat: | i |
      s/RegisteredService := services_[i]
      q-ptr := find-question_ query s.type-domain dns.RECORD-PTR
      q-meta := find-question_ query "_services._dns-sd._udp.local" dns.RECORD-PTR

      ptr-ttl := legacy-query ? 10 : 4500
      srv-ttl := legacy-query ? 10 : 120
      txt-ttl := legacy-query ? 10 : 4500
      host-ttl := legacy-query ? 10 : 120
      additional-flush := not legacy-query

      if q-meta:
        meta-answer := dns.StringResource
            "_services._dns-sd._udp.local"
            dns.RECORD-PTR
            ptr-ttl
            false
            s.type-domain
        if not (query and dns.has-known-answer query "_services._dns-sd._udp.local" dns.RECORD-PTR 4500 --record=meta-answer):
          use-unicast := legacy-query or
              (not is-probe-query and source != null and q-meta.unicast-ok and
                  (was-multicast-within-quarter-ttl_ meta-answer 4500 now))
          add-unique-record_ (use-unicast ? unicast-answers : multicast-answers) meta-answer

      if q-ptr:
        ptr-answer := dns.StringResource s.type-domain dns.RECORD-PTR ptr-ttl false s.full-name
        ptr-suppressed := query and
            dns.has-known-answer query s.type-domain dns.RECORD-PTR 4500 --record=ptr-answer
        if not ptr-suppressed:
          use-unicast := legacy-query or
              (not is-probe-query and source != null and q-ptr.unicast-ok and
                  (was-multicast-within-quarter-ttl_ ptr-answer 4500 now))
          ans-target := use-unicast ? unicast-answers : multicast-answers
          add-target := use-unicast ? unicast-additionals : multicast-additionals
          add-unique-record_ ans-target ptr-answer
          // RFC 6763 §12.1: Include SRV, TXT, and A in the Additional Record Section.
          add-unique-record_ add-target (dns.SrvResource s.full-name dns.RECORD-SRV srv-ttl additional-flush hostname_ 0 0 s.port)
          add-unique-record_ add-target (dns.TxtResource s.full-name txt-ttl additional-flush (build-txt-list_ s.txt))
          add-unique-record_ add-target (legacy-query ? host-a-10_ : host-a-120_)

      q-srv := find-question_ query s.full-name dns.RECORD-SRV
      q-txt := find-question_ query s.full-name dns.RECORD-TXT
      if q-srv or q-txt:
        srv-rec := dns.SrvResource s.full-name dns.RECORD-SRV srv-ttl additional-flush hostname_ 0 0 s.port
        txt-rec := dns.TxtResource s.full-name txt-ttl additional-flush (build-txt-list_ s.txt)
        srv-suppressed := q-srv != null and query != null and
            (dns.has-known-answer query s.full-name dns.RECORD-SRV 120 --record=srv-rec)
        txt-suppressed := q-txt != null and query != null and
            (dns.has-known-answer query s.full-name dns.RECORD-TXT 4500 --record=txt-rec)

        want-srv := q-srv != null and not srv-suppressed
        want-txt := q-txt != null and not txt-suppressed
        if want-srv or want-txt:
          srv-ok := not want-srv or (q-srv.unicast-ok and (was-multicast-within-quarter-ttl_ srv-rec 120 now))
          txt-ok := not want-txt or (q-txt.unicast-ok and (was-multicast-within-quarter-ttl_ txt-rec 4500 now))
          use-unicast := legacy-query or (not is-probe-query and source != null and srv-ok and txt-ok)
          ans-target := use-unicast ? unicast-answers : multicast-answers
          add-target := use-unicast ? unicast-additionals : multicast-additionals
          if want-srv: add-unique-record_ ans-target srv-rec
          if want-txt: add-unique-record_ ans-target txt-rec
          // RFC 6763 §12.2: Include target host address in the Additional Record Section.
          add-unique-record_ add-target (legacy-query ? host-a-10_ : host-a-120_)

      q-srv-neg := find-negative-question_ query s.full-name [dns.RECORD-SRV, dns.RECORD-TXT]
      if q-srv-neg:
        nsec-ttl := legacy-query ? 10 : 120
        nsec := dns.NsecResource s.full-name nsec-ttl additional-flush s.full-name [dns.RECORD-TXT, dns.RECORD-SRV]
        if not dns.has-known-answer query s.full-name dns.RECORD-NSEC 120 --record=nsec:
          use-unicast := legacy-query or
              (not is-probe-query and source != null and q-srv-neg.unicast-ok and
                  (was-multicast-within-quarter-ttl_ nsec 120 now))
          add-unique-record_ (use-unicast ? unicast-answers : multicast-answers) nsec

    if not unicast-answers.is-empty and source:
      filtered-uni-add := unicast-additionals.filter: | r/dns.Resource |
        not (unicast-answers.any (: dns.resource-equals it r))
      id := query ? query.id : 0
      questions := legacy-query and query ? query.questions : []
      send-raw_
          --queries=questions
          --records=unicast-answers
          --additionals=filtered-uni-add
          --id=id
          --is-response
          --is-authoritative
          --target=source

    if not multicast-answers.is-empty:
      filtered-mcast-add := multicast-additionals.filter: | r/dns.Resource |
        not (multicast-answers.any (: dns.resource-equals it r))
      // RFC 6762 §6: Probe defenses are permitted at 250ms intervals;
      // normal multicast responses are limited to 1s intervals.
      min-interval := is-probe-query ? PROBE-DEFENSE-RATE-LIMIT-US_ : MULTICAST-RATE-LIMIT-WINDOW-US_
      enqueue-or-send-multicast_ multicast-answers now
          --additionals=filtered-mcast-add
          --min-interval-us=min-interval

  add-unique-record_ list/List record/dns.Resource -> none:
    if list.any (: dns.resource-equals it record): return
    list.add record

  enqueue-or-send-multicast_ records/List now/int --additionals/List=[] --min-interval-us/int -> none:
    ready := []
    records.do: | rec/dns.Resource |
      key := record-rate-key_ rec
      last := last-multicast-times_.get key
      if not last or (now - last) >= min-interval-us:
        ready.add rec
        last-multicast-times_[key] = now
      else:
        due-us := last + min-interval-us
        existing/DeferredRecord_? := deferred-multicast_.get key
        if existing:
          effective-due := min existing.due-us due-us
          deferred-multicast_[key] = DeferredRecord_ rec key effective-due
        else if deferred-multicast_.size < MAX-DEFERRED-RECORDS_:
          deferred-multicast_[key] = DeferredRecord_ rec key due-us

    ready-additionals := []
    if not ready.is-empty:
      // Supplemental additional records are included opportunistically when
      // permitted by the rate limit, and are never deferred into standalone packets.
      additionals.do: | rec/dns.Resource |
        key := record-rate-key_ rec
        last := last-multicast-times_.get key
        if not last or (now - last) >= min-interval-us:
          ready-additionals.add rec
          last-multicast-times_[key] = now

    prune-last-multicast-times_ now

    if not ready.is-empty:
      send-raw_
          --queries=[]
          --records=ready
          --additionals=ready-additionals
          --is-response
          --is-authoritative

    if not deferred-multicast_.is-empty:
      schedule-deferred-multicast_

  schedule-deferred-multicast_ -> none:
    earliest-due := int.MAX
    deferred-multicast_.do: | _ item/DeferredRecord_ |
      if item.due-us < earliest-due: earliest-due = item.due-us
    if earliest-due == int.MAX: return

    // If a task is already scheduled to wake at or before earliest-due, let it run.
    if deferred-send-task_ and deferred-wakeup-us_ <= earliest-due: return
    if deferred-send-task_:
      deferred-send-task_.cancel
      deferred-send-task_ = null

    deferred-wakeup-us_ = earliest-due
    deferred-send-task_ = task::
      try:
        while not stopped_ and not deferred-multicast_.is-empty:
          next-due := int.MAX
          deferred-multicast_.do: | _ item/DeferredRecord_ |
            if item.due-us < next-due: next-due = item.due-us
          deferred-wakeup-us_ = next-due

          wait-us := next-due - Time.monotonic-us
          if wait-us > 0:
            sleep (Duration --us=wait-us)
          if stopped_ or (state_ != STATE-ANNOUNCING and state_ != STATE-ESTABLISHED):
            break

          send-now := Time.monotonic-us
          due-records := []
          sent-keys := []
          // Coalesce any record due within 5ms into a single UDP packet.
          deferred-multicast_.do: | key item/DeferredRecord_ |
            if item.due-us <= send-now + 5_000:
              due-records.add item.record
              last-multicast-times_[key] = send-now
              sent-keys.add key
          sent-keys.do: deferred-multicast_.remove it

          if not due-records.is-empty and not socket_.is-closed:
            send-raw_ --queries=[] --records=due-records --is-response --is-authoritative
      finally:
        if deferred-send-task_ == Task.current:
          deferred-send-task_ = null
          deferred-wakeup-us_ = 0

  cancel-deferred-multicast_ -> none:
    deferred-multicast_.clear
    if deferred-send-task_:
      deferred-send-task_.cancel
      deferred-send-task_ = null
      deferred-wakeup-us_ = 0

  send-raw_ -> none
      --queries/List
      --records/List
      --id/int=0
      --is-response/bool
      --is-authoritative/bool=false
      --authorities/List=[]
      --additionals/List=[]
      --target/net.SocketAddress?=null:
    if socket_.is-closed: return
    packets/List? := null
    encode-err := catch:
      packets = dns.encode-mdns-packets queries records
          --id=id
          --is-response=is-response
          --is-authoritative=is-authoritative
          --authorities=authorities
          --additionals=additionals
          --max-size=socket_.max-payload-size
    if encode-err or not packets:
      record-names := records.map: | r/dns.Resource | r.name
      log.error "mDNS encode failed" --tags={"error": encode-err, "records": record-names}
      return
    packets.do: | packet/ByteArray |
      send-err := catch:
        if target:
          socket_.send packet target
        else:
          socket_.send packet
      if send-err:
        log.debug "mDNS send skipped" --tags={"error": send-err}

  prune-last-multicast-times_ now/int -> none:
    if last-multicast-times_.size <= 32: return
    last-multicast-times_.filter --in-place: | _ timestamp/int |
      (now - timestamp) < MAX-QU-MULTICAST-WINDOW-US_

  find-question_ query/dns.DecodedPacket? name/string type/int -> dns.Question?:
    if not query: return null
    query.questions.do: | q/dns.Question |
      if (dns.name-equals q.name name) and (q.type == type or q.type == dns.RECORD-ANY):
        return q
    return null

  find-negative-question_ query/dns.DecodedPacket? name/string owned-types/List -> dns.Question?:
    if not query: return null
    query.questions.do: | q/dns.Question |
      if (dns.name-equals q.name name) and q.type != dns.RECORD-ANY and not (owned-types.contains q.type):
        return q
    return null

  /** Returns the current (possibly conflict-renamed) hostname. */
  hostname -> string:
    return hostname_

  /**
  Encodes a DNS-SD TXT map into RFC 6763 §6.4 `<character-string>` entries:
  - Empty / null map -> `[""]` (single empty string per RFC 6763 §6.1).
  - `v == false` -> key omitted.
  - `v == null` or `v == true` -> `"key"` (boolean / no-value attribute without `=`).
  - `v is ByteArray` -> binary `key=<raw bytes>` `ByteArray` clamped to 255 octets.
  - Other values -> `"key=value"` clamped to 255 octets.
  */
  build-txt-list_ txt/Map? -> List:
    if not txt or txt.is-empty: return [""]
    list := []
    txt.do: | k v |
      key-str := "$k"
      if key-str.is-empty or key-str.size > 255: continue.do
      if v == false: continue.do
      if v == null or v == true:
        list.add key-str
      else if v is ByteArray:
        prefix := "$key-str=".to-byte-array
        raw := v as ByteArray
        if prefix.size + raw.size > 255:
          throw "INVALID_TXT: entry for '$key-str' exceeds 255 octets"
        list.add (prefix + raw)
      else:
        entry := "$key-str=$v"
        if entry.size > 255:
          throw "INVALID_TXT: entry for '$key-str' exceeds 255 octets"
        list.add entry
    return list.is-empty ? [""] : list

class RegisteredService:
  type/string
  original-instance-name/string
  instance-name/string
  port/int
  txt/Map?
  full-name/string
  type-domain/string
  full-name-lower/string
  type-domain-lower/string

  constructor .type .original-instance-name .instance-name .port .txt:
    full-name = "$(instance-name).$(type).local"
    type-domain = "$(type).local"
    full-name-lower = full-name.to-ascii-lower
    type-domain-lower = type-domain.to-ascii-lower
