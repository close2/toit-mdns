/**
mDNS system service implementation.

Provides $MdnsServiceProvider, a persistent system service that coordinates
multicast socket I/O, caching, query resolution, and per-hostname state
machines across one or more client containers.
*/

import log
import net
import net.modules.dns
import system.services

import .api.mdns-service
import .net.dns-helper as dns
import .net.mdns-socket
import .server.cache
import .server.conflict-manager
import .server.query-engine
import .server.state-manager

/**
mDNS system service provider.

Multiple client applications can share this single service instance,
benefiting from shared caching and reference-counted hostname / service
announcements. Automatically recovers the multicast socket if the
underlying network interface resets while active clients are attached.
*/
class MdnsServiceProvider extends services.ServiceProvider
    implements services.ServiceHandler:
  managers_/Map := {:}            // lowercased hostname -> StateManager
  manager-refs_/Map := {:}        // lowercased hostname -> int
  client-commitments_/Map := {:}  // client-id -> lowercased hostname

  socket_/MdnsSocket? := null
  cache_/MdnsCache? := null
  query-engine_/QueryEngine? := null
  receive-task_/Task? := null

  group/net.IpAddress
  port/int
  local-ip/net.IpAddress?
  resolved-local-ip_/net.IpAddress? := null

  local-client-counter_/int := -1
  closed_/bool := false

  constructor
      --.port/int=MDNS-PORT
      --.group/net.IpAddress=MDNS-MULTICAST-ADDRESS
      --.local-ip/net.IpAddress?=null:
    super "mdns" --major=1 --minor=0
    provides MdnsService.SELECTOR --handler=this

  on-opened client/int -> none:
    ensure-socket_

  on-closed client/int -> none:
    cleanup-client_ client

  handle index/int arguments/any -> any
      --gid/int
      --client/int:
    if index == MdnsService.LOOKUP-INDEX:
      args := arguments as List
      return lookup args[0] --accept-ipv4=args[1] --accept-ipv6=args[2] --timeout-us=args[3]
    if index == MdnsService.LOOKUP-DETAILED-INDEX:
      args := arguments as List
      return lookup args[0] --record-types=args[1] --timeout-us=args[2]
    if index == MdnsService.REGISTER-INDEX:
      args := arguments as List
      type := args[0] as string
      port_ := args[1] as int
      txt := args[2]
      instance-name := args[3]
      target := args.size > 4 ? args[4] : null
      if not target: target = client-commitments_.get client
      return register type port_ --txt=txt --name=instance-name --hostname=target
    if index == MdnsService.SET-HOSTNAME-INDEX:
      return client-set-hostname_ client (arguments as string)
    if index == MdnsService.GET-HOSTNAME-INDEX:
      return client-get-hostname_ client
    unreachable

  register type/string port/int -> none
      --txt/Map?=null
      --name/string?=null
      --hostname/string?=null:
    ensure-socket_
    if not hostname: throw "No hostname specified for registration"
    key := hostname.to-ascii-lower
    manager/StateManager? := managers_.get key
    if not manager:
      throw "Hostname '$hostname' not active (call set-hostname first)"
    manager.register-service type port --txt=txt --name=name

  client-set-hostname_ client/int name/string -> none:
    if not dns.has-local-suffix name:
      throw "Invalid hostname: $name"
    ensure-socket_
    key := name.to-ascii-lower

    old-key := client-commitments_.get client
    if old-key == key: return
    if old-key:
      decrement-ref_ old-key

    client-commitments_[client] = key
    increment-ref_ key name

  client-get-hostname_ client/int -> string:
    committed-key := client-commitments_.get client
    if not committed-key: throw "Client has not set a hostname"
    manager/StateManager? := managers_.get committed-key
    if not manager: throw "Manager not found for $committed-key"
    return manager.hostname

  /**
  Increments the reference count for the lowercased $key, creating a
    manager for $name if needed.

  The manager is created with $name (not $key) so that the advertised
    hostname and derived default service-instance names preserve the
    caller's case (RFC 6762 §16).
  */
  increment-ref_ key/string name/string -> none:
    refs := manager-refs_.get key --init=(: 0)
    manager-refs_[key] = refs + 1

    if not managers_.contains key:
      cm := ConflictManager
      manager := StateManager socket_ cm name resolved-local-ip_ --expected-port=port
      managers_[key] = manager
      manager.start

  decrement-ref_ key/string -> none:
    curr := manager-refs_.get key
    if not curr:
      log.warn "mDNS decrement-ref_ with no current count" --tags={"name": key}
      return

    new-count := curr - 1
    if new-count <= 0:
      manager/StateManager? := managers_.get key
      if manager:
        manager.stop
        managers_.remove key
      manager-refs_.remove key
    else:
      manager-refs_[key] = new-count

  cleanup-client_ client/int -> none:
    key := client-commitments_.get client
    if key:
      client-commitments_.remove client
      decrement-ref_ key

  ensure-socket_ -> none:
    if socket_ and not socket_.is-closed: return
    open-socket-and-bind_

    // If the receive loop is still alive (e.g. backing off after a socket
    // error), it picks up the new $socket_ itself; don't start a second one.
    if receive-task_: return
    receive-task_ = task::
      try:
        receive-loop_
      finally:
        if receive-task_ == Task.current: receive-task_ = null

  open-socket-and-bind_ -> none:
    network := net.open
    new-socket/MdnsSocket? := null
    try:
      new-socket = MdnsSocket --network=network --group=group --port=port
      socket_ = new-socket
      resolved-local-ip_ = local-ip or network.address

      if not cache_: cache_ = MdnsCache
      if query-engine_:
        query-engine_.update-socket socket_
      else:
        query-engine_ = QueryEngine socket_ cache_

      managers_.do: | _ manager/StateManager |
        manager.update-network socket_ resolved-local-ip_

      new-socket = null
    finally:
      if new-socket:
        new-socket.close
        socket_ = null
        network.close

  receive-loop_ -> none:
    while not closed_:
      exception := catch:
        datagram := socket_.receive
        if closed_: return
        if not datagram: continue

        packet-bytes := datagram.data
        // Zero-allocation header & port check before constructing DecodedPacket:
        // - RFC 6762 §18.3 / §18.11: Ignore non-zero OPCODE or RCODE.
        // - RFC 6762 §6.10: Ignore responses not originating from port 5353.
        if not dns.is-valid-raw-mdns-header packet-bytes: continue
        is-response := (packet-bytes[2] & 0x80) != 0
        if is-response and datagram.address.port != port: continue

        decoded/dns.DecodedPacket? := null
        parse-exception := catch:
          decoded = dns.parse packet-bytes
        if parse-exception or not decoded:
          log.debug "mDNS ignoring malformed packet" --tags={"error": parse-exception}
          continue

        if not dns.is-valid-mdns-message decoded: continue

        // Snapshot manager values in case conflict/client handlers mutate managers_.
        active-managers := managers_.values
        active-managers.do: | manager/StateManager |
          manager-exception := catch:
            manager.process-packet decoded --source=datagram.address
          if manager-exception:
            log.warn "mDNS manager processing error"
                --tags={"error": manager-exception, "hostname": manager.hostname}

        // RFC 6762 §7.3 & §6.10: Only cache/resolve from validated port-5353 responses.
        if decoded.is-response and datagram.address.port == port:
          query-exception := catch:
            query-engine_.process-packet decoded
          if query-exception:
            log.warn "mDNS query-engine processing error"
                --tags={"error": query-exception}

      if exception:
        if closed_: return
        log.warn "mDNS receive error; resetting socket" --tags={"error": exception}
        broken := socket_
        socket_ = null
        resolved-local-ip_ = null
        if broken: catch: broken.close

        // If no managers or active queries remain, exit cleanly and let the
        // next client request re-initialize lazily via ensure-socket_.
        // Re-check $socket_: a concurrent $ensure-socket_ may already have
        // reopened it while we were logging/closing, relying on this loop.
        if not socket_ and managers_.is-empty and
            (not query-engine_ or not query-engine_.has-pending):
          return

        backoff-ms := 1000
        while not closed_ and not socket_:
          sleep (Duration --ms=backoff-ms)
          if closed_: return
          reopen-err := catch:
            open-socket-and-bind_
          if reopen-err:
            log.warn "mDNS socket reopen retry failed" --tags={"error": reopen-err}
            backoff-ms = min (backoff-ms * 2) 10_000

  close -> none:
    if closed_: return
    closed_ = true
    managers_.do: | _ manager/StateManager |
      manager.stop
    if receive-task_:
      receive-task_.cancel
      receive-task_ = null
    if socket_:
      socket_.close
      socket_ = null

  lookup name/string -> List
      --accept-ipv4/bool
      --accept-ipv6/bool
      --timeout-us/int:
    ensure-socket_
    mask := 0
    if accept-ipv4: mask |= dns.RECORD-A
    if accept-ipv6: mask |= dns.RECORD-AAAA
    results := query-engine_.lookup name --record-types=mask --timeout-us=timeout-us
    // Standard IP lookup RPC (LOOKUP-INDEX) is consumed both by Client.dns-lookup
    // (which accepts raw IP ByteArrays or [type, ip-bytes] pairs) and direct callers
    // like tests/client_test.toit (which expects [type, ip-bytes] pairs).
    return results

  lookup name/string -> List
      --record-types/int
      --timeout-us/int:
    ensure-socket_
    return query-engine_.lookup name --record-types=record-types --timeout-us=timeout-us

  /**
  Returns the hostname of the first active manager (primarily for diagnostics).
  */
  hostname -> string:
    if managers_.is-empty: return "no-active-check"
    return managers_.values.first.hostname

  connect-locally -> MdnsService:
    id := local-client-counter_--
    on-opened id
    return DirectMdnsService_ this id


class DirectMdnsService_ implements MdnsService:
  provider_/MdnsServiceProvider
  client-id_/int
  closed_/bool := false

  constructor .provider_ .client-id_:

  lookup name/string -> List
      --accept-ipv4/bool
      --accept-ipv6/bool
      --timeout-us/int:
    return provider_.lookup name
        --accept-ipv4=accept-ipv4
        --accept-ipv6=accept-ipv6
        --timeout-us=timeout-us

  lookup name/string -> List
      --record-types/int
      --timeout-us/int:
    return provider_.lookup name
        --record-types=record-types
        --timeout-us=timeout-us

  register type/string port/int -> none
      --txt/Map?=null
      --name/string?=null
      --hostname/string?=null:
    target := hostname
    if not target: target = provider_.client-commitments_.get client-id_
    provider_.register type port --txt=txt --name=name --hostname=target

  get-hostname -> string:
    return provider_.client-get-hostname_ client-id_

  set-hostname hostname/string -> none:
    provider_.client-set-hostname_ client-id_ hostname

  close -> none:
    if closed_: return
    closed_ = true
    provider_.on-closed client-id_
