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
import .net.ip-scope as ip-scope
import .net.mdns-socket
import .net.names as names
import .server.cache
import .server.conflict-manager
import .server.query-engine
import .server.state-manager

class RegisteredEntry_:
  service-key/string
  type/string
  instance-name/string
  is-default/bool

  constructor .service-key .type .instance-name .is-default:

/**
mDNS system service provider.

Multiple client applications can share this single service instance,
benefiting from shared caching and reference-counted hostname / service
announcements. Automatically recovers the multicast socket if the
underlying network interface resets while active clients are attached.
*/
class MdnsServiceProvider extends services.ServiceProvider
    implements services.ServiceHandler:
  static MAX-SERVICES-PER-CLIENT_ ::= 8
  static MAX-SERVICES-PER-HOSTNAME_ ::= 16
  static MAX-PENDING-PER-CLIENT_ ::= 4
  static MAX-LOOKUP-TIMEOUT-US_ ::= 60_000_000

  managers_/Map := {:}                // lowercased hostname -> StateManager
  manager-refs_/Map := {:}            // lowercased hostname -> int
  client-commitments_/Map := {:}      // client-id -> lowercased hostname
  client-services_/Map := {:}         // client-id -> Map<service-key, RegisteredEntry_>
  service-owners_/Map := {:}          // service-key -> client-id
  client-pending-lookups_/Map := {:}  // client-id -> int

  socket_/MdnsSocket? := null
  cache_/MdnsCache? := null
  query-engine_/QueryEngine? := null
  receive-task_/Task? := null
  ip-refresh-task_/Task? := null

  group/net.IpAddress
  port/int
  local-ip/net.IpAddress?
  cache-max-bytes/int
  local-prefix-length/int?
  resolved-local-ip_/net.IpAddress? := null

  local-client-counter_/int := -1
  closed_/bool := false

  constructor
      --.port/int=MDNS-PORT
      --.group/net.IpAddress=MDNS-MULTICAST-ADDRESS
      --.local-ip/net.IpAddress?=null
      --.cache-max-bytes/int=MdnsCache.DEFAULT-MAX-BYTES
      --.local-prefix-length/int?=null:
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
      if arguments is not List: throw "INVALID_ARGUMENT"
      args := arguments as List
      if args.size != 4 or args[0] is not string or args[1] is not bool or
          args[2] is not bool or args[3] is not int:
        throw "INVALID_ARGUMENT"
      timeout := min (max 0 (args[3] as int)) MAX-LOOKUP-TIMEOUT-US_
      return with-client-lookup_ client:
        lookup (args[0] as string)
            --accept-ipv4=(args[1] as bool)
            --accept-ipv6=(args[2] as bool)
            --timeout-us=timeout
    if index == MdnsService.LOOKUP-DETAILED-INDEX:
      if arguments is not List: throw "INVALID_ARGUMENT"
      args := arguments as List
      if args.size != 3 or args[0] is not string or args[1] is not int or args[2] is not int:
        throw "INVALID_ARGUMENT"
      timeout := min (max 0 (args[2] as int)) MAX-LOOKUP-TIMEOUT-US_
      return with-client-lookup_ client:
        lookup (args[0] as string)
            --record-types=(args[1] as int)
            --timeout-us=timeout
    if index == MdnsService.REGISTER-INDEX:
      if arguments is not List: throw "INVALID_ARGUMENT"
      args := arguments as List
      if args.size < 4 or args.size > 5: throw "INVALID_ARGUMENT"
      if args[0] is not string or args[1] is not int: throw "INVALID_ARGUMENT"
      if args[2] != null and args[2] is not Map: throw "INVALID_ARGUMENT"
      if args[3] != null and args[3] is not string: throw "INVALID_ARGUMENT"
      if args.size == 5 and args[4] != null and args[4] is not string:
        throw "INVALID_ARGUMENT"
      target := (args.size == 5 and args[4] != null) ? (args[4] as string) : null
      txt := args[2] != null ? (args[2] as Map) : null
      instance-name := args[3] != null ? (args[3] as string) : null
      return client-register_ client (args[0] as string) (args[1] as int)
          --txt=txt
          --name=instance-name
          --target-hostname=target
    if index == MdnsService.UNREGISTER-INDEX:
      if arguments is not List: throw "INVALID_ARGUMENT"
      args := arguments as List
      if args.size != 2 or args[0] is not string or (args[1] != null and args[1] is not string):
        throw "INVALID_ARGUMENT"
      instance-name := args[1] != null ? (args[1] as string) : null
      return client-unregister_ client (args[0] as string) --name=instance-name
    if index == MdnsService.SET-HOSTNAME-INDEX:
      if arguments is not string: throw "INVALID_ARGUMENT"
      return client-set-hostname_ client (arguments as string)
    if index == MdnsService.GET-HOSTNAME-INDEX:
      return client-get-hostname_ client
    unreachable

  with-client-lookup_ client/int [block] -> any:
    count := client-pending-lookups_.get client --init=(: 0)
    if count >= MAX-PENDING-PER-CLIENT_:
      throw "QUOTA_EXCEEDED: too many concurrent lookups"
    client-pending-lookups_[client] = count + 1
    try:
      return block.call
    finally:
      cur := client-pending-lookups_.get client
      if cur:
        if cur <= 1: client-pending-lookups_.remove client
        else: client-pending-lookups_[client] = cur - 1

  client-register_ client/int type/string svc-port/int -> none
      --txt/Map?=null
      --name/string?=null
      --target-hostname/string?=null:
    if svc-port < 0 or svc-port > 65535:
      throw "INVALID_ARGUMENT: port out of range"
    names.validate-service-type type
    if name: names.validate-instance-name name
    names.validate-txt txt
    ensure-socket_

    committed-key := client-commitments_.get client
    if not committed-key:
      throw "PERMISSION_DENIED: client has not set a hostname"
    if target-hostname != null and target-hostname.to-ascii-lower != committed-key:
      throw "PERMISSION_DENIED: cannot register service on another hostname"

    manager/StateManager? := managers_.get committed-key
    if not manager:
      throw "Hostname '$committed-key' not active (call set-hostname first)"

    is-default := name == null
    effective-name := name or (manager.hostname[..manager.hostname.size - 6])
    service-key := "$(committed-key)|$(type.to-ascii-lower)|$(effective-name.to-ascii-lower)"

    existing-owner := service-owners_.get service-key
    if existing-owner != null and existing-owner != client:
      throw "PERMISSION_DENIED: service is owned by another client"

    owned := client-services_.get client
    if existing-owner == null:
      if owned and owned.size >= MAX-SERVICES-PER-CLIENT_:
        throw "QUOTA_EXCEEDED: too many services for client"
      if manager.services-count >= MAX-SERVICES-PER-HOSTNAME_:
        throw "QUOTA_EXCEEDED: too many services for hostname"

    manager.register-service type svc-port --txt=txt --name=effective-name
    entry := RegisteredEntry_ service-key type effective-name is-default
    if not owned:
      owned = {:}
      client-services_[client] = owned
    owned[service-key] = entry
    service-owners_[service-key] = client

  client-unregister_ client/int type/string --name/string?=null -> bool:
    names.validate-service-type type
    if name: names.validate-instance-name name
    owned/Map? := client-services_.get client
    if not owned or owned.is-empty: return false
    committed-key := client-commitments_.get client
    if not committed-key: return false
    manager/StateManager? := managers_.get committed-key
    if not manager: return false

    entry/RegisteredEntry_? := null
    if name:
      key := "$(committed-key)|$(type.to-ascii-lower)|$(name.to-ascii-lower)"
      entry = owned.get key
    else:
      current-default := manager.hostname[..manager.hostname.size - 6]
      key := "$(committed-key)|$(type.to-ascii-lower)|$(current-default.to-ascii-lower)"
      entry = owned.get key
      if not entry:
        type-lower := type.to-ascii-lower
        owned.do: | _ candidate/RegisteredEntry_ |
          if candidate.is-default and candidate.type.to-ascii-lower == type-lower:
            entry = candidate
    if not entry: return false
    if (service-owners_.get entry.service-key) != client: return false

    owned.remove entry.service-key
    if owned.is-empty: client-services_.remove client
    service-owners_.remove entry.service-key
    return manager.unregister-service entry.type --name=entry.instance-name

  unregister-client-services_ client/int -> none:
    owned/Map? := client-services_.get client
    if not owned: return
    client-services_.remove client
    committed-key := client-commitments_.get client
    manager/StateManager? := committed-key ? (managers_.get committed-key) : null
    owned.do: | _ entry/RegisteredEntry_ |
      if (service-owners_.get entry.service-key) == client:
        service-owners_.remove entry.service-key
      if manager:
        manager.unregister-service entry.type --name=entry.instance-name

  client-set-hostname_ client/int name/string -> none:
    names.validate-hostname name
    ensure-socket_
    key := name.to-ascii-lower

    old-key := client-commitments_.get client
    if old-key == key: return
    if old-key:
      unregister-client-services_ client
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
      manager/StateManager? := null
      on-rename := :: | old-name/string new-name/string |
        handle-manager-rename_ manager cm old-name new-name
      manager = StateManager socket_ cm name resolved-local-ip_
          --expected-port=port
          --local-prefix-length=local-prefix-length
          --on-rename=on-rename
      managers_[key] = manager
      manager.start

  handle-manager-rename_
      manager/StateManager
      cm/ConflictManager
      old-name/string
      new-name/string -> string:
    old-key := old-name.to-ascii-lower
    candidate := new-name
    new-key := candidate.to-ascii-lower
    while new-key != old-key and (managers_.contains new-key):
      candidate = cm.resolve-probing-conflict candidate
      new-key = candidate.to-ascii-lower
    if new-key != old-key:
      if (managers_.get old-key) == manager:
        managers_.remove old-key
        managers_[new-key] = manager
      refs := manager-refs_.get old-key
      if refs != null:
        manager-refs_.remove old-key
        manager-refs_[new-key] = refs
      client-commitments_.do: | cid committed |
        if committed == old-key:
          client-commitments_[cid] = new-key
      old-prefix := "$old-key|"
      new-prefix := "$new-key|"
      client-services_.do: | cid owned/Map |
        if (client-commitments_.get cid) == new-key:
          rekeyed := {:}
          owned.do: | old-skey entry/RegisteredEntry_ |
            new-skey := (old-skey.starts-with old-prefix)
                ? "$new-prefix$(old-skey[old-prefix.size..])"
                : old-skey
            if new-skey != old-skey:
              service-owners_.remove old-skey
              service-owners_[new-skey] = cid
            rekeyed[new-skey] = RegisteredEntry_ new-skey entry.type entry.instance-name entry.is-default
          client-services_[cid] = rekeyed
    return candidate

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
    client-pending-lookups_.remove client
    unregister-client-services_ client
    key := client-commitments_.get client
    if key:
      client-commitments_.remove client
      decrement-ref_ key

  ensure-socket_ -> none:
    if socket_ and not socket_.is-closed: return
    open-socket-and-bind_

    // If the receive loop is still alive (e.g. backing off after a socket
    // error), it picks up the new $socket_ itself; don't start a second one.
    if not receive-task_:
      receive-task_ = task::
        try:
          receive-loop_
        finally:
          if receive-task_ == Task.current: receive-task_ = null

    if local-ip == null and not ip-refresh-task_:
      ip-refresh-task_ = task::
        try:
          ip-refresh-loop_
        finally:
          if ip-refresh-task_ == Task.current: ip-refresh-task_ = null

  ip-refresh-loop_ -> none:
    while not closed_:
      sleep (Duration --s=30)
      if closed_: return
      refresh-local-ip_

  refresh-local-ip_ -> none:
    if local-ip != null or not socket_ or socket_.is-closed or managers_.is-empty:
      return
    new-ip/net.IpAddress? := null
    catch: new-ip = socket_.network-address
    if new-ip and new-ip != resolved-local-ip_:
      log.info "Local IP changed; updating mDNS responders"
          --tags={"old": resolved-local-ip_, "new": new-ip}
      resolved-local-ip_ = new-ip
      managers_.do: | _ manager/StateManager |
        manager.update-network socket_ new-ip

  open-socket-and-bind_ -> none:
    network := net.open
    new-socket/MdnsSocket? := null
    try:
      new-socket = MdnsSocket --network=network --group=group --port=port
      socket_ = new-socket
      resolved-local-ip_ = local-ip or network.address

      if not cache_: cache_ = MdnsCache --max-bytes=cache-max-bytes
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

        if not ip-scope.is-local-source datagram.address.ip resolved-local-ip_
            --prefix-length=local-prefix-length:
          continue
        packet-bytes := datagram.data
        // Zero-allocation header & port check before constructing DecodedPacket:
        // - RFC 6762 §18.3 / §18.11: Ignore non-zero OPCODE or RCODE.
        // - RFC 6762 §6.10: Ignore responses not originating from port 5353.
        if not dns.is-valid-raw-mdns-header packet-bytes: continue
        is-response := (packet-bytes[2] & 0x80) != 0
        if is-response:
          if datagram.address.port != port: continue
          if managers_.is-empty and (not query-engine_ or not query-engine_.has-pending):
            continue
        else:
          if managers_.is-empty: continue

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
    if query-engine_:
      query-engine_.close
    if ip-refresh-task_:
      ip-refresh-task_.cancel
      ip-refresh-task_ = null
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
    if not dns.is-mdns-lookup-name name:
      throw "INVALID_ARGUMENT: not a .local name: $name"
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
    if not dns.is-mdns-lookup-name name:
      throw "INVALID_ARGUMENT: not a .local name: $name"
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
      --name/string?=null:
    provider_.client-register_ client-id_ type port --txt=txt --name=name

  unregister type/string --name/string?=null -> bool:
    return provider_.client-unregister_ client-id_ type --name=name

  get-hostname -> string:
    return provider_.client-get-hostname_ client-id_

  set-hostname hostname/string -> none:
    provider_.client-set-hostname_ client-id_ hostname

  close -> none:
    if closed_: return
    closed_ = true
    provider_.on-closed client-id_
