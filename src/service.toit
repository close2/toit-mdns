/**
mDNS system service implementation.

This module provides the $MdnsServiceProvider, a system service that runs
persistently to handle all mDNS operations for the device.

# RFC 6762 Compliance

The service implements key aspects of RFC 6762 (Multicast DNS):
- **Probing**: Before claiming a hostname, we probe to detect conflicts
- **Announcing**: After successful probing, we announce our presence
- **Conflict Resolution**: If another device uses our name, we rename
- **Caching**: Responses are cached to reduce network traffic

# Component Architecture

The service is composed of specialized managers:
- $StateManager: Handles probing/announcing state machine and conflict defense
- $QueryEngine: Processes queries and manages the response cache
- $ConflictManager: Generates new names when conflicts occur
- $MdnsSocket: Wraps UDP multicast socket operations

# Lazy Initialization

The socket and managers are created on-demand when the first client connects.
This conserves resources when mDNS is not actively being used.
*/

import net
import net.modules.dns
import system as system
import system.services

import log

import .api.mdns_service
import .net.dns_helper as dns
import .net.mdns_socket
import .server.conflict_manager
import .server.cache
import .server.query_engine
import .server.state_manager

/**
mDNS system service provider.

This service runs persistently and handles all mDNS operations for the device.
Multiple client applications can share this single service instance,
benefiting from shared caching and coordinated announcements.

Implements the mDNS service logic and handles RPC calls from MdnsServiceClient.
Uses reference counting to manage hostnames based on client commitments.
*/
class MdnsServiceProvider extends services.ServiceProvider
    implements services.ServiceHandler:
  
  managers_/Map := {:} // Map<string, StateManager>
  manager-refs_/Map := {:} // Map<string, int>
  client-commitments_/Map := {:} // Map<int, string>

  socket_/MdnsSocket? := null
  cache_/MdnsCache? := null
  query-engine_/QueryEngine? := null

  group/net.IpAddress
  port/int
  local-ip/net.IpAddress?
  resolved-local-ip_/net.IpAddress? := null

  local-client-counter_ := -1


  constructor
      --.port/int=MDNS-PORT
      --.group/net.IpAddress=MDNS-MULTICAST-ADDRESS
      --.local-ip/net.IpAddress?=null:
    super "mdns" --major=1 --minor=0
    provides MdnsService.SELECTOR --handler=this

  on-opened client/int:
    // We wait for the client to set a hostname.
    ensure-socket_
  
  on-closed client/int:
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
      // Use client context if explicit hostname not provided (though arguments might still allow it for overrides?)
      // For now, let's assume REGISTER uses the client's committed hostname.
      // The RPC interface signature we have currently is: [type, port, txt, name, hostname]
      // We should probably check if hostname is passed (it was optional in previous step).
      // But the Plan says: "Uses client_commitments_[id] to find target manager."
      
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
    
    manager/StateManager? := managers_.get hostname
    if not manager:
      // This implies the client must have "set-hostname" first to create the manager.
      throw "Hostname '$hostname' not active (call set-hostname first)"
      
    manager.register-service type port --txt=txt --name=name

  client-set-hostname_ client/int name/string -> none:
    ensure-socket_
    
    // 1. Decrement old
    old-name := client-commitments_.get client
    if old-name:
      decrement-ref_ old-name

    // 2. Update commitment
    client-commitments_[client] = name
    
    // 3. Increment new
    increment-ref_ name

  client-get-hostname_ client/int -> string:
    committed-name := client-commitments_.get client
    if not committed-name: throw "Client has not set a hostname"
    manager := managers_.get committed-name
    if not manager: throw "Manager not found for $committed-name"
    return manager.hostname

  increment-ref_ name/string:
    refs := manager-refs_.get name --init=(: 0)
    manager-refs_[name] = refs + 1
    
    if not managers_.contains name:
      cm := ConflictManager
      manager := StateManager socket_ cm name resolved-local-ip_ --expected-port=port
      managers_[name] = manager
      manager.start

  decrement-ref_ name/string:
    curr := manager-refs_.get name
    if not curr: return // Should not happen
    
    new-count := curr - 1
    manager-refs_[name] = new-count
    
    if new-count <= 0:
      manager/StateManager? := managers_.get name
      if manager: 
        manager.stop
        managers_.remove name
      manager-refs_.remove name

  cleanup-client_ client/int:
    hostname := client-commitments_.get client
    if hostname:
      decrement-ref_ hostname
      client-commitments_.remove client

  ensure-socket_:
    if socket_: return
    network := net.open
    socket_ = MdnsSocket --network=network --group=group --port=port
    resolved-local-ip_ = local-ip or network.address

    cache_ = MdnsCache
    query-engine_ = QueryEngine socket_ cache_
    
    // Start receiving loop
    task::
      while not closed_:
        exception := catch:
          datagram := socket_.receive
          if closed_: break
          if not datagram: continue
          
          packet-bytes := datagram.data
          
          // Broadcast to all state managers.
          // Catch parse errors per-packet so a single malformed packet
          // (e.g. from non-mDNS multicast traffic) doesn't kill the loop.
          parse-exception := catch:
            managers_.do: | name manager/StateManager |
              manager.process-packet packet-bytes --source=datagram.address
            
            // Allow QueryEngine to process answers/updates.
            // RFC 6762 §7.3: "A Multicast DNS querier MUST NOT cache
            //  resource records observed in the Known-Answer Section of
            //  other Multicast DNS queries." — Only cache from responses.
            decoded := dns.parse packet-bytes
            if decoded.is-response:
              query-engine_.process-packet decoded
          if parse-exception:
            log.debug "mDNS ignoring malformed packet" --tags={"error": parse-exception}
            continue
        if exception:
          if not closed_: log.error "mDNS receive error" --tags={"error": exception}
          break
      socket_.close

  closed_/bool := false
  
  close:
    closed_ = true
    managers_.do: | name manager/StateManager |
      manager.stop
    if socket_: socket_.close

  lookup name/string -> List
      --accept-ipv4/bool
      --accept-ipv6/bool
      --timeout-us/int:
    ensure-socket_
    mask := 0
    if accept-ipv4: mask |= dns.RECORD-A
    if accept-ipv6: mask |= dns.RECORD-AAAA
    return query-engine_.lookup name --record-types=mask --timeout-us=timeout-us

  lookup name/string -> List
      --record-types/int
      --timeout-us/int:
    ensure-socket_
    return query-engine_.lookup name --record-types=record-types --timeout-us=timeout-us

  /**
  Returns the hostname of the first active manager.
  This is primarily for debugging purposes.
  To get the hostname for a specific client context, use $connect-locally or the RPC interface.
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

  close:
    provider_.on-closed client-id_
