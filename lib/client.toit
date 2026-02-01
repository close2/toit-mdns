/**
Multicast DNS (mDNS) client library.

This library provides a high-level interface for mDNS/DNS-SD operations:
- Name resolution (.local hostnames)
- Service discovery (browsing for services by type)
- Service registration (advertising your own services)

# Architecture

The mDNS functionality is split into a client (this library) and a system
service (MdnsServiceProvider). The client communicates with the service 
via RPC, which handles the actual multicast socket, caching, and RFC 6762
compliance.

This separation allows multiple applications to share a single mDNS socket
and cache, while the service handles conflict resolution and probing.

# Usage

```
client := Client
// Resolve a hostname
ip := client.dns-lookup "my-device.local"
// Browse for HTTP services
instances := client.browse "_http._tcp"
// Register your own service
client.register-service "_http._tcp" 8080 --txt={"path": "/api"}
```
*/

import net
import net.udp
import net.modules.dns
import system
import system.services show ServiceClient

import ..src.api.mdns_service
import ..src.service as service

/**
Primary user-facing mDNS client.

Provides convenient methods for DNS lookups, service browsing, and service
registration. All operations are delegated to the mDNS system service,
which maintains a shared cache and socket.
*/
class Client:
  static DEFAULT-HOSTNAME ::= "$(system.hostname).local"
  
  service_/MdnsService

  requested-hostname_/string? := null

  constructor
      --hostname/string=DEFAULT-HOSTNAME
      --service/MdnsService?=null:
    if service:
      service_ = service
    else:
      rpc-client := MdnsServiceClient
      rpc-client.open
      service_ = rpc-client

    set-hostname hostname

  /// Returns a DnsClient that delegates to this client.
  dns-client -> dns.DnsClient:
    return DnsClient this

  // Convenience method for DNS lookup (single IP).
  dns-lookup name/string -> net.IpAddress
      --network/udp.Interface?
      --accept-ipv4/bool=true
      --accept-ipv6/bool=false
      --timeout/Duration=dns.DNS-DEFAULT-TIMEOUT:
    
    // We delegate the lookup to the service.
    // The service handles caching and querying.
    results := service_.lookup name
        --accept-ipv4=accept-ipv4
        --accept-ipv6=accept-ipv6
        --timeout-us=timeout.in-us
    
    // Results is a list of byte arrays (IP addresses).
    if results.is-empty: throw "HOST_NOT_FOUND"
    
    // Pick first valid one (service should have filtered already, but double check).
    results.do: | ip-bytes |
      ip := net.IpAddress ip-bytes
      if (not ip.is-ipv6 and accept-ipv4) or (ip.is-ipv6 and accept-ipv6):
        return ip
        
    throw "HOST_NOT_FOUND"

  /// Detailed lookup used by DnsClient and browse.
  dns-lookup name/string -> List
      --record-types/Set
      --network/udp.Interface?
      --timeout/Duration=dns.DNS-DEFAULT-TIMEOUT:
    
    mask := 0
    record-types.do: mask |= it

    // Call detailed lookup
    results := service_.lookup name
        --record-types=mask
        --timeout-us=timeout.in-us
    
    // Parse results
    // Expected format: List of [type, data]
    parsed := []
    results.do: | entry |
      type := entry[0]
      data := entry[1]
      
      if type == dns.RECORD-A or type == dns.RECORD-AAAA:
        parsed.add (net.IpAddress data)
      else if type == dns.RECORD-TXT or type == dns.RECORD-PTR or type == dns.RECORD-CNAME:
        parsed.add data.to-string
      else if type == dns.RECORD-SRV:
        // SRV data expected to be [priority, weight, port, target].
        if data is List and data.size == 4:
         parsed.add (dns.SrvResource name type 0 false data[3] data[0] data[1] data[2])

    return parsed

  /**
  Browses for services of the given type.
  Returns a list of Service Instance Names (strings).
  Example type: "_http._tcp"
  */
  browse type/string -> List
      --network/udp.Interface?
      --timeout/Duration=dns.DNS-DEFAULT-TIMEOUT:
    
    // Browse means looking for PTR records for [type].local
    query-name := "$(type).local"
    return dns-lookup query-name
        --record-types={dns.RECORD-PTR} 
        --network=network 
        --timeout=timeout

  /**
  Parses the given [hostname].
  Returns a pair of the name and the suffix.
  */
  static parse_ hostname/string -> List:
    if not hostname.ends-with ".local": throw "Invalid hostname: $hostname"
    return [hostname[..hostname.size - 6], ".local"]

  /**
  Sets the hostname for this client.
  The [hostname] must end with ".local".
  
  This is a client-specific setting. The service will manage this hostname's
  lifecycle based on whether any connected clients are requesting it.
  
  If the hostname is already in use by another device, the service will
  automatically rename it (e.g., "name.local" -> "name (2).local") and
  the effective hostname can be retrieved via $hostname.
  */
  set-hostname hostname/string:
    // Verify format
    parse_ hostname
    
    requested-hostname_ = hostname
    service_.set-hostname hostname

  /**
  Returns the actual, conflict-resolved hostname this client is using.
  */
  hostname -> string:
    return service_.get-hostname

  /**
  Registers a service to be announced.
  The [type] should be a service type like "_http._tcp".
  The [port] is the port the service is running on.
  The [txt] map contains TXT record key-value pairs.
  The [name] is the instance name. If null, it defaults to the hostname (without .local).
  The [hostname] argument overrides the client's default hostname for this specific registration.
  */
  register-service type/string port/int
      --txt/Map?=null
      --name/string?=null
      --hostname/string?=null:
    service_.register type port --txt=txt --name=name --hostname=hostname

  /**
  Closes the client connection.
  For a standard Client, this does nothing of significance.
  For a $LocalMdnsClient, this stops the local provider.
  */
  close:
    // Default implementation does nothing, as the service is shared/remote.

/**
Adapter that exposes $Client as the standard $dns.DnsClient interface.

This allows mDNS resolution to be used transparently wherever the Toit SDK
expects a DnsClient. For example, you can pass this to HTTP clients or
other networking code that accepts a custom DNS resolver.

The adapter delegates all calls to the underlying $Client, which in turn
communicates with the mDNS system service.
*/
class DnsClient implements dns.DnsClient:
  client_/Client

  constructor .client_:

  // dns-lookup style (single IP).
  get name/string -> net.IpAddress
      --network/udp.Interface
      --accept-ipv4/bool=true
      --accept-ipv6/bool=false
      --timeout/Duration=dns.DNS-DEFAULT-TIMEOUT:
    return client_.dns-lookup name
        --network=network
        --accept-ipv4=accept-ipv4
        --accept-ipv6=accept-ipv6
        --timeout=timeout

  // dns-lookup-multi style (List of results).
  get name/string -> List
      --record-type/int
      --network/udp.Interface
      --timeout/Duration=dns.DNS-DEFAULT-TIMEOUT:
    return client_.dns-lookup name
        --record-types={record-type}
        --network=network
        --timeout=timeout

  // Internal helper required by dns.DnsClient interface
  get_ name/string -> List
      --record-types/Set
      --network/udp.Interface
      --timeout/Duration=dns.DNS-DEFAULT-TIMEOUT:
    return client_.dns-lookup name
        --record-types=record-types
        --network=network
        --timeout=timeout


/**
RPC client stub for the mDNS system service.

This class handles the serialization and communication with the
MdnsServiceProvider running in the system service container. It uses
Toit's ServiceClient infrastructure a for reliable message passing.

Method indices (LOOKUP-INDEX, etc.) must match those defined in
$MdnsService.
*/
class MdnsServiceClient extends ServiceClient implements MdnsService:
  static SELECTOR ::= MdnsService.SELECTOR
  constructor:
    super SELECTOR

  lookup name/string -> List
      --accept-ipv4/bool
      --accept-ipv6/bool
      --timeout-us/int:
    return invoke_ MdnsService.LOOKUP-INDEX [name, accept-ipv4, accept-ipv6, timeout-us]

  lookup name/string -> List
      --record-types/int
      --timeout-us/int
      --limit/int=50:
    return invoke_ MdnsService.LOOKUP-DETAILED-INDEX [name, record-types, timeout-us]

  register type/string port/int -> none
      --txt/Map?=null
      --name/string?=null
      --hostname/string?=null:
    invoke_ MdnsService.REGISTER-INDEX [type, port, txt, name, hostname]

  set-hostname hostname/string -> none:
    invoke_ MdnsService.SET-HOSTNAME-INDEX hostname

  get-hostname -> string:
    return invoke_ MdnsService.GET-HOSTNAME-INDEX null

  close:
    // Do nothing for RPC client

/**
A client that uses a local mDNS service provider.
This is useful for applications that want to use mDNS without
running a separate system service container.

The client manages the lifecycle of the local provider.
Calling $Client.close on it will stop the provider.
*/
class LocalMdnsClient extends Client:
  provider_/service.MdnsServiceProvider
  
  constructor --hostname/string=Client.DEFAULT-HOSTNAME:
    provider_ = service.MdnsServiceProvider
    // Connect locally to the provider we just created.
    super --hostname=hostname --service=provider_.connect-locally

  close:
    // Close the client connection first (releases ID)
    service_.close
    // Then stop the provider
    provider_.close

