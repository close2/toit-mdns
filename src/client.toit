/**
Multicast DNS (mDNS) and DNS-SD client library.

Provides a high-level interface for:
- Name resolution (`.local` hostnames)
- Service discovery (browsing for services by type)
- Service registration (advertising services with `PTR`, `SRV`, `TXT`, and `A` records)

# Usage

```
client := Client
ip := client.dns-lookup "my-device.local"
instances := client.browse "_http._tcp"
client.register-service "_http._tcp" 8080 --txt={"path": "/api"}
```
*/

import net
import net.udp
import net.modules.dns
import system
import system.services show ServiceClient

import .api.mdns-service
import .private.dns-helper as dns-helper
import .private.names as names
import .service as service

/// Error text used when a hostname lookup yields no matching IP address.
HOST-NOT-FOUND-ERROR ::= "No name record found"

/**
Primary user-facing mDNS client.

Delegates lookups, browsing, and service registration to the shared
$service.MdnsServiceProvider (via RPC) or an in-process provider
(see $LocalMdnsClient).
*/
class Client:
  static DEFAULT-HOSTNAME ::= "$(system.hostname).local"

  service_/MdnsService
  requested-hostname_/string? := null
  closed_/bool := false

  constructor
      --hostname/string=DEFAULT-HOSTNAME
      --service/MdnsService?=null:
    owns-service := service == null
    if service:
      service_ = service
    else:
      rpc-client := MdnsServiceClient
      rpc-client.open
      service_ = rpc-client

    completed := false
    try:
      set-hostname hostname
      completed = true
    finally:
      if not completed and owns-service:
        catch: service_.close

  /** Returns a $dns.DnsClient adapter that delegates to this client. */
  dns-client -> dns.DnsClient:
    return DnsClient this

  /**
  Resolves $name to a single $net.IpAddress, throwing a $dns.DnsException
  if no matching address record is found within $timeout or if $name is not
  a `.local` or reverse-lookup name.

  The $network parameter is accepted for $dns.DnsClient compatibility and
  is ignored because the mDNS provider manages the multicast socket.
  */
  dns-lookup name/string -> net.IpAddress
      --network/udp.Interface?=null
      --accept-ipv4/bool=true
      --accept-ipv6/bool=false
      --timeout/Duration=dns.DNS-DEFAULT-TIMEOUT:
    if not dns-helper.is-mdns-lookup-name name:
      throw (dns.DnsException "Not a .local name" --name=name)
    results := service_.lookup name
        --accept-ipv4=accept-ipv4
        --accept-ipv6=accept-ipv6
        --timeout-us=timeout.in-us

    if results.is-empty:
      throw (dns.DnsException HOST-NOT-FOUND-ERROR --name=name)

    results.do: | entry |
      // Support both [type, ip-bytes] pairs from QueryEngine and raw ByteArray entries.
      ip-bytes := (entry is List and entry.size == 2) ? entry[1] : entry
      if ip-bytes is ByteArray:
        ip := net.IpAddress ip-bytes
        if (not ip.is-ipv6 and accept-ipv4) or (ip.is-ipv6 and accept-ipv6):
          return ip

    throw (dns.DnsException HOST-NOT-FOUND-ERROR --name=name)

  /**
  Resolves specific DNS $record-types (a $List or $Set of `dns.RECORD-*`
  constants) for $name.

  The $network parameter is accepted for $dns.DnsClient compatibility and
  is ignored because the mDNS provider manages the multicast socket.

  Returns:
  - $net.IpAddress instances for `RECORD-A` / `RECORD-AAAA`
  - `string` values for `RECORD-PTR`, `RECORD-CNAME`, and `RECORD-TXT`
    (binary, non-UTF-8 `TXT` character-strings are returned as $ByteArray)
  - $dns.SrvResource instances for `RECORD-SRV`
  */
  dns-lookup name/string -> List
      --record-types/Collection
      --network/udp.Interface?=null
      --timeout/Duration=dns.DNS-DEFAULT-TIMEOUT:
    if not dns-helper.is-mdns-lookup-name name:
      throw (dns.DnsException "Not a .local name" --name=name)
    mask := 0
    record-types.do: mask |= it

    results := service_.lookup name
        --record-types=mask
        --timeout-us=timeout.in-us

    parsed := []
    results.do: | entry |
      type := entry[0]
      data := entry[1]

      if type == dns.RECORD-A or type == dns.RECORD-AAAA:
        parsed.add (net.IpAddress data)
      else if type == dns.RECORD-TXT:
        // Binary (non-UTF-8) character-strings are returned as `ByteArray`.
        if data is List:
          data.do: parsed.add (txt-entry_ it)
        else if data != null:
          parsed.add (txt-entry_ data)
      else if type == dns.RECORD-PTR or type == dns.RECORD-CNAME:
        parsed.add data.to-string
      else if type == dns.RECORD-SRV:
        if data is List and data.size == 4:
          parsed.add (dns.SrvResource name type 0 false data[3] data[0] data[1] data[2])

    return parsed

  static txt-entry_ entry -> any:
    if entry is ByteArray:
      bytes := entry as ByteArray
      return bytes.is-valid-string-content ? bytes.to-string : bytes
    return entry.to-string

  /**
  Browses for DNS-SD services of $type (for example `"_http._tcp"`),
  returning discovered Service Instance Names (`string`s).
  */
  browse type/string -> List
      --network/udp.Interface?=null
      --timeout/Duration=dns.DNS-DEFAULT-TIMEOUT:
    query-name := (dns-helper.has-local-suffix type) ? type : "$(type).local"
    return dns-lookup query-name
        --record-types={dns.RECORD-PTR}
        --network=network
        --timeout=timeout

  /**
  Validates $hostname and splits it into `[prefix, ".local"]`.
  */
  static parse_ hostname/string -> List:
    names.validate-hostname hostname
    prefix := hostname[..hostname.size - 6]
    return [prefix, hostname[hostname.size - 6..]]

  /**
  Sets the hostname for this client (must end with `.local`).
  */
  set-hostname hostname/string -> none:
    parse_ hostname
    requested-hostname_ = hostname
    service_.set-hostname hostname

  /** Returns the effective, conflict-resolved hostname for this client. */
  hostname -> string:
    return service_.get-hostname

  /**
  Registers a DNS-SD service to be probed and announced on this client's hostname.
  */
  register-service type/string port/int -> none
      --txt/Map?=null
      --name/string?=null:
    names.validate-service-type type
    if name: names.validate-instance-name name
    names.validate-txt txt
    service_.register type port --txt=txt --name=name

  /**
  Unregisters a previously registered DNS-SD service, sending goodbye packets
  if already announced. Returns true if a matching service was removed.
  */
  unregister-service type/string --name/string?=null -> bool:
    names.validate-service-type type
    if name: names.validate-instance-name name
    return service_.unregister type --name=name

  /**
  Closes this client connection and releases its hostname reference on the
  underlying mDNS service provider.
  */
  close -> none:
    if closed_: return
    closed_ = true
    service_.close

/**
Adapter exposing $Client as the standard SDK $dns.DnsClient interface.
*/
class DnsClient implements dns.DnsClient:
  client_/Client

  constructor .client_:

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

  get name/string -> List
      --record-types/Collection
      --network/udp.Interface
      --timeout/Duration=dns.DNS-DEFAULT-TIMEOUT:
    return client_.dns-lookup name
        --record-types=record-types
        --network=network
        --timeout=timeout


/**
RPC client stub for the mDNS system service.
*/
class MdnsServiceClient extends ServiceClient implements MdnsService:
  static SELECTOR ::= MdnsService.SELECTOR
  closed_/bool := false

  constructor:
    super SELECTOR

  lookup name/string -> List
      --accept-ipv4/bool
      --accept-ipv6/bool
      --timeout-us/int:
    return invoke_ MdnsService.LOOKUP-INDEX [name, accept-ipv4, accept-ipv6, timeout-us]

  lookup name/string -> List
      --record-types/int
      --timeout-us/int:
    return invoke_ MdnsService.LOOKUP-DETAILED-INDEX [name, record-types, timeout-us]

  register type/string port/int -> none
      --txt/Map?=null
      --name/string?=null:
    invoke_ MdnsService.REGISTER-INDEX [type, port, txt, name]

  unregister type/string --name/string?=null -> bool:
    return invoke_ MdnsService.UNREGISTER-INDEX [type, name]

  set-hostname hostname/string -> none:
    invoke_ MdnsService.SET-HOSTNAME-INDEX hostname

  get-hostname -> string:
    return invoke_ MdnsService.GET-HOSTNAME-INDEX null

  close -> none:
    if closed_: return
    closed_ = true
    super

/**
An in-process mDNS client backed by its own local $service.MdnsServiceProvider.
*/
class LocalMdnsClient extends Client:
  provider_/service.MdnsServiceProvider

  constructor --hostname/string=Client.DEFAULT-HOSTNAME:
    provider := service.MdnsServiceProvider
    completed := false
    try:
      instance := LocalMdnsClient.internal_ provider --hostname=hostname
      completed = true
      return instance
    finally:
      if not completed: catch: provider.close

  constructor.internal_ .provider_ --hostname/string:
    super --hostname=hostname --service=provider_.connect-locally

  close -> none:
    super
    provider_.close
