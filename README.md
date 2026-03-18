# mDNS for Toit

A comprehensive mDNS (Multicast DNS) and DNS-SD (DNS Service Discovery) package for Toit.
It allows ESP32 devices to resolve `.local` hostnames, discover services, and advertise their own services on the local network.

## Features

- **Hostname Resolution**: Resolve `.local` hostnames to IP addresses.
- **Service Discovery**: Browse for services (e.g., `_http._tcp`) and resolve instances.
- **Service Registration**: Advertise your own services with PTR, SRV, TXT, and A records.
- **Caching**: Efficient caching of records to minimize network traffic and latency.
- **Conflict Resolution**: Handles name conflicts automatically (RFC 6762).
- **Unicast Responses**: Support for Unicast responses (QU bit) to reduce multicast traffic.
- **RFC Compliance**: Implements core "MUST" requirements of RFC 6762 and RFC 6763.

## Usage

This package follows a Provider/Client model. The `MdnsServiceProvider` handles the mDNS state machine and networking, while `Client` talks to it.

You can run the Provider in two ways:
1.  **Shared Service (Recommended)**: Run `MdnsServiceProvider` in its own container. Other containers on the device can then share this single instance via `MdnsClient`.
2.  **Local Usage**: Run `MdnsServiceProvider` directly in your application container.

### Option 1: Shared Service

**1. Install Provider**

Create a file `mdns-provider.toit`:

```toit
import mdns.service

main:
  service := service.MdnsServiceProvider
  service.install
```

Install it on your device:

```bash
jag container install mdns mdns-provider.toit
```

**2. Use Client**

In your other applications, simply use the client:

```toit
import mdns.client show Client

main:
  client := Client
  // client.dns-lookup / client.register-service / client.browse
```

### Option 2: Local Usage

If you don't want to run a separate container, you can start the service directly in your app.

> [!NOTE]
> `MdnsServiceProvider` is a `ServiceProvider` and will register itself as the system's mDNS service provider upon instantiation. Be aware of this if you are running multiple instances or want to avoid global service registration.

```toit
import mdns.client show Client LocalMdnsClient

main:
  // Create a client that manages its own local mDNS provider
  client := LocalMdnsClient
  
  // Optional: Set as default mDNS resolver for the SDK
  // dns.default-mdns-client = client.dns-client

  // Use the client as normal
  client.register-service "_http._tcp" 8080 
      --name="MyDevice" 
      --txt={"path": "/"}
      
  // ... when done, close the client to stop the service
  // client.close
```

### Publishing Device Name

Each client connection manages its own requested hostname. The service announces a hostname only while at least one client is requesting it (reference counted). 

By default, a client requests `toit-device.local` (or similar system default). You can change this using `set-hostname`.

```toit
import mdns.client show Client

main:
  client := Client
  client.set-hostname "my-cool-device.local" 
  
  // The service will now probe and announce "my-cool-device.local".
  // If the client disconnects or the app exits, the hostname is released.
```

## RFC Compliance

This implementation targets RFC 6762 (mDNS) and RFC 6763 (DNS-SD).

| Feature                      | RFC  | Status        | Notes                                              |
|:-----------------------------|:-----|:--------------|:---------------------------------------------------|
| **Probing**                  | 6762 | ✅ Implemented | 3 probes, 250ms apart, random jitter, tiebreaking. |
| **Announcing**               | 6762 | ✅ Implemented | 2 unsolicited responses, 1s apart (§8.3).          |
| **Conflict Resolution**      | 6762 | ✅ Implemented | Defends, renames, 15-conflict rate limiting.       |
| **Response Generation**      | 6762 | ✅ Implemented | Correct TTLs, AA bit, record aggregation.          |
| **Known-Answer Suppression** | 6762 | ✅ Implemented | Suppresses when TTL ≥ 50% (§7.1).                  |
| **Unicast Responses**        | 6762 | ✅ Implemented | QU bit handling.                                   |
| **Message Validation**       | 6762 | ✅ Implemented | Rejects non-zero OPCODE/RCODE (§18).               |
| **Source Port Check**        | 6762 | ✅ Implemented | Rejects responses not from port 5353 (§6.10).      |
| **Response Rate Limiting**   | 6762 | ✅ Implemented | Max 1 multicast/second (§6.16).                    |
| **Probe Tiebreaking**        | 6762 | ✅ Implemented | Authority Section comparison (§8.2).               |
| **NSEC Negative Responses**  | 6762 | ❌ Not impl.   | Unique-name NSEC records not yet generated.        |
| **Truncated Packets (TC)**   | 6762 | ❌ Not impl.   | Multi-packet Known-Answer not supported.           |
| **Service Registration**     | 6763 | ✅ Implemented | PTR, SRV, TXT, A records.                          |
| **Service Enumeration**      | 6763 | ✅ Implemented | Browsing via generic PTR queries.                  |
| **Service Resolution**       | 6763 | ✅ Implemented | Resolving Service Instance Names.                  |
| **TXT Record Strings**       | 6763 | ✅ Implemented | Multiple key-value pairs (RFC 1035).               |
| **Subtypes**                 | 6763 | ❌ Not impl.   | Browsing by subtype not supported.                 |

## Why use `Client`?

The `Client` provided by this package is the recommended way to interact with mDNS on Toit.

While Toit's `net` library can resolve `.local` names it only implements one-shot queries.

The Client can also be set as default dns client for `.local` requests, rather than relying on one-shot queries.
```toit
import mdns.client show Client

client := Client
dns.default-mdns-client = client.dns-client
```

The background `MdnsServiceProvider` continuously listens to the multicast group. It maintains a cache of the network state, meaning lookups can often be answered instantly without waiting for a network query.
