# mDNS for Toit

A comprehensive mDNS (Multicast DNS, RFC 6762) and DNS-SD (DNS Service Discovery, RFC 6763) package for Toit.
It enables ESP32 and desktop Toit applications to resolve `.local` hostnames, discover services, and advertise their own services on the local network.

## Features

- **Hostname Resolution**: Resolve `.local` hostnames to IP addresses, including drop-in integration with `net.modules.dns`.
- **Service Discovery**: Browse for services (e.g., `_http._tcp`) across multiple responders and resolve instances.
- **Service Registration**: Advertise services with `PTR`, `SRV`, `TXT`, and `A` records, plus `_services._dns-sd._udp.local` enumeration.
- **Bounded Opt-In Caching**: Caches queried records (and their DNS-SD additionals) with bounded keys and entries to protect ESP32 heap memory.
- **RFC-Compliant Probing & Defense**: Probing with jitter, pairwise lexicographic tiebreaking, deferred rate-limited multicast responses, restricted-form `NSEC` negative answers, and voluntary `TTL=0` goodbyes.
- **Automatic Socket Recovery**: Recovers cleanly if the underlying Wi-Fi / UDP multicast interface resets while active clients are attached.

## Usage

This package follows a Provider/Client model: `MdnsServiceProvider` manages the multicast socket, cache, and RFC 6762 state machines, while `Client` communicates with it.

You can run the provider in two ways:
1. **Shared Service (Recommended for multi-container devices)**: Run `MdnsServiceProvider` in its own container so multiple applications share a single socket and cache via RPC.
2. **In-Process Usage**: Use `LocalMdnsClient` to run an isolated provider inside your application container.

### Option 1: Shared Service

**1. Install Provider**

Create `mdns-provider.toit`:

```toit
import mdns.service show MdnsServiceProvider

main:
  provider := MdnsServiceProvider
  provider.install
```

Install it on your device:

```bash
jag container install mdns mdns-provider.toit
```

**2. Use Client**

```toit
import mdns.client show Client

main:
  client := Client --hostname="my-device.local"
  client.register-service "_http._tcp" 8080 --txt={"path": "/"}

  ip := client.dns-lookup "other-device.local"
  instances := client.browse "_http._tcp"
```

### Option 2: In-Process Usage (`LocalMdnsClient`)

If you do not run a separate `mdns` container, `LocalMdnsClient` creates an in-process `MdnsServiceProvider` via `connect-locally` (without calling `.install` on the global system service registry):

```toit
import mdns.client show LocalMdnsClient
import net.modules.dns

main:
  client := LocalMdnsClient --hostname="my-device.local"

  // Optional: set as the SDK's default .local mDNS resolver.
  dns.default-mdns-client = client.dns-client

  client.register-service "_http._tcp" 8080
      --name="MyDevice"
      --txt={"path": "/"}

  // When done, close the client to send goodbye packets and stop the provider:
  // client.close
```

### Publishing a Device Name

Each client connection manages its own requested hostname (reference-counted by the provider). When `client.close` is called (or the client container exits), its reference is released and `TTL=0` goodbye records are sent once the reference count reaches zero.

```toit
import mdns.client show Client

main:
  client := Client
  client.set-hostname "my-cool-device.local"
```

## RFC Compliance

This implementation targets RFC 6762 (mDNS) and RFC 6763 (DNS-SD).

| Feature                      | RFC  | Status        | Notes                                                               |
|:-----------------------------|:-----|:--------------|:--------------------------------------------------------------------|
| **Probing**                  | 6762 | ✅ Implemented | 3 probes (QU), 250ms apart, 0–250ms jitter, 15-conflict rate limit. |
| **Probe Tiebreaking**        | 6762 | ✅ Implemented | Sorted `(class, type, rdata)` Authority Section comparison (§8.2).  |
| **Announcing & Goodbyes**    | 6762 | ✅ Implemented | 2 announcements 1s apart (§8.3) + voluntary `TTL=0` goodbyes (§10.1). |
| **Conflict Resolution**      | 6762 | ✅ Implemented | Defends established names/services and renames on persistent conflict (§9). |
| **Response Generation**      | 6762 | ✅ Implemented | Correct TTLs, `AA` bit, `cache-flush`, deduplicated aggregation.    |
| **Known-Answer Suppression** | 6762 | ✅ Implemented | Suppresses answers when query carries matching RR with TTL ≥ 50% (§7.1). |
| **Unicast Responses**        | 6762 | ✅ Implemented | `QU` bit (quarter-TTL rule) and legacy unicast responses (§5.4, §6.7). |
| **Message Validation**       | 6762 | ✅ Implemented | Rejects non-zero `OPCODE`/`RCODE`, ignores `Z`/`AD`/`CD` (§18).     |
| **Source Port Check**        | 6762 | ✅ Implemented | Rejects responses not from port 5353 in responder & querier (§6.10). |
| **Response Rate Limiting**   | 6762 | ✅ Implemented | Deferred multicast scheduling: max 1/s (250ms on probe defense, §6). |
| **NSEC Negative Responses**  | 6762 | ✅ Implemented | Restricted-form `NSEC` for unique host & service names (§6.1).      |
| **Truncated Packets (TC)**   | 6762 | ❌ Not impl.   | Multi-packet Known-Answer continuations not supported.              |
| **Service Registration**     | 6763 | ✅ Implemented | `PTR`, `SRV`, `TXT`, `A`, and `_services._dns-sd._udp.local` (§9).  |
| **Service Enumeration**      | 6763 | ✅ Implemented | Multi-responder `PTR` browsing with aggregation & Known-Answers.    |
| **Service Resolution**       | 6763 | ✅ Implemented | Resolving Service Instance Names (`SRV` + `TXT` + `A`).             |
| **TXT Record Strings**       | 6763 | ✅ Implemented | Multi-key, boolean/valueless, and binary `<character-string>` support (§6). |
| **Subtypes**                 | 6763 | ❌ Not impl.   | Browsing by `_sub` subtype not supported.                           |
