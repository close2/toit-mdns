/**
mDNS service interface definition.

Defines the RPC contract between clients (MdnsServiceClient) and the
service provider (MdnsServiceProvider). Method indices must match on
both sides for correct message routing.

This interface follows Toit's ServiceSelector pattern for type-safe
service discovery.
*/

import system.services show ServiceSelector

/**
mDNS service RPC interface.

Defines the method signatures and indices for client-service communication.
Each method has a corresponding INDEX constant used in the RPC dispatch.
*/
interface MdnsService:
  static SELECTOR ::= ServiceSelector
      --uuid="3d63eed1-785e-43e4-878f-204e4cd390ff"  // Random UUID
      --major=0
      --minor=1

  /// Standard lookup matching dns.dns-lookup arguments.
  lookup name/string -> any
      --accept-ipv4/bool
      --accept-ipv6/bool
      --timeout-us/int
  static LOOKUP-INDEX ::= 100

  /// Detailed lookup for specific record types.
  lookup name/string -> any
      --record-types/int
      --timeout-us/int
  static LOOKUP-DETAILED-INDEX ::= 101

  /**
  Registers a service.
  $type: The service type, e.g. "_http._tcp".
  $port: The port the service is running on.
  $txt: A map of TXT record key-values.
  $name: Optional instance name. If null, uses the device hostname (without .local).
  $hostname: Optional hostname to attach the service to. If null, uses the primary hostname.
  */
  register type/string port/int -> none
      --txt/Map?=null
      --name/string?=null
      --hostname/string?=null
  static REGISTER-INDEX ::= 200

  /**
  Sets the hostname for this client context.
  The hostname must end in '.local'.
  */
  set-hostname hostname/string -> none
  static SET-HOSTNAME-INDEX ::= 300

  /**
  Gets the actual conflict-resolved hostname for this client context.
  */
  get-hostname -> string
  static GET-HOSTNAME-INDEX ::= 301

  /**
  Closes the service connection.
  This is a local operation to release resources (like the client ID).
  */
  close -> none
