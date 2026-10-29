# Hostname resolution

`LookupHostname(ctx, HostnameQuery, ...ClientOption) ([]HostnameResult, error)`
resolves A/AAAA records independently of DNS-SD. No service instance, PTR, SRV or
TXT record is required. It provides automatic transport selection and explicit
controls, reusing the existing multicast client and unicast DNS machinery.

## Names and transport selection

The name must be an ASCII DNS hostname with at least two labels. The optional
final dot and ASCII case are normalized. Labels contain letters, digits and
interior hyphens. Bare names, escapes, IP literals and malformed labels are
rejected. Names are queried as absolute names; no search suffix is appended.

`HostnameQuery.Transport` selects the policy:

| Value | Behaviour |
| --- | --- |
| `HostnameAuto` (zero/default) | `.local` uses multicast. Other names use configured unicast DNS. |
| `HostnameMulticast` | Force multicast, including for non-`.local` names. |
| `HostnameUnicast` | Force unicast DNS. |

`UnicastDNS()` also explicitly selects unicast and uses configured system DNS
servers. `UnicastDNS("192.0.2.53:53")` selects an explicit resolver. Resolver
addresses, platform configuration sources and their limitations follow
[the existing unicast implementation](UNICAST.md#resolver-configuration).
Combining `HostnameMulticast` with `UnicastDNS` is an error.

```go
// Automatic multicast.
results, err := zeroconf.LookupHostname(ctx,
    zeroconf.HostnameQuery{Name: "api.dev.example.local."})

// Automatic configured DNS, including private DNS domains.
results, err = zeroconf.LookupHostname(ctx,
    zeroconf.HostnameQuery{Name: "api.example.com."})

// Explicit multicast for a non-.local name.
results, err = zeroconf.LookupHostname(ctx,
    zeroconf.HostnameQuery{Name: "api.example.com.", Transport: zeroconf.HostnameMulticast})

// Explicit DNS server, useful for diagnostics and controlled tests.
results, err = zeroconf.LookupHostname(ctx,
    zeroconf.HostnameQuery{Name: "api.example.com."}, zeroconf.UnicastDNS("192.0.2.53:53"))
```

Automatic selection never retries a failed `.local` multicast query through
unicast DNS, or a failed ordinary DNS query through multicast. A forced unicast
lookup of `.local` is an explicit caller override. DNS CNAME chains stay within
the selected transport; an automatic unicast lookup rejects a CNAME into `.local`
instead of leaking a new `.local` question to DNS or inventing a cross-transport
result. Callers can explicitly query that target through multicast.

This is hostname resolution through DNS and mDNS, not a replacement for the OS
resolver. It does not implement hosts-file lookup, NSS, DNS search lists, NRPT or
all interface-specific VPN resolver policy. It does not call `net.LookupHost` as
a hidden substitute. Command behaviour and application-specific naming belong in
callers rather than this API.

## Families, interfaces and results

`Families` selects address record types: `IPv4`, `IPv6` or `IPv4AndIPv6` (the zero
value defaults to both). This is independent of the IP family carrying a packet.
For multicast, `SelectIPTraffic(IPv4)` can carry questions and answers for both A
and AAAA. Unicast uses the configured resolver addresses' packet families;
non-default `SelectIPTraffic` and `SelectIfaces` are rejected there because this
implementation does not bind ordinary DNS exchanges to selected interfaces.

Each result identifies its actual `Transport`. Multicast results remain separate
by canonical receiving `InterfaceIndex`; same-named hosts on different links are
never combined. Unicast results have index zero, without a guessed link scope.
Unusable, multicast and unspecified addresses are rejected. Unicast link-local
addresses are also rejected because the DNS answer supplies no receiving-link
scope. IPv4-mapped AAAA records are rejected.

For multicast, packets without a usable interface index or from unselected
interfaces are ignored. Explicit interfaces must have a working selected packet
transport. Automatic selection skips loopback, point-to-point and addressless
interfaces. Resolve the canonical interface index to the appropriate native IPv6
zone before using a link-local address. Go's
[Go 1.21.13 Windows interface implementation](https://github.com/golang/go/blob/go1.21.13/src/net/interface_windows.go)
uses `IfIndex` with `Ipv6IfIndex` as a fallback; native IPv6 indices can differ.
Existing packet helpers perform the receive/send index conversion.

Each `HostnameAddress` has the address record owner's `Name`, owned `IP` bytes,
received `TTL` and effective `Expiry`. The owner can be a CNAME target. Addresses
are deduplicated and sorted. Unicast CNAME lifetimes can shorten the effective
expiry below the address record TTL. Zero-TTL unicast answers are usable only for
the current lookup and must not be cached. Other returned snapshots may expire
while another family is completing; callers must respect `Expiry`.

`NoData` contains per-family explicit negative assertions. Multicast uses NSEC;
unicast requires an applicable SOA and follows the smaller SOA TTL/MINIMUM.
`NXDOMAIN` distinguishes that DNS response from NODATA. A negative for one family
never suppresses the other family's addresses. Missing multicast families or
silent links remain unknown. Unicast failures do not become negative answers.

## Completion and errors

`Duration` defaults to one second and must not be negative:

* Multicast uses the entire duration after transport setup to collect split
  packets and separate links. Longer windows reuse the service client's initial
  four-second retry interval and exponential backoff with jitter, capped at sixty
  seconds. The default window sends one query.
* Unicast uses the duration as a maximum, including resolver configuration. A and
  AAAA run independently and return when all requested families have finished.
  Exchanges reuse EDNS negotiation, truncated-UDP TCP fallback, configured-server
  failover and a two-second per-server maximum within the overall deadline.

Nil error means successful protocol results, which may contain only explicit
negatives. Inspect addresses and `NoData` together. `ErrNoHostnameResponse` means a
multicast window ended without a live requested address or negative answer; it
is never NXDOMAIN. Unicast silence, malformed/incomplete replies and SERVFAIL are
errors. Query or context deadlines return `context.DeadlineExceeded`.
Cancellation returns `context.Canceled`. Errors retain available partial results.

Both paths close their sockets and wait for their workers before returning.
Each call owns its results and may run concurrently with other calls. There is no
new shared cache or subscription. `Unannouncements` is rejected. Local socket
setup is not independently interruptible; the context applies where the existing
transport/configuration calls support it.

## Protocol and equivalence

Multicast processing follows [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762):
accept successful authoritative QUERY responses from the configured mDNS source
port, validate IN class after masking cache-flush, and read matching addresses
from answer/additional sections. Query proposals and authority data cannot become
hostname results. NSEC ignores the next-domain field as section 6.1 requires;
DNSSEC-style NSEC with the NSEC bit set is ignored. Goodbye and cache-flush use the
one-second grace period, including protection for recently received split RRSets.
Each record expires independently. Positive answers take precedence during a
negative grace period. Changes after return cannot update the snapshot.

The API is guided by Bonjour's
[DNSServiceGetAddrInfo](https://github.com/apple-oss-distributions/mDNSResponder/blob/d4658af3f5f291311c6aee4210aa6d39bda82bbe/mDNSShared/dns_sd.h)
and Avahi's
[hostname resolver and transport selection](https://github.com/avahi/avahi/blob/02ac280d038dd66a45165d82421cfb8fcbca3bcd/avahi-core/browse.c).
Both provide hostname operations and transport controls. This library deliberately
provides a one-shot result rather than claiming identical subscription semantics.
Its automatic policy follows `.local` multicast/other configured DNS; unlike
Avahi's no-wide-area case, ordinary DNS failures do not select multicast.
Existing `Browse` and service `Lookup` retain their explicit opt-in unicast
contract. DNS-SD service target alias restrictions remain unchanged.

## Verification

Normal multicast tests use an ephemeral test port and synthetic names, never the
native mDNS port or this computer's hostname. Unicast tests use controlled
loopback DNS servers. Packet and network tests cover routing, families,
interfaces, split records, lifetimes, negatives, aliases, TCP/EDNS, failures,
cancellation, concurrency and cleanup.

The optional macOS test briefly registers only synthetic A/AAAA records through
Bonjour's DNSServiceRegisterRecord API. It waits for startup announcements to
finish before querying. Run only this test with an explicitly selected interface:

```sh
ZEROCONF_INTEROP_INTERFACE=en0 go test -tags interop \
  -run '^TestNativeHostnameInterop$' -v -count=1 -timeout 25s
```

It requires permission for that test network, Python 3 and a running Bonjour
service. It needs no desktop control, service restart, packet capture or admin
privileges. Native execution, cross-compilation and interoperability with Avahi or
Bonjour must be reported separately.
