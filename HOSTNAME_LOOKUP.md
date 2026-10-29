# One-shot mDNS hostname lookup

`LookupHostname(ctx, HostnameQuery, ...ClientOption) ([]HostnameResult, error)`
queries a hostname independently of DNS-SD. It sends direct A and/or AAAA
questions, reusing the existing client socket setup, DNS decoder, multicast send
path, retry scheduler and shutdown. Platform packet operations are shared with
registration, including Windows adapter-index conversion. No service records are
created or required, and no process-wide cache or subscription is introduced.

## Request and completion

`HostnameQuery.Name` must be an ASCII DNS hostname below `.local`, with letters,
digits and interior hyphens in each label. Multi-label names are supported. The
optional final dot and ASCII case are normalized. Bare names, the `.local` apex,
other domains, escapes and malformed labels are rejected before opening sockets.

`Families` selects address record types. Zero defaults to `IPv4AndIPv6`.
`SelectIPTraffic` independently selects the packet transports. For example,
`Families: IPv6` with `SelectIPTraffic(IPv4)` asks for AAAA over IPv4 multicast.

`Duration` is the collection window after transport setup, defaulting to one
second. Negative durations are rejected. The entire window is used, including
after a positive or negative answer, to collect split packets and independent
links. A longer window reuses the service client's initial four-second retry
interval and exponential backoff with jitter, capped at sixty seconds. There is
no final DNS-SD lookup or system-resolver fallback. The default one-second window
sends one query; increase it if retries are needed on a lossy network.

The lookup stops accepting packets when the collection window ends or its
context is canceled, whichever happens first. It cancels its workers, closes both
transport sockets and waits for its send/receive goroutines before returning.
The context also applies to setup to the extent supported by local socket calls;
these calls are not independently interruptible. Each concurrent call owns its
sockets, timer and answer state. No answer is shared between calls or retained
after return.

## Results and errors

Each `HostnameResult` belongs to one receiving interface, identified by its
canonical `net.Interface` index. Same-named hosts from different links remain
separate, even if their address bytes match. Unselected interfaces and packets
without a usable interface index are ignored. No interface is guessed, including
when only one was selected. An explicit interface without a usable selected
transport fails setup. Automatic selection skips loopback, point-to-point and
addressless interfaces. Every retained link must have at least one working
selected transport. A missing IPv6 packet transport does not prevent collecting
AAAA answers over IPv4.

Resolve the canonical interface index into the appropriate platform IPv6 zone
before using a link-local address. Windows has separate IPv4 and IPv6 adapter
indices: a canonical `net.Interface.Index` must not be assumed to be the native
IPv6 scope identifier. The packet helpers convert received native IPv6 indices
back to canonical indices and reject unknown mappings. The receiving link is
preserved even when AAAA arrives in an IPv4 packet. Native Windows runtime
validation remains required.

`Addresses` contains owned IP byte slices, each with its received positive-record
TTL and effective absolute expiry. Duplicate addresses on a link are renewed
rather than repeated. `NoData` contains independently expiring NSEC assertions
for the requested address families. A family missing from both lists remains
unknown. An unanswered link remains unknown and has no result. Ordering is
stable by interface index and address text, then negative address family.

* A nil error means at least one live address or explicit NSEC negative was
  collected. It does not mean every family or selected link answered.
* `ErrNoHostnameResponse` means the collection window ended without a live
  requested address or negative answer. This includes silence and records that
  expired within the window. It is never an authoritative NXDOMAIN result.
* A context deadline or cancellation returns `context.DeadlineExceeded` or
  `context.Canceled`, even when partial results are available.
* Socket setup, send and receive failures return errors. Any live results already
  collected accompany an error during collection. Context errors take precedence
  when cancellation and a socket error coincide.

Use the returned error and the records together. A complete IPv4 answer plus
silence for AAAA is a partial dual-stack result, not proof of IPv6 absence. A
result containing only `NoData` is an explicit negative result for those families
on that link, not proof that the hostname is absent everywhere. The results are
snapshots; callers must respect `Expiry`, particularly when goodbye/cache-flush
processing shortened it below the original TTL.

## Packet and lifetime policy

The authority is [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762), especially
sections 6, 6.1, 6.2, 10.1, 10.2 and 18. Only successful authoritative QUERY
responses from the configured mDNS source port contribute IN-class records.
The cache-flush bit is masked from the class. Matching A/AAAA records are read
from answer and additional sections, never query proposals or authority data.
Unrelated names, inappropriate flags/classes, malformed packets, unspecified or
multicast addresses, and IPv4-mapped AAAA values are ignored. Names use DNS ASCII
case comparison with final-dot normalization. CNAME chasing is not supported.

NSEC bitmaps supply no-data only for requested families whose types are absent.
The next-domain field is ignored as required by section 6.1. Conventional
DNSSEC-style NSEC records with the NSEC bit set are ignored. Positive records in
the same packet take precedence over a contradictory bitmap. Positive answers
replace earlier negative state; a negative received after a positive shortens
the positive's remaining lifetime to at most one second. Until that positive
expires, it takes precedence in the returned snapshot.

Each positive and negative record expires separately. A goodbye shortens an
existing matching record to at most one second, without creating a new result.
Cache-flush address records shorten older same-family records on that link to at
most one second; records received in the last second are protected, allowing
split RRSets. Reannouncements can rescue a goodbye or pending flush. Expired
records are omitted. Changes after the lookup ends cannot update its snapshot.

`Unannouncements` is rejected because this API is not a subscription. The
`UnicastDNS` option, when present in a combined build, is also rejected. Unicast
hostname resolution is deferred and does not create a dependency on that feature.
`.local` lookups always use multicast; no public DNS request is substituted.

## Tests

Normal tests use the existing multicast test destination and ephemeral test port,
never the native mDNS port or this computer's hostname. Deterministic encoded
packet tests cover family selection, split records, interface separation,
deduplication, renewal, expiry, negatives and removal. Controlled multicast tests
exercise the public API, concurrent calls and transport cleanup without service
advertisements. Registration and DNS-SD behavior remain covered by their existing
tests and [RFC 6763](https://www.rfc-editor.org/rfc/rfc6763) requirements.

The optional macOS test registers only two synthetic address records through
Bonjour's `DNSServiceCreateConnection` and `DNSServiceRegisterRecord` APIs. It
waits for startup announcements to finish, then performs a fresh independent
hostname lookup. The connection is removed when its helper exits. Explicitly
select an interface and run only this test:

```sh
ZEROCONF_INTEROP_INTERFACE=en0 go test -tags interop \
  -run '^TestNativeHostnameInterop$' -v -count=1 -timeout 25s
```

This uses the real network and briefly publishes synthetic addresses. It requires
permission for that test environment. It needs Python 3 and a running Bonjour
daemon, but no desktop control, service restart, packet capture or administrator
privileges. Cross-compilation is distinct from native execution. Avahi and native
Windows validation must be reported separately when performed.
