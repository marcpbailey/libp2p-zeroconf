# Registration establishment and conflicts

`Register` and `RegisterProxy` return after opening the transport and starting
registration. Their signatures and nonblocking behavior are unchanged. Use
`Server.WaitForReady(ctx)` to obtain the initial establishment result across all
selected interfaces. Canceling this wait does not cancel registration.

After initial success, monitor `Server.Done()` and inspect `Server.Err()` for a
terminal failure. The initial readiness result remains unchanged by later failure.
`ConflictError` identifies the contested name and interface. Normal `Shutdown`
leaves `Err()` nil; shutdown before readiness returns `ErrServerClosed` to waiters.
The library does not choose replacement names.

Each selected interface has independent probing and announcement state. Ordinary
registration uses that interface's addresses; proxy registration keeps its
explicit address data. A terminal failure on one required interface stops the
whole registration and withdraws records already established on other links.
During reprobes the affected interface suppresses responses
and TXT announcements. Text updates during initial probing restart that sequence without shortening
a pending startup delay or conflict retry.

Windows currently lacks receive-interface metadata in the pinned x/net version.
Registration therefore requires one explicitly selected interface there, rather
than treating packets from an unknown interface as evidence for every link.
Socket/packet errors are reported through the lifecycle API. A family with no
usable interface address is not opened.

Default tests use private multicast groups and an ephemeral port. Native responder
tests require `-tags interop`, a specific `ZEROCONF_INTEROP_INTERFACE`, and a
`-run` filter selecting only the interoperability test. They publish synthetic
names. `ZEROCONF_INTEROP_CAPTURE` optionally records only these test DNS wire
packets with source and interface metadata through an ordinary UDP listener.

## Protocol and reference mapping

The normative reference is [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762.html):

| Section | Implementation |
| --- | --- |
| 8.1 | Probe unique names with ANY questions and proposed data; delay startup and space three probes by 250 ms. |
| 8.2 | Match authority records to question name/class/type, sort class/type/uncompressed RDATA, remove duplicates, and compare complete lists; the loser waits one second. |
| 8.1 | Fifteen conflicts within ten seconds impose at least five seconds between further attempts. |
| 9 | Established conflicts return to probing; a subsequent loss ends registration. |
| 6.6, 10.1 | Identical data cooperates; matching goodbyes refresh active records. |
| 6, 14 | Accept responses only from the mDNS source port; maintain link-specific state and addresses. |
| 15.1 | Avoid QU requests when another socket already occupies the multicast port. |

Avahi revision `3ed8102c8a881e6fe273bbf06f45e86dccf51e02` was inspected as
reference behavior. Its `announce.c` tracks group establishment and per-interface
announcers. Its `server.c` withdraws initial collisions, reprobes established
conflicts, and refreshes identical goodbye records. Its simultaneous-probe path
processes individual authority records, unlike the RFC's complete sorted-list
comparison. This implementation follows the RFC list comparison. No Avahi C
source is incorporated.

## Native interoperability evidence

Controlled tests use Avahi 0.8 (Debian package 0.8-10+deb12u1) and Bonjour
2881.160.4. They check native discovery, a fresh SRV query after unsolicited
announcements stop, withdrawal, and collision with an established native service.
The collision phase allows the native startup announcement sequence to finish.

An additional Bonjour experiment starting the library during the native startup
announcements did not receive a defending response. Its three probes were all
within one second of the last native announcement. The examined Bonjour source
at [revision 641cdf73ef46e1824895cbc44ad8ac7647da2479](https://github.com/apple-oss-distributions/mDNSResponder/blob/641cdf73ef46e1824895cbc44ad8ac7647da2479/mDNSCore/mDNS.c)
limits multicast query responses based on LastMCTime in ProcessQuery. That source
revision is 2881.120.11, not the exact installed daemon. It supports a rate-limit
explanation for the observation but does not establish the installed daemon's
internal cause. The earlier experiment remains a recorded compatibility failure.
RFC 6762 section 8.1 requires ignoring conflicts received before the first probe;
this implementation does not use a cached native announcement as a substitute
for a live defensive response.
