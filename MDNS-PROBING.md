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
whole registration. During reprobes the affected interface suppresses responses
and TXT announcements. Text updates during initial probing restart that sequence.

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
| 8.2 | Sort class/type/uncompressed RDATA, remove duplicate records, and compare complete lists; the loser waits one second. |
| 8.1 | Fifteen conflicts within ten seconds impose at least five seconds between further attempts. |
| 9 | Established conflicts return to probing; a subsequent loss ends registration. |
| 6.6, 10.1 | Identical data cooperates; matching goodbyes refresh active records. |
| 14 | Maintain link-specific state and addresses. |
| 15.1 | Avoid QU requests when another socket already occupies the multicast port. |

Avahi revision `3ed8102c8a881e6fe273bbf06f45e86dccf51e02` was inspected as
reference behavior. Its `announce.c` tracks group establishment and per-interface
announcers. Its `server.c` withdraws initial collisions, reprobes established
conflicts, and refreshes identical goodbye records. Its simultaneous-probe path
processes individual authority records, unlike the RFC's complete sorted-list
comparison. This implementation follows the RFC list comparison. No Avahi C
source is incorporated.
