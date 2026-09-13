# AWGSocks architecture

This document answers the architecture questions that had to be settled before
any code was written, and explains why the data path works without a system wide
VPN.

## 1. The core idea

AWGSocks assembles three independent pieces:

```
+---------------------------+   +--------------------------+   +-------------------+
| gVisor userspace TCP/IP   |   | AmneziaWG userspace      |   | A regular         |
| stack (netstack), which   |-->| device (amneziawg-go):   |-->| Windows UDP       |
| presents a tun.Device     |   | Noise plus Jc/S/H/I      |   | socket (conn.Bind)|
+---------------------------+   +--------------------------+   +-------------------+
```

The only thing Windows knows about in that chain is the UDP socket on the right.
The IP stack on the left lives entirely inside the process: as far as Windows is
concerned it does not exist. That is why no routing table entry is needed.

## 2. How a SOCKS5 connection enters the tunnel

```
A program you configured
   |  SOCKS5 CONNECT example.com:443
   v
127.0.0.1:10808                         internal/socks5
   |  Dialer interface, no net.Dial
   v
awg.Tunnel.DialTCP                      internal/awg
   |  netstack.Net.DialContextTCPAddrPort
   v
gVisor netstack                         TCP state machine, produces IP packets
   |  tun.Device.Read  ->  device
   v
AmneziaWG device                        ChaCha20-Poly1305 plus Jc/Jmin/Jmax,
   |                                    S1-S4, H1-H4, I1-I5, header protection
   v
conn bind                               a regular Windows UDP socket
   |  UDP -> Endpoint
   v
AmneziaWG server -> Internet
```

The important part is that the TCP stream is never turned into a Windows socket.
There is no `net.Dial` in `internal/socks5`, and a test (`noleak_test.go`) walks
the package source at the AST level to keep it that way. When the tunnel is down
a SOCKS5 request fails, because there is no other path it could take.

## 3. Architecture review questions

### 3.1 Which upstream AmneziaWG implementation is embedded

`github.com/amnezia-vpn/amneziawg-go/v3`. Configuration parsing and UAPI
generation come from `github.com/amnezia-vpn/amneziawg-windows/v3`, which is the
`conf` package of the official AmneziaWG Windows client.

The pinned versions and commits, and the reasoning behind them, are in
[UPSTREAM.md](UPSTREAM.md).

### 3.2 Why this is real AmneziaWG and not standard WireGuard

Because all cryptography and all obfuscation run in the upstream device.
AWGSocks implements no AmneziaWG algorithm. That the parameters really reach the
device can be read straight out of `awgsocks status`, which reports them from
the running device:

```
Active AWG params : DISABLE_COOKIES=0 H1=301745575-401745574 H2=876826554-976826553 H3=1337755454-1437755454 H4=1776593183-1876593183 JC=10 JMAX=1000 JMIN=50 RANDOM_TRAILERS=0 S1=150 S2=135 S3=107 S4=43
```

The `internal/e2e` test goes further: it stands up a second AmneziaWG device as
a server and moves real data with the same parameters. If either side were plain
WireGuard, the message types (H1-H4) would not be recognised and not one packet
would pass.

### 3.3 Where Jc, Jmin and Jmax are implemented

`Device.JunkPackets()` in `device/noise-protocol.go` builds `Jc` random packets,
each sized `Jmin + rand(Jmax - Jmin)`. `SendHandshakeInitiation` in
`device/send.go` sends them ahead of the handshake packet.

> [!NOTE]
> When `Jmin > Jmax` that subtraction underflows a uint32 upstream and asks for
> an enormous allocation. AWGSocks rejects the combination during configuration
> validation.

### 3.4 Where S1-S4 are implemented

`device/send.go`. Each message type gets its own random prefix:

| Parameter | Field | Upstream |
| --- | --- | --- |
| S1 | handshake initiation | `device.paddings.init` |
| S2 | handshake response | `device.paddings.response` |
| S3 | cookie reply | `device.paddings.cookie` |
| S4 | transport (data) | `device.paddings.transport` |

On receive, `DeterminePacketTypeAndPadding` in `device/receive.go` skips the
prefix.

### 3.5 Where H1-H4 are implemented

Sending:

- `device/noise-protocol.go:199` `device.headers.init.Load().PickOne()`
- `device/noise-protocol.go:375` `device.headers.response...PickOne()`
- `device/send.go:245` `device.headers.cookie...PickOne()`
- `device/send.go:600` `device.headers.transport...PickOne()`

Receiving: `device/receive.go:605`, `DeterminePacketTypeAndPadding`, checks
`Contains()` on each range.

### 3.6 How H1-H4 ranges are represented

The `UintRange` type in `device/noise-types.go` packs `[lo, hi]` into a `uint64`.
`FromString` accepts `a` or `a-b` and rejects `hi < lo`.

In the words of the official documentation: for each outgoing packet a random
value is selected from the range, and on reception any value in the range is
accepted. That is `PickOne()` and `Contains()`. AWGSocks never collapses a range
to a single value, and a test checks that.

Upstream `mergeWithDevice` additionally requires the four ranges to be disjoint.
AWGSocks applies the same check during validation so the user gets an error that
names the line.

### 3.7 Which current AWG parameters the pinned commit supports

`handleDeviceLine` in `device/uapi.go` accepts:

`jc`, `jmin`, `jmax`, `s1`, `s2`, `s3`, `s4`, `h1`, `h2`, `h3`, `h4`,
`i1`, `i2`, `i3`, `i4`, `i5`, `header_protection_key`,
`content_padding_addition`, `rekey_after_time`, `rekey_timeout`,
`reject_after_time`, `keepalive_timeout`, `max_handshake_attempts`,
`random_trailers`, `disable_cookies`.

That list matches the accept list in `internal/config/params.go` exactly. An AWG
parameter outside it is not ignored silently, it is rejected with a clear error.

### 3.8 How a SOCKS5 TCP stream becomes an IP packet

`netstack.Net.DialContextTCPAddrPort` opens a connection in the gVisor TCP state
machine. gVisor uses the tunnel address from the `Address` line as the source and
produces IP packets, which it hands to `tun.Device.Read` through a
`channel.Endpoint`. The AmneziaWG device reads them, encrypts them and sends them
as UDP.

The conversion therefore happens in the gVisor stack inside the process, not in
the operating system kernel.

### 3.9 Why that traffic does not use Windows routing

Because no Windows socket is ever opened for it. A `gonet.TCPConn` satisfies
`net.Conn`, but underneath it there is no operating system socket, only gVisor
buffers. The Windows routing table makes no decision about that stream.

### 3.10 How the AmneziaWG endpoint stays reachable over the normal network

`conn.NewStdNetBind()` opens a regular `net.ListenUDP` socket. Since AWGSocks
never changes the default route, that socket uses the machine's normal physical
connection. While `awgsocks run` is active the only operating system sockets the
process holds are:

```
TCP  127.0.0.1:10808     SOCKS5 listener
UDP  0.0.0.0:<ephemeral> AmneziaWG endpoint socket
UDP  [::]:<ephemeral>    the IPv6 side of the same socket
```

plus one loopback UDP socket per active SOCKS5 UDP association.

#### Choosing the UDP bind

The `conn` package offers two bind implementations on Windows, `std` and `rio`.
Both are upstream code and indistinguishable at the protocol level, so the
choice does not touch this architecture: it changes only how the operating
system handles that one UDP socket. Which is the default and why is in
[Choosing udp_bind](CONFIGURATION.md#choosing-udp_bind), next to the numbers.

### 3.11 How a routing loop is avoided

The classic loop happens when the encrypted UDP is itself routed into the tunnel
by a system wide `0.0.0.0/0` route. AWGSocks installs no such route, so the loop
cannot form. `AllowedIPs = 0.0.0.0/0, ::/0` goes only into the device's internal
`allowedips` trie, which answers "which peer carries which destination" and has
nothing to do with operating system routing.

### 3.12 Why other Windows traffic does not enter the tunnel

The only things that enter the gVisor stack are packets written to it, and the
only code that writes to it is `awg.Tunnel.DialTCP`, `awg.Tunnel.ListenUDP` and
`awg.Tunnel.LookupHost`, all of which are called only by the SOCKS5 server, plus
the single throwaway datagram described in
[section 4](#4-the-transport-padding-priming-packet). A
program that does not use the proxy never touches AWGSocks at all.

### 3.13 What happens to SOCKS traffic if AmneziaWG drops

`awg.Tunnel` keeps a readiness channel that is closed only once a live handshake
has been observed and reopened when the handshake goes stale. `DialTCP` calls
`WaitReady` first:

| Tunnel state | Result | SOCKS5 reply |
| --- | --- | --- |
| Not running | `ErrTunnelDown`, immediately | `0x03` network unreachable |
| Paused, its configuration connected through another client | `ErrTunnelDown`, immediately | `0x03` network unreachable |
| Running, no handshake | `ErrNotReady` after 15 seconds, or 20 for a hostname, whose wait counts against in-tunnel resolution | `0x03` network unreachable |
| Running, live handshake | The connection is made | `0x00` |

No alternative egress is ever attempted, and UDP ASSOCIATE fails closed the same
way; see [UDP behaviour](NETWORKING.md#udp-behaviour).

### 3.14 Where DNS is resolved for SOCKS hostname requests

Inside `netstack.Net.LookupContextHost`. The query goes to the servers named on
the `[Interface] DNS` line, over UDP through the gVisor stack, which means it
travels inside the tunnel. The Windows resolver is never consulted for SOCKS
destinations.

With no DNS configured the request is refused rather than handed to Windows,
which is what keeps this fail-closed: see
[DNS behaviour](NETWORKING.md#dns-behaviour).

> [!NOTE]
> The one exception is an `Endpoint` given as a hostname. The server address has
> to be known before the tunnel exists, so that single lookup uses the Windows
> resolver. With an IP address in `Endpoint`, as in the example configuration, no
> DNS query happens at all.

DNS inside the tunnel runs over UDP, so packet loss is normal and costly.
What `internal/dns` and `Tunnel.lookupUncached` do about it, and why reducing
the number of queries matters more than shortening timeouts, is in
[DNS cache](NETWORKING.md#dns-cache).

### 3.15 and 3.16 Where Wintun is used, and why it is not needed

It is not used. Wintun lets a userspace program appear to the operating system
as a network adapter. AWGSocks does not want to appear as one, because the whole
point is not to be a system wide VPN.

Using Wintun would bring the chain: create adapter, assign address, install
route, set DNS. Every one of those steps would violate the project's hardest
requirement.

The `golang.zx2c4.com/wintun` binding is linked into the binary because
`tun/netstack` imports the `tun` package and `tun_windows.go` lives in that same
package. No Wintun function is ever called, `wintun.dll` is never loaded, and no
adapter appears; how to check both on a running process is in
[Verifying routing and adapters](TESTING.md#verifying-routing-and-adapters).

What the choice costs, in one view:

| Item | State |
| --- | --- |
| Driver to install | None |
| Network adapter created | None |
| Windows route added | None |
| System DNS setting changed | None |
| Adapter to clean up on uninstall | None |
| Privilege required to run the tunnel | None; installing and controlling the service needs Administrator |

### 3.17 Which Windows privileges are required

| Operation | Privilege |
| --- | --- |
| `awgsocks version`, `check` | None |
| `awgsocks run` (foreground) | None, but it needs a writable data directory |
| `awgsocks install`, `uninstall`, `repair` | Administrator |
| `awgsocks start`, `stop`, `restart` | Administrator |
| `awgsocks status`, `reload`, `reconnect` | Access to the management pipe (Administrator or the service account) |
| The service itself | LocalSystem |
| Running the tunnel | No extra privilege, no raw socket and no driver |

Unlike solutions built on Wintun, the tunnel itself needs no administrative
rights. Elevation is for managing the service and the files it runs from, never
for carrying traffic.

## 4. The transport padding priming packet

Upstream starts its TUN reader inside `NewDevice`, before any configuration
exists. That loop reads `S4` once per iteration and then blocks in
`tun.Read(..., offset)`, so the very first packet out of the tunnel is framed
with the padding that was in effect at device creation, which is zero. It goes
out without the S4 prefix and the peer discards it as a message of unknown type.
The next iteration re-reads S4 and every later packet is correct.

TCP hides this, because the lost packet is a SYN and the retransmission
succeeds. UDP does not retransmit, so the first datagram of a DHT announce or a
DNS query would simply vanish, and a DNS query would then wait five seconds for
its retry.

`primeTransportPadding` in `internal/awg/tunnel.go` therefore sends one
throwaway datagram to a discard address in TEST-NET-1 right after the device
comes up, so the cost is one discarded packet at startup instead of a lost first
packet at the worst possible moment.

## 5. Proof of the data path

`internal/e2e/e2e_test.go` builds this:

```
AWGSocks client (production code)          AmneziaWG server (test harness)
  SOCKS5 127.0.0.1:<port>                    netstack 10.66.66.1 / fd42:42:42::1
  awg.Tunnel                      UDP        HTTP  :8080
  netstack 10.66.66.2        <---------->    DNS   :53
  Jc/Jmin/Jmax, S1-S4, H1-H4                 UDP   :7000
                                             the same Jc/Jmin/Jmax, S1-S4, H1-H4
```

What it verifies:

- SOCKS5 CONNECT to an IPv4 destination returns a real HTTP body
- SOCKS5 CONNECT to an IPv6 destination returns a real HTTP body
- A hostname in the `.invalid` TLD, which only the in-tunnel DNS server can
  resolve, does resolve
- Without in-tunnel DNS, `example.com` does not resolve, proving the system
  resolver is not used
- Once the tunnel is stopped, even a genuinely reachable loopback server is
  refused
- SOCKS5 UDP ASSOCIATE carries datagrams both ways over real AmneziaWG
- UDP ASSOCIATE is refused when the tunnel is down
- 32 concurrent connections
- 512 KiB, far above the MTU, transferred intact
- Data still flows after a reconnect
- The same data path over the Windows Registered I/O bind
- A hostname still resolves when one of the two DNS replies is lost, so a
  single dropped datagram cannot make a name look as though it does not exist
- A request sent before the server can be reached is held and then served once
  the handshake completes, rather than refused
