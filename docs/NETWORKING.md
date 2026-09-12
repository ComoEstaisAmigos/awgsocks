# DNS, UDP and routing behaviour

What AWGSocks does with name lookups, UDP datagrams and the Windows routing
table, and why none of it can leak outside the tunnel.

## DNS behaviour

Where names are resolved:

| Case | Resolver | Inside the tunnel |
| --- | --- | --- |
| SOCKS5 CONNECT with ATYP=DOMAINNAME | the servers in `[Interface] DNS`, over the gVisor stack | Yes |
| SOCKS5 UDP ASSOCIATE with ATYP=DOMAINNAME | same | Yes |
| SOCKS5 CONNECT with an IP literal | no resolution | - |
| `Endpoint` given as a hostname | the Windows resolver, before the tunnel exists | No, necessarily |
| The rest of the operating system | the Windows resolver, unmodified | No |

With no `DNS` line in the configuration, hostname requests are refused with
`0x04 host unreachable`. Falling back to the system resolver would be a DNS
leak, so it does not happen.

Windows DNS settings are never modified, so programs that do not use the proxy
keep using their normal resolver.

### DNS cache

A SOCKS5 client that resolves remotely sends a hostname with every CONNECT. A
browser opens several connections per host and many hosts per page, so one page
load can ask for the same name a dozen times within a second. Without a cache
each of those becomes a fresh A and AAAA query over UDP inside the tunnel.

That burst is what makes the link, and the public resolver behind it, drop
datagrams. The upstream resolver waits five seconds per server before retrying,
so **one lost query stalls a page resource for five seconds**. The symptom is
exactly this: some sites take thirty seconds, some tabs spin for minutes.

Three layers deal with it:

| Layer | Effect |
| --- | --- |
| Cache | A successful answer is reused for 60 seconds, a failure for 5 |
| Coalescing | Concurrent lookups for the same name collapse into one query |
| Concurrency limit | At most 8 in-flight tunnel queries, which flattens the burst |

Each attempt also gets a growing budget of 2, 4 and 6 seconds, so a datagram
that is still lost costs about two seconds rather than five.

The `DNS cache` line in `awgsocks status` shows whether it is working.

## UDP behaviour

AWGSocks implements SOCKS5 `UDP ASSOCIATE`, so UDP traffic can go through the
tunnel rather than around it.

This matters most for BitTorrent. DHT, UDP trackers and uTP all run on UDP.
With a TCP only proxy a client normally sends them **directly, from your real
address**, which defeats the point. Torrent clients generally do not disable
those features just because a SOCKS5 proxy is configured.

How it works:

- The relay socket is bound to loopback only, like the TCP listener.
- One in-tunnel socket per address family serves every destination, the way a
  NAT does, so one client can talk to hundreds of peers.
- Hostname destinations inside a UDP datagram are resolved by the same in-tunnel
  resolver as CONNECT.
- The association lives exactly as long as its TCP control connection, as
  RFC 1928 requires, with an idle timeout as a backstop.
- The in-tunnel socket is opened while the client is still listening, so a
  tunnel that cannot carry UDP is reported as a failed `UDP ASSOCIATE` rather
  than as datagrams that silently vanish.

Set `"udp_associate": false` to turn it off. That is more restrictive for the
proxy but usually worse overall, because clients that cannot use the proxy for
UDP tend to send it directly instead.

> [!NOTE]
> QUIC and WebRTC also use UDP. Browsers normally fall back from HTTP/3 when a
> proxy is configured. WebRTC is a well known browser deanonymisation vector
> regardless of proxy settings, so disable it in the browser if that matters to
> you.

### MTU and the AmneziaWG per-packet prefix

AmneziaWG puts an `S4` byte random prefix on **every** transport packet. The
classic WireGuard default of 1420 does not account for it:

```
packet = MTU + S4 + 32 (WG header and tag) + 8 (UDP) + 20 (IPv4)
       = 1420 + 43 + 32 + 8 + 20
       = 1523  ->  does not fit a 1500 byte path
```

Large outbound packets are then lost. The failure is one sided and easy to
misread: downloads keep working, because the large packets in that direction are
produced by the server, and `curl` keeps working, because its requests are
small. A browser sends a roughly 2 KB ClientHello carrying a post-quantum key
share, so it hits a full size packet immediately and hangs on "performing a TLS
handshake".

AWGSocks prevents this: with no `MTU` line in the `.conf` it derives
`1420 - S4 - ContentPaddingAddition` and reports the choice as a warning. An
explicit `MTU` is honoured as written, and only warned about if it looks too
high.

## Routing behaviour

AWGSocks writes **nothing** to the Windows routing table.

`AllowedIPs = 0.0.0.0/0, ::/0` is accepted and preserved, but it means "this
peer may carry any destination". It goes only into the AmneziaWG device's
internal `allowedips` trie and has nothing to do with Windows routing.

Because no system wide route is installed, the encrypted UDP cannot be routed
back into the tunnel either: the endpoint socket uses the default physical
connection. To see for yourself that the routing table is untouched, compare it
before and after starting the service, as in
[Verifying routing and adapters](TESTING.md#verifying-routing-and-adapters).
