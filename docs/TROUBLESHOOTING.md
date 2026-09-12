# Troubleshooting

Symptoms first. Each one names what you would see, then what causes it.

## The browser says the proxy refuses connections

Check that the service is actually running:

```bat
.\awgsocks.exe status
```

`Service state : stopped` means it is installed but was never started, which is
what happens when `install` is run without `--start`:

```bat
.\awgsocks.exe start
```

If `Listening : yes` and the browser still cannot connect, confirm it is using
`127.0.0.1`, port `10808`, SOCKS v5, and no authentication.

## TLS handshakes hang and uploads fail

The symptom is a browser stuck on "performing a TLS handshake" forever while the
same site loads fine with `curl`. Downloads work, uploads do not.

This is the MTU problem described under
[UDP behaviour](NETWORKING.md#mtu-and-the-amneziawg-per-packet-prefix). Check that `check`
reports a derived MTU rather than 1420:

```bat
.\awgsocks.exe check --config C:\ProgramData\AWGSocks\client.conf
```

If you wrote an explicit `MTU` line yourself, it is honoured as is, so lower it.

> [!NOTE]
> The derivation cancels `S4` out, so over an IPv4 endpoint the packet on the
> wire is always `1420 + 32 + 8 + 20 = 1480` bytes whatever `S4` is, which fits
> a 1492 byte PPPoE path as well as a 1500 byte one. An IPv6 endpoint costs 20
> bytes more and lands on exactly 1500, which a narrower path drops. Lower `MTU`
> in the `.conf` if your endpoint is IPv6 and your path is under 1500.

## Pages load very slowly or never finish

First confirm this is not a bandwidth problem:

```bat
curl.exe -o NUL --proxy socks5h://127.0.0.1:10808 -w "%{speed_download} B/s\n" "https://speed.cloudflare.com/__down?bytes=25000000"
```

If that number is close to your non-VPN measurement, throughput is fine and the
problem is almost always DNS. Look at the `DNS cache` line in
`awgsocks status`: a high `tunnel queries` count relative to `hits` means name
resolution is the bottleneck.

Try a different DNS server in the configuration. Some public resolvers rate
limit queries coming from a VPN server's shared address, which causes the losses.

> [!NOTE]
> A 1 to 2 MB file measures the TLS handshake, not throughput. See
> [Measuring throughput honestly](TESTING.md#measuring-throughput-honestly).

## Hostnames do not resolve but IP addresses work

The configuration probably has no `DNS` line. Check the `In-tunnel DNS` field in
`awgsocks status`, add one to the `.conf` and run `awgsocks reload`.

The other possibility is that the in-tunnel DNS server is not covered by
`AllowedIPs`.

## The service will not start

```bat
.\awgsocks.exe check --config C:\ProgramData\AWGSocks\client.conf
type C:\ProgramData\AWGSocks\logs\awgsocks.log
```

An invalid configuration is the usual cause, and `check` names the line.

## No handshake

`awgsocks status` shows `Last handshake : never`. Check, in order:

1. The `Endpoint` address and port.
2. Whether UDP reaches the server at all, given firewalls and ISP filtering.
3. Whether the AWG parameters (`Jc`, `S1-S4`, `H1-H4`) on the server match the
   client exactly. In AmneziaWG a mismatch means the far side does not recognise
   the packets at all.
4. Whether `PresharedKey` is set on both sides.

## status says it cannot reach the management pipe

Run the command from an elevated prompt. The pipe ACL is restrictive on purpose.

## Torrents connect but peers are few

Check that `udp_associate` is enabled, and that the client is set to send peer
connections through the proxy rather than only trackers. With UDP disabled, DHT
and UDP trackers cannot work through the proxy at all.

## The connection drops after sleep

The service listens for power events and reconnects on resume. If you run it
with `run` rather than as a service, those events do not arrive; use
`awgsocks reconnect`.

## More detail in the logs

Set `"log_level": "debug"` in `config.json` and run:

```bat
.\awgsocks.exe reload
```

No key material is written even at DEBUG level.
