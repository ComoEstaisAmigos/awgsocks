# Testing and verification

## Automated tests

```bat
scripts\test.bat
```

or individually:

```bat
gofmt -l .\cmd .\internal
go vet ./...
go test ./...
go build ./...
```

### What each package covers

| Package | Verifies |
| --- | --- |
| `internal/config` | The AmneziaWG 1.5 configuration class, H1-H4 range syntax, the generated UAPI, rejection of unsupported parameters, the MTU derivation, UTF-16 and BOM handling, the loopback-only rule |
| `internal/logging` | That no key material can reach a log line, level filtering, rotation |
| `internal/dns` | Cache hits, coalescing of concurrent lookups, negative caching, the concurrency limit |
| `internal/socks5` | The SOCKS5 protocol, IPv4, IPv6 and hostname destinations, UDP ASSOCIATE, reply code mapping, refusal to bind outside loopback, and **that the source contains no `net.Dial`** |
| `internal/awg` | The upstream dry run, fail-closed behaviour, UAPI status parsing, dropping of secret fields, and **that the package contains no `net.Dial`** |
| `internal/service` | Service lifecycle, port release on stop, that a broken configuration never replaces a healthy tunnel, what each reload applies, non-delayed start and the retry of a tunnel that cannot come up yet, and which ACL `repair` gives each file |
| `internal/e2e` | **The end to end data path over real AmneziaWG**, with both UDP bind implementations |
| `internal/winsys` | That the data directory ACL names SYSTEM and Administrators and nobody else, and that `config.json` is readable but not writable by a standard user |
| `internal/version` | That `scripts/build.bat` stamps the same release version the code declares, and that no document quotes an upstream version or commit other than the pinned one |
| `cmd/awgsocks` | That the double click message names only the helper scripts that are really present, and offers a command that runs in any shell |

### Race detector

```powershell
$env:CGO_ENABLED = "1"
go test -race ./...
```

> [!NOTE]
> On Windows the race detector needs cgo, which means a C compiler such as
> MinGW-w64 must be installed. It is **not** needed to build AWGSocks; without a
> compiler `go test -race` stops with `-race requires cgo`.

### The leak guard tests

`internal/socks5/noleak_test.go` and `internal/awg/tunnel_test.go` walk the
package source at the AST level and fail if `net.Dial`, `net.Dialer`,
`net.LookupHost`, `net/http` or any other direct egress appears. If someone adds
one later, the build breaks.

Bind calls are allowed, because a listening socket cannot reach a remote
destination on its own. The one case where that is not quite true, a bound UDP
socket sending anywhere, is closed separately by `loopbackPacketConn` and
`TestUDPRelayRefusesNonLoopbackReply`.

### The end to end data path test

`internal/e2e` stands up a second AmneziaWG device as a server and uses the
entire production stack on the client side. Both ends apply the same
`Jc/Jmin/Jmax`, `S1-S4` and `H1-H4`. If either side were plain WireGuard the
message types would not be recognised and no packet would pass, so the test
passing is evidence that the obfuscation is genuinely in effect.

Sample output:

```
--- PASS: TestDataPathIPv4 (1.02s)
--- PASS: TestDataPathIPv6 (1.02s)
--- PASS: TestRemoteDNSThroughTunnel (1.02s)
--- PASS: TestSystemResolverIsNeverUsed (1.02s)
--- PASS: TestFailsClosedWhenTunnelStops (1.02s)
--- PASS: TestConcurrentConnections (1.06s)
--- PASS: TestLargeTransfer (1.10s)
--- PASS: TestReconnectRecoversHandshake (2.05s)
--- PASS: TestDataPathWithWindowsRIOBind (1.01s)
--- PASS: TestExperimentalNetstackModesDataPath (3.03s)
--- PASS: TestUDPThroughTunnel (1.01s)
--- PASS: TestUDPFailsClosedWhenTunnelStops (1.01s)
--- PASS: TestInTunnelDNSSurvivesALostResponse (3.01s)
--- PASS: TestRequestBeforeTheNetworkArrivesIsHeldNotRefused (6.01s)
```

> [!NOTE]
> One run of `go test ./...` with every package in parallel once ended with
> `STATUS_HEAP_CORRUPTION (0xC0000374)` in the `internal/e2e` process. It has
> not happened again across more than twenty full runs, 200 `BindUpdate` cycles,
> 180 parallel device setup and teardown cycles, or teardown while a transfer
> was in flight, and the race detector is clean on every package. Chasing it is
> why the default `udp_bind` is `std`; the reasoning is in
> [Choosing udp_bind](CONFIGURATION.md#choosing-udp_bind).

> [!WARNING]
> Every run of `internal/e2e` leaves one process behind. The test binary is
> rebuilt at a new path each time and binds the AmneziaWG endpoint socket on all
> interfaces, which is how the upstream bind opens it. Windows Defender Firewall
> wants to ask about each new binary doing that, and when the question is never
> answered the `PickerHost.exe FirewallNotificationDialogServer` process behind
> it stays alive. Task Manager lists it as "File Picker UI Host".
>
> One is harmless. Running the suite in a loop is not: chasing a flaky test here
> left 236 of them holding 3.2 GB. To clear only those, without touching a file
> picker that is really open:
>
> ```powershell
> Get-CimInstance Win32_Process -Filter "Name='PickerHost.exe'" | Where-Object CommandLine -like '*FirewallNotificationDialogServer*' | Invoke-CimMethod -MethodName Terminate
> ```

## Manual leak tests

These need a real AmneziaWG server.

### TEST A: the SOCKS5 exit address must be the VPN server

```bat
curl.exe --proxy socks5h://127.0.0.1:10808 https://api.ipify.org
```

Expected: the public address of your AmneziaWG server.

For comparison, without the proxy:

```bat
curl.exe https://api.ipify.org
```

The two must differ.

### TEST B: a SOCKS request must fail when the tunnel cannot carry it

```bat
.\awgsocks.exe stop
curl.exe --proxy socks5h://127.0.0.1:10808 https://api.ipify.org
```

Expected: curl cannot reach the proxy at all, because stopping the service
closes the port.

```
curl: (7) Failed to connect to api.ipify.org:443 over proxy 127.0.0.1 after 2024 ms: Could not connect to server
```

> [!WARNING]
> This must never return your ISP address. If it does, there is a leak.

The other way to fail is with the service running and no handshake, which is
what an unreachable or wrongly configured server gives you. The proxy accepts
the request, waits for the tunnel, and then refuses it with SOCKS5 reply `0x03`:

```
curl: (97) cannot complete SOCKS5 connection to api.ipify.org. (3)
```

That answer takes 20 seconds for a hostname, because the wait counts against
in-tunnel name resolution, and 15 for an IP address.

### TEST C: the default Internet connection must work while the service is stopped

```bat
.\awgsocks.exe stop
curl.exe https://api.ipify.org
```

Expected: your ISP address, as normal.

### TEST D: a program without proxy settings must use the normal connection

```bat
.\awgsocks.exe start
curl.exe https://api.ipify.org
```

Expected: your ISP address.

### TEST E: a real program through the proxy

Point a program at `127.0.0.1:10808` as a SOCKS5 proxy, with hostname
resolution through the proxy turned on, and have it fetch
`https://api.ipify.org`. It should report the VPN server address.

### TEST F: UDP through the proxy

Run something that uses SOCKS5 `UDP ASSOCIATE`, then check `awgsocks status`.
The `UDP ASSOCIATE` line must show at least one active association and a
datagram count that climbs. If it does not, the program is not sending UDP
through the proxy and is sending it around the tunnel instead.

### TEST G: stopping must not break Windows networking

```bat
.\awgsocks.exe stop
ping 8.8.8.8
nslookup example.com
```

All of these must work normally.

## Verifying routing and adapters

While the service runs:

```powershell
route print -4
Get-NetAdapter
Get-DnsClientServerAddress
Get-Process awgsocks | Select-Object -ExpandProperty Modules |
    Where-Object { $_.ModuleName -like "*wintun*" }
```

Expected:

- The routing table is identical to before the service started
- No new network adapter
- DNS settings unchanged
- No Wintun module in the list

To compare before and after:

```powershell
route print -4 > before.txt
.\awgsocks.exe start
route print -4 > after.txt
Compare-Object (Get-Content before.txt) (Get-Content after.txt)
```

The output should be empty.

## Verifying open sockets

```powershell
$p = Get-Process awgsocks
Get-NetTCPConnection -OwningProcess $p.Id -State Listen |
    Select-Object LocalAddress, LocalPort
Get-NetUDPEndpoint -OwningProcess $p.Id |
    Select-Object LocalAddress, LocalPort
```

Expected:

```
TCP  127.0.0.1  10808        SOCKS5 listener, loopback only
UDP  0.0.0.0    <ephemeral>  AmneziaWG endpoint socket
UDP  ::         <ephemeral>  the IPv6 side of the same socket
```

Plus one loopback UDP socket for each active SOCKS5 UDP association.

If you see `0.0.0.0:10808` the configuration is wrong, although AWGSocks refuses
that at startup anyway.

## Verifying that the proxy is not reachable remotely

From another machine, or using your own LAN address:

```powershell
Test-NetConnection -ComputerName <LAN-IP> -Port 10808
```

`TcpTestSucceeded` must be `False`.

## Verifying that no key material is logged

The log directory is closed to standard users, so run this from an
Administrator prompt:

```powershell
Select-String -Path "$env:ProgramData\AWGSocks\logs\*.log" `
  -Pattern '\b[0-9a-fA-F]{64}\b'
```

The output should be empty. Set `log_level` to `debug` and try again: even at
DEBUG level no key is written, because every line passes the filter in
`internal/logging/redact.go`.

## Measuring throughput honestly

Do not use small downloads. A 1 to 2 MB file mostly measures the TLS handshake
and TCP slow start.

```bat
curl.exe -o NUL --proxy socks5h://127.0.0.1:10808 -w "%{speed_download} B/s\n" --max-time 180 "https://speed.cloudflare.com/__down?bytes=25000000"
```

Also measure the upload direction, because an MTU problem shows up there first
while downloads still look fine:

```bat
curl.exe -o NUL --proxy socks5h://127.0.0.1:10808 -w "%{speed_upload} B/s\n" --max-time 60 -X POST --data-binary "@C:\Windows\System32\ntoskrnl.exe" https://speed.cloudflare.com/__up
```

## Where the CPU actually goes

The repository carries a loopback benchmark that drives the complete production
path: SOCKS5 CONNECT, the gVisor network stack, the AmneziaWG device, a real UDP
socket, and a second AmneziaWG device serving the far end.

```bat
go test ./internal/e2e -run "^$" -bench BenchmarkProductionUpload -benchtime=3s
```

`BenchmarkProductionUpload` writes in one direction, which is what a download or
an upload looks like. `BenchmarkProductionDataPath` echoes every byte back and
waits for it, so it reports roughly a third less. Prefer the one directional
figure when judging capacity, and read both as a floor rather than a ceiling:
the harness runs both tunnel endpoints, the SOCKS5 server and the benchmark
client in a single process on one CPU, while a real installation runs only the
client half.

Measured on a 6 core Ryzen 5 5600, one direction, 256 KiB blocks:

| streams | throughput | process CPU |
| ------- | ---------- | ----------- |
| 1       | ~118 Mbit/s | ~4.5 cores |
| 4       | ~456 Mbit/s | ~5.4 cores |
| 8       | ~460 Mbit/s | ~5.4 cores |

A CPU profile of the single stream case attributes the time like this:

| component | share of CPU |
| --------- | ------------ |
| Windows socket syscalls (`runtime.cgocall`) | ~57% |
| Go scheduler, wakeups, work stealing | ~20% |
| AmneziaWG encryption and decryption | ~2.3% |

```bat
go test ./internal/e2e -run "^$" -bench "BenchmarkProductionUpload/streams=1$" -benchtime=5s -cpuprofile cpu.prof -o e2e.test.exe
go tool pprof -top -nodecount=25 e2e.test.exe cpu.prof
```

The obfuscated AmneziaWG cryptography is not what costs anything here. The cost
is the number of UDP socket operations, so that is where any future optimisation
has to aim.

### Comparing the two UDP binds

[Choosing udp_bind](CONFIGURATION.md#choosing-udp_bind) explains why `std` is
the default rather than the Registered I/O bind the official Windows client
uses. This is what the choice actually costs:

```bat
go test ./internal/e2e -run "^$" -bench BenchmarkBindModeUpload -benchtime=3s -count=2
```

| bind | one stream | four streams | process CPU, one stream |
| ---- | ---------- | ------------ | ----------------------- |
| `std` | ~119 Mbit/s | ~457 Mbit/s | ~4.6 cores |
| `rio` | ~120 Mbit/s | ~470 Mbit/s | ~4.1 cores |

The throughput difference sits inside run to run variance. The CPU difference
does not: RIO does the same work for roughly a tenth less processor time, which
follows from the profile above, since it is the socket layer that dominates.
Choosing `rio` to go faster would be choosing it for the wrong reason.

### The network stack handoff experiment

`internal/awg/netstack.go` carries three experimental handoffs between the
gVisor stack and the AmneziaWG device, reachable only from benchmarks and their
correctness tests. Nothing in the application or in configuration can select
them. They exist to answer one question with numbers instead of intuition: is
the upstream one packet at a time handoff worth forking gVisor over?

```bat
go test ./internal/awg -run TestBatchTun -v
go test ./internal/e2e -run TestExperimentalNetstackModesDataPath -v
go test ./internal/e2e -run "^$" -bench BenchmarkExperimentalUpload -benchtime=3s -count=3
```

The answer measured on this machine was no. Against the upstream handoff, the
best experimental mode gained about 2% on a single stream and about 9% across
four, while adding a goroutine, a copy per packet and tens of megabytes of
queue buffers to the data path of a leak critical proxy. That is not a trade
worth making, so production keeps the upstream path untouched.

> [!NOTE]
> A batching adapter must never wait for a batch to fill. The AmneziaWG
> handshake is built and sent by the peer directly and never passes through the
> TUN read path, so a batching bug hides behind a tunnel that reports itself
> connected while the first data packet of every connection is stuck in the
> queue. `TestBatchTunNeverWaitsToFillABatch` is the regression test for exactly
> that failure.
