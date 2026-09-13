# AWGSocks

Runs a real AmneziaWG client tunnel entirely in userspace and exposes it as a
SOCKS5 proxy that only the local machine can reach.

**This is an application-scoped VPN, not a system wide one.** Only programs
configured to use `127.0.0.1:10808` go through the tunnel. Everything else keeps
using the default Windows Internet connection.

```
Programs you point at the proxy --> 127.0.0.1:10808 --> SOCKS5 --> AmneziaWG --> VPN server --> Internet
Every other program -------------> default Windows connection -----------------------------> Internet
```

## Contents

- [What it does and does not do](#what-it-does-and-does-not-do)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Pinned upstream versions](#pinned-upstream-versions)
- [Download](#download)
- [Building](#building)
- [Quick start](#quick-start)
- [Security model](#security-model)
- [Testing](#testing)
- [Known limitations](#known-limitations)
- [Documentation](#documentation)
- [License](#license)

## What it does and does not do

### It does

- Speak real AmneziaWG. All cryptography and all obfuscation come from the
  official `amneziawg-go` implementation.
- Apply `Jc`, `Jmin`, `Jmax`, `S1-S4` and `H1-H4` exactly as configured. The
  `a-b` range syntax for `H1-H4` is preserved and never collapsed to a single
  value.
- Pass through `I1-I5`, `HeaderProtectionKey`, `ContentPaddingAddition`, the
  timing ranges, `RandomTrailers` and `DisableCookies` when your server uses them.
- Derive a safe MTU from the AmneziaWG per-packet overhead, which plain
  WireGuard defaults get wrong. See
  [MTU and the AmneziaWG per-packet prefix](docs/NETWORKING.md#mtu-and-the-amneziawg-per-packet-prefix).
- Support IPv4 and IPv6 destinations.
- Serve SOCKS5 `CONNECT` and `UDP ASSOCIATE` on `127.0.0.1:10808` with no
  authentication.
- Resolve hostnames inside the tunnel, which is socks5h behaviour.
- Run as a real Windows service with automatic reconnect, sleep and resume
  handling and recovery from network changes.

### It does not

- Change the Windows default gateway.
- Install a `0.0.0.0/0` or `::/0` route, even though `AllowedIPs` contains them.
- Change system DNS settings.
- Change system proxy settings.
- Create a network adapter. It does not use Wintun and installs no driver.
- Fall back to the default Internet connection when the tunnel is down. Requests fail instead.
- Listen anywhere except loopback.
- Support the SOCKS5 `BIND` command.

## Architecture

```
+--------------------------+
| A program you configured |   SOCKS5 CONNECT / UDP ASSOCIATE
+------------+-------------+
             |
             v
+----------------------------------------------------------+
| AWGSocks process                                         |
|                                                          |
|  127.0.0.1:10808                                         |
|  internal/socks5                                         |
|     | Dialer interface, no direct socket                 |
|     v                                                    |
|  internal/awg                                            |
|     | netstack.Net.DialContextTCPAddrPort / ListenUDP    |
|     v                                                    |
|  gVisor userspace TCP/IP stack                           |
|  tunnel address: 10.66.66.2 / fd42:42:42::2              |
|     | IP packets                                         |
|     v                                                    |
|  AmneziaWG device (amneziawg-go)                         |
|  Noise + Jc/Jmin/Jmax + S1-S4 + H1-H4 + I1-I5            |
|     | encrypted and obfuscated UDP                       |
|     v                                                    |
|  conn bind: a regular Windows UDP socket                 |
+-----+----------------------------------------------------+
      |
      | the normal Windows default route, never modified
      v
  AmneziaWG server ---> Internet
```

For the full reasoning, including answers to the architecture review questions,
see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### Why a leak is not possible

The `internal/socks5` package contains no `net.Dial`. Egress happens only
through an injected `Dialer` interface whose single implementation is the
AmneziaWG tunnel. A test walks the package source at the AST level and fails the
build if that ever changes. When the tunnel is down, a SOCKS5 request is refused
with `0x03 network unreachable`, because there is nowhere else for it to go.

## Requirements

### Runtime

| Item | Requirement |
| --- | --- |
| Operating system | Windows 10 or Windows 11, x64 |
| Extra software | None |
| Drivers | None |
| Privileges | Administrator to install and control the service. The tunnel itself needs none. |

`awgsocks.exe` is a single file. It needs no DLLs and no runtime libraries
beside it.

### Build time

| Item | Requirement |
| --- | --- |
| Go | 1.25.0 or newer |
| Git | Optional for `scripts\build.bat`, which uses it to stamp the commit and its date into the binary. Required by `scripts\package.bat` |
| MinGW-w64 | Only to run `go test -race`, see [docs/TESTING.md](docs/TESTING.md) |

It builds with `CGO_ENABLED=0`. Every Windows specific call goes through
`golang.org/x/sys/windows`.

## Pinned upstream versions

| Component | Version | Commit |
| --- | --- | --- |
| `github.com/amnezia-vpn/amneziawg-go/v3` | `v3.1.20260828` | `b5928efb6ca19f0153958460c3d141f04abc5c2e` |
| `github.com/amnezia-vpn/amneziawg-windows/v3` | `v3.1.20260814` | `e90531d15802cb976773f3b63443bc281f738ca3` |
| `gvisor.dev/gvisor` | `v0.0.0-20231202080848-1f7806d17489` | pinned by amneziawg-go |
| `github.com/Microsoft/go-winio` | `v0.6.2` | - |
| Wintun | not used | - |

At runtime:

```bat
.\awgsocks.exe version
```

Why these versions, and what to update when bumping them, is in
[docs/UPSTREAM.md](docs/UPSTREAM.md).

## Download

Built releases are on the [releases page](../../releases/latest): one zip
holding `awgsocks.exe` and the six service scripts. Before unpacking, compare
the zip against the value in the release's `SHA256SUMS.txt`, from PowerShell in
the folder you downloaded it to:

```powershell
Get-FileHash -Algorithm SHA256 .\awgsocks-*-windows-amd64.zip
```

Where you unpack it barely matters, because installing copies the executable
into `C:\ProgramData\AWGSocks` and runs the service from that copy. The
reason is under [Installing](docs/SERVICE.md#installing).

Building it yourself is the next section and needs nothing but Go.

## Building

```bat
scripts\build.bat
```

or by hand:

```powershell
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go build -trimpath -ldflags="-s -w" -o awgsocks.exe .\cmd\awgsocks
```

Checks:

```bat
scripts\test.bat
```

The same zip a release carries:

```bat
scripts\package.bat
```

It clones the repository into a temporary directory, builds the committed
`HEAD` there, and writes `awgsocks-<version>-windows-amd64.zip` and
`SHA256SUMS.txt` to `release\`. Working in a fresh clone means nothing
uncommitted can end up in the zip. `-Ref <tag>` packages a tag instead.

The zip is reproducible: packaging the same commit again gives the same
SHA256, so anyone can check that a release was built from its tag. The build
date inside the executable and the timestamps inside the zip are the commit
date, and the Go toolchain is pinned in `scripts\package.ps1`, which downloads
it when a different version is installed.

The service scripts live in `windows\` in the source tree. They expect
`awgsocks.exe` beside them, which is how the zip lays them out.

## Quick start

Six scripts sit next to `awgsocks.exe`. Each one asks for Administrator rights
itself, so double clicking is enough.

| Script | What it does |
| ------ | ------------ |
| `service-install.bat` | Validates your configuration, installs the service and starts it, then checks that the proxy really answers |
| `service-start.bat` | Starts an already installed service and waits for the proxy to answer |
| `service-stop.bat` | Stops the tunnel and closes the proxy port, leaving the service installed |
| `service-status.bat` | Shows the tunnel and proxy state, which applications are using the proxy, and whether any of them is also going out directly |
| `service-config.bat` | Opens the settings file, then applies the change and reports what took effect |
| `service-uninstall.bat` | Stops and removes the service and deletes `C:\ProgramData\AWGSocks`, after asking |

`service-install.bat` uses a single `.conf` file sitting next to it. If there
is none, or more than one, it opens a file picker, starting in the official
AmneziaVPN client's configuration folder when that client is installed.

That is the whole setup. Point a program at `127.0.0.1:10808` as a SOCKS5
proxy with no authentication, and turn on whatever its setting is called for
resolving hostnames through the proxy. Without that the program resolves names
itself and leaks them outside the tunnel.

To confirm it works, run the [quick leak check](#testing).

> [!NOTE]
> `service-uninstall.bat` deletes the copy of your configuration that the
> service runs from, under `C:\ProgramData\AWGSocks`. The original `.conf`
> file you installed from is never touched.

[docs/SERVICE.md](docs/SERVICE.md) covers the same steps run by hand.

## Security model

| Area | Implementation |
| --- | --- |
| Proxy reachability | `127.0.0.1` only. A non-loopback address is rejected both in configuration validation and in the listener. |
| Proxy authentication | None, and none is needed: the proxy is reachable only from the local machine. No password is stored. |
| UDP relay reachability | Loopback only, and a wrapper refuses to send a reply to any non-loopback address. |
| Management interface | The `\\.\pipe\AWGSocks` named pipe only. There is no TCP management port. |
| Pipe ACL | LocalSystem, Administrators, and the account the process runs as. Nobody else. |
| File permissions | `C:\ProgramData\AWGSocks` and its contents use `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` with inheritance disabled. The one exception is `config.json`, which any local user may read and only SYSTEM and Administrators may write, because it holds no key material. |
| Service binary | `C:\ProgramData\AWGSocks\awgsocks.exe` under the same ACL, so a LocalSystem service is never launched from a user writable directory. |
| Key storage | `config.json` holds no keys. `client.conf` is the only place. |
| Logging | Every line passes a redaction filter before it is written. Labelled key assignments, 64 character hex strings and 44 character base64 keys become `[REDACTED]`, at DEBUG level too. |
| Command execution | Nothing from the configuration file is ever executed. |
| Service account | LocalSystem. The tunnel itself needs no extra privilege. |

## Testing

Automated tests, leak tests and manual verification steps are in
[docs/TESTING.md](docs/TESTING.md).

Quick leak check:

```bat
curl.exe --proxy socks5h://127.0.0.1:10808 https://api.ipify.org
curl.exe https://api.ipify.org
```

The first should print your VPN server address, the second your ISP address.

```bat
.\awgsocks.exe stop
curl.exe --proxy socks5h://127.0.0.1:10808 https://api.ipify.org
```

This must fail. If it prints your ISP address, there is a leak.

## Known limitations

| Limitation | Detail |
| --- | --- |
| No SOCKS5 BIND | `CONNECT` and `UDP ASSOCIATE` are supported, `BIND` is not. Few clients need it. |
| UDP fragmentation | SOCKS5 UDP datagrams with a non-zero `FRAG` field are dropped, as RFC 1928 permits. No common client uses it. |
| Endpoint hostname resolution | When `Endpoint` is a hostname it is resolved by the Windows resolver before the tunnel exists. Use an IP address to avoid that. |
| DNS search domains | Non-IP entries in `DNS` are treated as search domains and are not applied. A warning is emitted. |
| ICMP | You cannot ping through the proxy, because SOCKS5 carries no ICMP. |
| Single tunnel | One service instance runs one AmneziaWG configuration. |
| One configuration, one client | A `.conf` cannot be connected in AWGSocks and in another client at the same time, because two clients with one key take the server session from each other. AWGSocks pauses while it sees that happen; see [TROUBLESHOOTING](docs/TROUBLESHOOTING.md#everything-loses-its-connection-while-another-vpn-app-is-connected). |
| Packet counters | The AmneziaWG UAPI exposes byte counters only, so `status` reports bytes rather than packets. |
| I1-I5 validation | The syntax of these can only be checked by the upstream device, which the `awgsocks check` dry run does. |
| `range<uint16>` parameters | The official documentation types `ContentPaddingAddition` and the timing parameters as `range<uint16>` while the pinned upstream accepts `range<uint32>`. AWGSocks follows upstream and warns above 65535. |
| Default UDP bind | The official AmneziaWG Windows client uses the Registered I/O bind; AWGSocks defaults to standard UDP sockets. See [Choosing udp_bind](docs/CONFIGURATION.md#choosing-udp_bind). |

## Documentation

| Document | What is in it |
| --- | --- |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Every `.conf` and `config.json` setting, `udp_bind`, hot reload |
| [docs/SERVICE.md](docs/SERVICE.md) | Installing, running and removing the service by hand, and reading `status` |
| [docs/NETWORKING.md](docs/NETWORKING.md) | DNS, UDP and routing behaviour, and the MTU derivation |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Symptoms and their causes |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How the tunnel, the netstack and the proxy fit together |
| [docs/TESTING.md](docs/TESTING.md) | The test suite, the leak tests and the benchmarks |
| [docs/UPSTREAM.md](docs/UPSTREAM.md) | Which upstream commits are pinned and how to move them |

## License

MIT. See [LICENSE](LICENSE).

This project uses AmneziaWG and WireGuard unmodified. "WireGuard" is a
registered trademark of Jason A. Donenfeld.
