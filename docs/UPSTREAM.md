# Pinned upstream versions

AWGSocks reimplements no AmneziaWG or WireGuard algorithm. All cryptography and
all obfuscation run in the official upstream code pinned below.

## Pinned versions

| Component | Module | Version | Commit |
| --- | --- | --- | --- |
| AmneziaWG userspace | `github.com/amnezia-vpn/amneziawg-go/v3` | `v3.1.20260828` | `b5928efb6ca19f0153958460c3d141f04abc5c2e` |
| AmneziaWG conf parser and UAPI writer | `github.com/amnezia-vpn/amneziawg-windows/v3` | `v3.1.20260814` | `e90531d15802cb976773f3b63443bc281f738ca3` |
| Wintun Go binding | `golang.zx2c4.com/wintun` | `v0.0.0-20230126152724-0fa3db229ce2` | indirect, never called |
| gVisor netstack | `gvisor.dev/gvisor` | `v0.0.0-20231202080848-1f7806d17489` | pinned by amneziawg-go |
| Windows named pipes | `github.com/Microsoft/go-winio` | `v0.6.2` | - |
| Go toolchain | - | 1.25.0 or newer (developed on 1.27.1) | - |

These must stay identical to the requirements in `go.mod` and the constants in
`internal/version/version.go`. `awgsocks version` prints them at runtime.

## Why this AmneziaWG version

### The target configuration class

The configuration this project was built for carries:

```
Jc, Jmin, Jmax
S1, S2, S3, S4
H1, H2, H3, H4   (range<uint32>)
```

`S3` and `S4` were added upstream by the merge labelled "AmneziaWG v1.5"
(`amneziawg-go` commit `c207898`, 2025-07-07). That makes this an AmneziaWG 1.5
class configuration: an upstream older than 1.5 would not recognise `S3` and
`S4` at all.

### Why 3.1 is pinned rather than 1.5

`v3.1.20260828` supports every 1.5 parameter including `S3` and `S4`, and does
not change their wire format. The features added in 3.x (I1-I5,
HeaderProtectionKey, ContentPaddingAddition, timing ranges, RandomTrailers,
DisableCookies) are **inert** when absent from the configuration, because
upstream reads a zero value as "off":

- `device.junk.count/min/max` default to 0 and `JunkPackets()` returns an empty
  list
- `device.paddings.*` default to 0, so no prefix is added
- `device.headers.*` default to the standard WireGuard message types 1 to 4
- `device.ipackets` defaults to `nil`, so no I packet is sent
- `device.headerProtection.key` defaults to zero and `HeaderProtectionCipher()`
  returns `nil`, so no header encryption happens
- `device.timings.*` default to zero, and every use in `device/timers.go` is
  guarded by `if !t.IsZero()`, falling back to the standard WireGuard constants
- `randomTrailers` and `disableCookies` default to `false`

So with a 1.5 class configuration the 3.1 upstream emits exactly the same
packets a 1.5 upstream would. That keeps compatibility with an existing server
while letting a server upgrade enable newer parameters without a rebuild.

> [!WARNING]
> This does not mean new parameters are added to an old configuration. AWGSocks
> enables no AWG parameter that is not in the configuration file. The
> `Active AWG params` line in `awgsocks status` shows what is actually set on the
> device, read back from the device itself.

## Why the parser is upstream too

The requirement was not to reinterpret AmneziaWG syntax unnecessarily. AWGSocks
therefore imports the `conf` package used by the official AmneziaWG Windows
client directly:

```
client.conf
  -> conf.FromWgQuickWithUnknownEncoding   amneziawg-windows/conf/parser.go
  -> conf.Config                           amneziawg-windows/conf/config.go
  -> conf.ToUAPI                           amneziawg-windows/conf/writer.go
  -> device.IpcSet                         amneziawg-go/device/uapi.go
```

That is the same chain the official client follows in its `tunnel/service.go`.

AWGSocks adds only a **validation** layer in front of it (`internal/config`).
That layer does not parse: it makes errors clearer before parsing and catches
cases upstream could not accept anyway.

| Check | Reason |
| --- | --- |
| An unknown AWG parameter is rejected | Silent ignoring is forbidden |
| Overlapping `H1-H4` ranges are rejected | Upstream `mergeWithDevice` rejects them too, but without a line number |
| `Jmin > Jmax` is rejected | Upstream underflows a uint32 and asks for an enormous allocation |
| `S1-S4 < 12` with `HeaderProtectionKey` is rejected | Upstream applies the same rule |
| `PreUp`, `PostUp`, `PreDown`, `PostDown` are rejected | Running commands under LocalSystem would be a privilege escalation path |
| `Table` accepts only `off` | A configuration asking for system wide routing must not be ignored silently |
| A non-loopback `socks5_listen` is rejected | An unauthenticated proxy must not be exposed to the network |

## The UDP bind implementation

`amneziawg-go` offers two binds on Windows, and AWGSocks can use either
unmodified:

| `udp_bind` | Upstream function | Source |
| --- | --- | --- |
| `std` (default) | `conn.NewStdNetBind` | `conn/bind_std.go` |
| `rio` | `conn.NewDefaultBind` = `conn.NewWinRingBind` | `conn/bind_windows.go` |

`conn.NewDefaultBind()` returns the RIO bind on Windows; AWGSocks selects
`conn.NewStdNetBind()` by default. Why, and what it costs, is in
[Choosing udp_bind](CONFIGURATION.md#choosing-udp_bind).

> [!NOTE]
> Both binds are upstream code and indistinguishable at the protocol level.
> Selecting one is a configuration choice, not a change to upstream behaviour.

## One upstream race worth knowing about

Upstream starts its TUN reader inside `NewDevice`, before `IpcSet` has run, and
that loop captures the transport padding before blocking in `tun.Read`. The
first packet out of a freshly created device is therefore framed without the
`S4` prefix and the peer discards it.

TCP hides it, because the lost packet is a SYN. UDP does not. AWGSocks works
around it by sending one throwaway datagram to a discard address right after the
device comes up; see `primeTransportPadding` in `internal/awg/tunnel.go`.

## No local modifications

None of the upstream modules is forked, patched or vendored with changes.
The versions in `go.mod` are fetched from the official repositories and verified
by `go.sum`.

To confirm:

```bat
go mod verify
go list -m all
```

## Updating the pinned versions

1. Determine the new upstream version and commit SHA.
2. Run `go get github.com/amnezia-vpn/amneziawg-go/v3@<version>`.
3. Update the constants in `internal/version/version.go`.
4. Add any new UAPI keys to the accept list in `internal/config/params.go`.
5. Update `upstreamVersionNote` in `internal/config/tunnel.go`.
6. Run `go test ./...`. The `internal/e2e` test moves real data between two
   AmneziaWG devices, so it also verifies wire compatibility.
