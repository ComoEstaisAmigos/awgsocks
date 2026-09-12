# Configuration reference

Every setting AWGSocks reads, in both files: the AmneziaWG `.conf` that describes
the tunnel, and the `config.json` that describes the proxy around it.

## AmneziaWG configuration

`C:\ProgramData\AWGSocks\client.conf` is the file your server produced, and it
is the single source of truth for tunnel parameters.

```ini
[Interface]
PrivateKey = <base64>
Address = 10.66.66.2/32,fd42:42:42::2/128
DNS = 1.1.1.1,1.0.0.1

Jc = 10
Jmin = 50
Jmax = 1000

S1 = 150
S2 = 135
S3 = 107
S4 = 43

H1 = 301745575-401745574
H2 = 876826554-976826553
H3 = 1337755454-1437755454
H4 = 1776593183-1876593183

[Peer]
PublicKey = <base64>
PresharedKey = <base64>
Endpoint = 203.0.113.10:54522
AllowedIPs = 0.0.0.0/0,::/0
```

A fuller example with comments: [config/example.conf](../config/example.conf).

### Supported parameters

| Section | Parameters |
| --- | --- |
| `[Interface]` | `PrivateKey`, `Address`, `DNS`, `MTU`, `ListenPort`, `Table` (only `off`) |
| `[Interface]` AWG | `Jc`, `Jmin`, `Jmax`, `S1-S4`, `H1-H4`, `I1-I5`, `HeaderProtectionKey`, `ContentPaddingAddition`, `RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts`, `RandomTrailers`, `DisableCookies` |
| `[Peer]` | `PublicKey`, `PresharedKey`, `Endpoint`, `AllowedIPs`, `PersistentKeepalive` |

> [!WARNING]
> A parameter outside that list is **not ignored silently**. AWGSocks fails with
> a clear error naming the line. A blunt incompatibility error is better than a
> tunnel that looks connected while not using the protocol behaviour you asked
> for.

`PreUp`, `PostUp`, `PreDown` and `PostDown` are rejected. The service runs as
LocalSystem, so executing commands from a configuration file would be a
privilege escalation path.

## Application configuration

`C:\ProgramData\AWGSocks\config.json`:

```json
{
  "config": "C:\\ProgramData\\AWGSocks\\client.conf",
  "socks5_listen": "127.0.0.1:10808",
  "auto_start": true,
  "log_level": "info",
  "max_connections": 1024,
  "log_max_size_mb": 8,
  "log_max_files": 5,
  "udp_associate": true,
  "udp_bind": "std"
}
```

This file never contains key material.

### Reading and editing it

`C:\ProgramData\AWGSocks` is closed to everyone but SYSTEM and Administrators,
because the service binary sits in it and runs as LocalSystem: anyone able to
replace a file there would get code execution as SYSTEM. Explorer therefore
refuses to open the folder and offers to "grant permanent access".

> [!WARNING]
> Do not accept that offer. It adds your account to the folder with Full
> control, and Full control on a directory carries `FILE_DELETE_CHILD`, which
> lets `awgsocks.exe` be deleted and replaced whatever its own permissions say.
> The next service start would then run the replacement as SYSTEM.
>
> If it was already accepted, undo it from an Administrator prompt:
>
> ```bat
> .\awgsocks.exe repair
> ```

`config.json` itself is readable by any local user, because it holds no key
material, so opening it by its full path needs no elevation:

```bat
notepad C:\ProgramData\AWGSocks\config.json
```

That works even though the folder will not open, because Windows grants bypass
traverse checking by default: the file's own permissions decide.

Writing it does need Administrator, and that is deliberate. `config` names the
`.conf` a LocalSystem service loads, so being able to rewrite this file means
being able to redirect what that service brings up.

The short way to edit it is to double click `service-config.bat`. It asks for
Administrator rights itself, opens the file, and when you close the editor it
applies the change and prints which settings took effect and which need a
restart. That last part matters, because not every field can be applied to a
running process: see
[What a reload can and cannot apply](#what-a-reload-can-and-cannot-apply).

By hand, from an Administrator prompt:

```bat
notepad C:\ProgramData\AWGSocks\config.json
.\awgsocks.exe reload
```

Or to raise an editor from a PowerShell prompt that is not elevated:

```powershell
Start-Process notepad -Verb RunAs -ArgumentList "C:\ProgramData\AWGSocks\config.json"
```

`client.conf` and the log files stay closed to standard users: the first holds
your private key, and the second records every destination reached once
`log_level` is `debug`.

| Field | Meaning |
| --- | --- |
| `config` | Path to the AmneziaWG `.conf` |
| `socks5_listen` | SOCKS5 listen address, must be loopback |
| `auto_start` | Bring the tunnel up when the service starts, retrying until the network allows it |
| `log_level` | `debug`, `info`, `warn`, `error` |
| `max_connections` | Cap on simultaneous SOCKS5 sessions |
| `log_max_size_mb` | Log rotation threshold |
| `log_max_files` | How many rotated logs to keep |
| `udp_associate` | Offer SOCKS5 UDP ASSOCIATE, see [UDP behaviour](NETWORKING.md#udp-behaviour) |
| `udp_bind` | Which upstream UDP bind carries the endpoint: `std` or `rio` |

## Choosing udp_bind

Two upstream implementations can open the AmneziaWG endpoint socket. Both live
in the `conn` package of `amneziawg-go`; AWGSocks writes neither.

| Value | Implementation | Note |
| --- | --- | --- |
| `std` (default) | `conn.NewStdNetBind` | Standard Go UDP sockets, the path amneziawg-go uses on every non-Windows platform |
| `rio` | `conn.NewDefaultBind` = `conn.NewWinRingBind` | Windows Registered I/O ring buffers, what the official AmneziaWG Windows client uses |

The protocol, the cryptography, the obfuscation and the endpoint path are
identical either way. Only the operating system level handling of the UDP socket
differs.

> [!NOTE]
> Why `std` is the default: the RIO bind tears down by closing its completion
> queues, calling `RIODeregisterBuffer`, releasing the ring memory with
> `VirtualFree`, and only **then** closing the socket whose request queue still
> references those registrations (upstream `conn/bind_windows.go`,
> `afWinRingBind.CloseAndZero`). AWGSocks rebinds its UDP socket on every network
> change, sleep and resume, and reconnect, so it runs that teardown far more
> often than a desktop VPN client does. During development one AmneziaWG test
> process died with `STATUS_HEAP_CORRUPTION (0xC0000374)`, and the RIO bind is
> the only component in the process that touches the Windows process heap. The
> fault could not be reproduced afterwards, so this is a precaution rather than
> a proven defect.
>
> What it costs, measured rather than assumed: on the loopback benchmark in
> `internal/e2e` the RIO bind did not move throughput outside run to run
> variance, but it did cut process CPU by roughly a tenth at the same rate. The
> trade is CPU efficiency, not peak speed. Set `"udp_bind": "rio"` and restart
> if you want it. The numbers are in
> [Comparing the two UDP binds](TESTING.md#comparing-the-two-udp-binds).

## Hot reload

```bat
.\awgsocks.exe reload
```

1. The new configuration is parsed and applied to a real AmneziaWG device as a
   dry run.
2. If it is invalid, nothing changes and **the running tunnel is untouched**.
3. If it is valid, it is applied. When the address, DNS and MTU are unchanged,
   the tunnel is updated over UAPI rather than rebuilt.

### What a reload can and cannot apply

Not every field in `config.json` can be changed on a running process. `reload`
prints which category each change fell into, so a setting is never quietly
dropped.

| Field | On reload |
| --- | --- |
| `config` | Applied, the new `.conf` is read |
| `log_level` | Applied |
| `log_max_size_mb`, `log_max_files` | Applied to the open log file |
| `socks5_listen` | Applied, the listener is rebuilt |
| `max_connections` | Applied, the listener is rebuilt |
| `udp_associate` | Applied, the listener is rebuilt |
| `auto_start` | Stored, and takes effect at the next service start |
| `udp_bind` | **Not applied.** Needs `awgsocks restart` |

> [!NOTE]
> Rebuilding the listener closes SOCKS5 sessions that were open, because the
> accept loop sizes its concurrency limit when it starts and a Go channel's
> capacity cannot change afterwards. The tunnel itself is not dropped, so no new
> handshake is needed. `reload` says so when it happens.

`udp_bind` is the one field a reload cannot honour: the bind is chosen when the
AmneziaWG device is built, so changing it means tearing the tunnel down and
handshaking again, which is exactly what `reload` promises not to do. It reports
the change as not applied instead of pretending:

```
no setting in config.json changed
the AmneziaWG configuration was re-applied and a fresh handshake was requested
NOT applied, run `awgsocks restart` for it to take effect: udp_bind std -> rio
```

The AmneziaWG `.conf` is re-applied on every reload whether or not it differs,
which is why that line appears even when nothing changed.
