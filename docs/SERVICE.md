# Service installation and control

Installing, running and removing the Windows service by hand. The scripts in
[Quick start](../README.md#quick-start) run these same commands, so this is what you
want in a script of your own or when something needs diagnosing.

## Installing

> [!IMPORTANT]
> The install commands must be run from an elevated command prompt.

### 1. Validate the configuration

```bat
.\awgsocks.exe check --config C:\path\client.conf
```

This parses the file and **applies it to a real AmneziaWG device as a dry run**.
Not a single packet is sent. Anything the device would reject shows up here with
a clear message.

Example output:

```
File           : C:\path\client.conf
AWG generation : AmneziaWG 1.5 (Jc/Jmin/Jmax, S1-S4, H1-H4)
Tunnel address : 10.66.66.2/32, fd42:42:42::2/128
DNS            : 1.1.1.1, 1.0.0.1
MTU            : 1377
Endpoint       : 203.0.113.10:54522
AWG parameters : JC, JMIN, JMAX, S1, S2, S3, S4, H1, H2, H3, H4
Peer #1        : AllowedIPs=0.0.0.0/0,::/0, PresharedKey=true
WARNING        : MTU lowered to 1377 automatically: AmneziaWG adds S4=43 ...

Result         : valid. Accepted by v3.1.20260828.
AllowedIPs note: 0.0.0.0/0 and ::/0 are accepted but are NEVER installed as Windows routes.
```

### 2. Install the service

```bat
.\awgsocks.exe install --config C:\path\client.conf --start
```

Installation:

1. Creates `C:\ProgramData\AWGSocks` and its `logs` subdirectory.
2. Copies the configuration to `C:\ProgramData\AWGSocks\client.conf`
   (`--in-place` keeps it where it is).
3. Copies `awgsocks.exe` to `C:\ProgramData\AWGSocks\awgsocks.exe` and registers
   the service against that copy.
4. Writes `config.json`.
5. Restricts file permissions to SYSTEM and Administrators, except
   `config.json`, which any local user may read because it holds no key
   material.
6. Registers the `AWGSocks` service with automatic start and recovery actions
   that restart it after an unexpected exit.

The service starts with the other automatic services, not as a delayed one, so
the SOCKS5 port is open within seconds of boot and a program launched at logon
is not refused for the first two minutes. That can be before the network is
usable. When the tunnel cannot come up yet, for example because `Endpoint` is a
hostname that cannot be resolved so early, the service keeps its port open,
refuses requests explicitly, and retries the tunnel: first after a second, then
backing off to once a minute, and at once whenever a network address appears.
`status` shows it as not yet connected in the meantime.

> [!WARNING]
> Step three is a security measure, not a convenience. The service runs as
> LocalSystem. If its binary stayed in a directory you can write to, such as the
> Desktop or Downloads, any process running as you could replace it and gain
> code execution as SYSTEM. The binary is therefore copied into a directory only
> SYSTEM and Administrators can write to.
>
> The consequence: after updating `awgsocks.exe` you must run
> `awgsocks uninstall` and then `awgsocks install` for the service to pick up
> the new version.

> [!NOTE]
> Without `--start` the service is installed but **not running**, and nothing
> listens on the SOCKS5 port. A browser then reports only that the proxy refuses
> connections. Run `awgsocks start` after installing.

### Install options

| Option | Meaning |
| --- | --- |
| `--config <file>` | AmneziaWG `.conf` file (required) |
| `--in-place` | Do not copy the configuration into ProgramData |
| `--socks <address>` | SOCKS5 listen address, default `127.0.0.1:10808` |
| `--log-level <level>` | `debug`, `info`, `warn`, `error` |
| `--no-autostart` | Do not bring the tunnel up when the service starts |
| `--start` | Start the service once it is installed |

## Service commands

```bat
.\awgsocks.exe --help        Help
.\awgsocks.exe version       Version and pinned upstream identities
.\awgsocks.exe check         Validate a configuration
.\awgsocks.exe install       Install the service
.\awgsocks.exe uninstall     Remove the service
.\awgsocks.exe start         Start the service
.\awgsocks.exe stop          Stop the service
.\awgsocks.exe restart       Restart the service
.\awgsocks.exe status        Status report
.\awgsocks.exe reload        Reload the configuration
.\awgsocks.exe reconnect     Force a fresh AmneziaWG handshake
.\awgsocks.exe repair        Put the data directory permissions back as installed
.\awgsocks.exe run           Run in the foreground, for debugging
```

### repair

Re-applies the permissions an install sets, and changes nothing else: not
the service registration, not the configuration, not the running tunnel.

It is there for one situation. Explorer cannot open
`C:\ProgramData\AWGSocks` and offers to grant permanent access; accepting
adds the interactive user to that directory with Full control, which carries
`FILE_DELETE_CHILD`. The service binary lives there and runs as LocalSystem,
so from then on it can be replaced by anyone logged in as that user. `repair`
closes the directory again, re-locks `client.conf`, the logs and
`awgsocks.exe`, and leaves `config.json` readable.

See [Reading and editing it](CONFIGURATION.md#reading-and-editing-it) for why
`config.json` is the one file a standard user may read.

### status output

```
== AWGSocks ==
Service state     : running
Uptime            : 12m30s
Configuration     : C:\ProgramData\AWGSocks\client.conf

== SOCKS5 ==
Listen address    : 127.0.0.1:10808
Listening         : yes
Active sessions   : 4
Total sessions    : 152
Rejected          : 0 (non-loopback or over the limit)
Failed requests   : 1
Relayed           : 4.2 MiB sent / 58.1 MiB received
UDP ASSOCIATE     : enabled, 1 active associations, 812 sent / 794 received datagrams (96.4 KiB / 102.1 KiB)

== AmneziaWG tunnel ==
State             : connected
Endpoint          : 203.0.113.10:54522
Last handshake    : 2026-09-11 03:51:02 (43s ago)
Sent              : 5.0 MiB
Received          : 59.3 MiB
Reconnects        : 0
Last error        : -
Tunnel addresses  : 10.66.66.2/32, fd42:42:42::2/128
In-tunnel DNS     : 1.1.1.1, 1.0.0.1
MTU               : 1377
AllowedIPs        : 0.0.0.0/0, ::/0
DNS cache         : 37 entries, 214 hits, 46 coalesced, 39 tunnel queries (87% saved)
AWG generation    : AmneziaWG 1.5 (Jc/Jmin/Jmax, S1-S4, H1-H4)
Active AWG params : H1=301745575-401745574 H2=876826554-976826553
                    H3=1337755454-1437755454 H4=1776593183-1876593183
                    JC=10 JMAX=1000 JMIN=50 S1=150 S2=135 S3=107 S4=43

== Versions ==
AWGSocks          : 1.0.0
AmneziaWG         : v3.1.20260828 (commit b5928efb6ca1)
AWG conf parser   : v3.1.20260814 (commit e90531d15802)
Wintun            : not used (userspace gVisor netstack; no Windows adapter is created)
Go                : go1.27.1
UDP bind          : std (conn.NewStdNetBind)
Windows routes    : untouched (this is not a system wide VPN)
```

The `Active AWG params` line is read back **from the running device**, so it is
direct evidence that the configured parameters are actually in effect.

Add `--json` for machine readable output.

> [!NOTE]
> `status`, `reload` and `reconnect` talk to the management pipe and need
> Administrator privileges.

## Uninstalling

```bat
.\awgsocks.exe uninstall
```

This:

- Stops the service and removes its registration
- Deletes the `logs` directory and `config.json`
- Deletes the service binary copy in ProgramData
- **Keeps `client.conf`** and tells you where it is
- States explicitly that there is no Wintun adapter and no Windows route to
  clean up, because none was ever created

To delete everything including the configuration:

```bat
.\awgsocks.exe uninstall --purge
```

Your default Internet connection is unaffected, because it was never modified.
