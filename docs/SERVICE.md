# Service installation and control

Installing, running and removing the Windows service by hand. The scripts in
[Quick start](../README.md#quick-start) run these same commands, so this is what you
want in a script of your own or when something needs diagnosing.

## Installing

> [!IMPORTANT]
> Installing must be run from an elevated command prompt. Validating the
> configuration first does not need one.

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
3. Copies `awgsocks.exe` and the service scripts beside it to
   `C:\Program Files\AWGSocks` and registers the service against that copy.
4. Writes `config.json`. If one is already there, for example after
   `uninstall --keep-settings`, its settings are kept and only `config` is
   pointed at the new `.conf`.
5. Sets the permissions: `C:\ProgramData\AWGSocks` for SYSTEM and
   Administrators, with read access for the service account and write access
   only to `logs`; `config.json` also readable by any local user, because it
   holds no key material; `C:\Program Files\AWGSocks` readable and runnable by
   any user and writable only by SYSTEM and Administrators.
6. Registers the `AWGSocks` service to run as `NT SERVICE\AWGSocks`, with its
   privileges limited to `SeChangeNotifyPrivilege`, automatic start, and
   recovery actions that restart it after an unexpected exit.

The service starts with the other automatic services, not as a delayed one, so
the SOCKS5 port is open within seconds of boot and a program launched at logon
is not refused for the first two minutes. That can be before the network is
usable. When the tunnel cannot come up yet, for example because `Endpoint` is a
hostname that cannot be resolved so early, the service keeps its port open,
refuses requests explicitly, and retries the tunnel: first after a second, then
backing off to once a minute, and at once whenever a network address appears.
In the meantime `status` shows the tunnel `State` as `failed` with the reason
under `Last error`, or as `connecting` while an attempt is under way.

The tunnel also stays down, without a single handshake, while the same
configuration is connected through another client on this machine, such as the
AmneziaVPN app, and comes back when that client disconnects. Two clients with
one key take the server session from each other, which cuts off every program
routed through the other client; see
[Everything loses its connection while another VPN app is connected](TROUBLESHOOTING.md#everything-loses-its-connection-while-another-vpn-app-is-connected).

> [!WARNING]
> Step three is a security measure, not a convenience. If the service binary
> stayed in a directory you can write to, such as the Desktop or Downloads, any
> process running as you could replace it, and the next service start would run
> the replacement as the service account, which can read your private key. The
> binary is therefore copied into a directory only SYSTEM and Administrators can
> write to.
>
> Step six limits the damage if AWGSocks itself were ever compromised. The
> service does not run as LocalSystem, and without `SeImpersonatePrivilege` its
> account has none of the usual routes to SYSTEM. Limiting privileges is a layer
> of defence, not a guarantee.
>
> The consequence: after updating `awgsocks.exe` you must run
> `awgsocks uninstall` and then `awgsocks install` for the service to pick up
> the new version. `service-install.bat` does both, and afterwards the scripts
> in `C:\Program Files\AWGSocks` are the ones to use. The other scripts hand
> over to that copy when run from anywhere else, finding it through the
> service's registered path rather than an environment variable, so a copy a
> standard user can modify is never the one that gets elevated.

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
.\awgsocks.exe repair        Put the file permissions back as installed
.\awgsocks.exe run           Run in the foreground, for debugging
```

### repair

Re-applies the permissions an install sets, and changes nothing else: not
the service registration, not the configuration, not the running tunnel.

It is there for one situation: someone accepted Explorer's offer to grant
permanent access to `C:\ProgramData\AWGSocks`, which opens the private key and
lets `config.json` be replaced. Why that is dangerous, and why `config.json` is
the one file a standard user may read anyway, is in
[Reading and editing it](CONFIGURATION.md#reading-and-editing-it). `repair`
closes the directory again, re-locks `client.conf` and the logs, leaves
`config.json` readable, and puts the permissions on
`C:\Program Files\AWGSocks` back.

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
Failed requests   : 1 (0 names not resolved, 1 could not connect)
Hostname requests : 97
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
Active AWG params : DISABLE_COOKIES=0 H1=301745575-401745574 H2=876826554-976826553 H3=1337755454-1437755454 H4=1776593183-1876593183 JC=10 JMAX=1000 JMIN=50 RANDOM_TRAILERS=0 S1=150 S2=135 S3=107 S4=43

== Versions ==
AWGSocks          : 1.1.0
AmneziaWG         : v3.1.20260828 (commit b5928efb6ca1)
AWG conf parser   : v3.1.20260814 (commit e90531d15802)
Wintun            : not used (userspace gVisor netstack; no Windows adapter is created)
Go                : go1.27.1
UDP bind          : std (conn.NewStdNetBind)
Windows routes    : untouched (this is not a system wide VPN)
```

The `Active AWG params` line is read back **from the running device**, so it is
direct evidence that the configured parameters are actually in effect. The
device always reports `DISABLE_COOKIES` and `RANDOM_TRAILERS`, so they appear
as `0`, meaning off, even when the configuration does not mention them.

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
- Deletes `awgsocks.exe` from `C:\ProgramData\AWGSocks` if an older version
  left it there
- **Keeps `C:\Program Files\AWGSocks`**, so the service can be installed again
  from its scripts; delete that folder by hand to remove the program
- **Keeps `client.conf`** and tells you where it is
- States explicitly that there is no Wintun adapter and no Windows route to
  clean up, because none was ever created

To replace the service without losing the settings in `config.json` or the
logs, which is what `service-install.bat` does when the service is already
installed:

```bat
.\awgsocks.exe uninstall --keep-settings
```

To delete everything including the configuration:

```bat
.\awgsocks.exe uninstall --purge
```

Your default Internet connection is unaffected, because it was never modified.
