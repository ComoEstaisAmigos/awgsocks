// Command awgsocks runs a real AmneziaWG client tunnel in userspace and
// exposes it as a loopback-only SOCKS5 proxy.
//
// It is an application-scoped VPN: only programs configured to use
// 127.0.0.1:10808 are tunnelled. Windows routing, the default gateway, system
// DNS and the system proxy settings are never modified.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ComoEstaisAmigos/awgsocks/internal/awg"
	"github.com/ComoEstaisAmigos/awgsocks/internal/config"
	"github.com/ComoEstaisAmigos/awgsocks/internal/ipc"
	"github.com/ComoEstaisAmigos/awgsocks/internal/logging"
	"github.com/ComoEstaisAmigos/awgsocks/internal/service"
	"github.com/ComoEstaisAmigos/awgsocks/internal/version"
	"github.com/ComoEstaisAmigos/awgsocks/internal/winsys"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	// When launched by the SCM, run as a service regardless of arguments.
	if service.IsWindowsService() {
		return runService()
	}

	if len(args) == 0 {
		// A double click gets a console of its own that closes the moment this
		// returns, so the usage text would flash past unread. Say what to do
		// instead, and hold the window open long enough to read it.
		if winsys.OwnsConsole() {
			doubleClickHelp(os.Stdout, exeDir())
			waitForEnter(os.Stdin)
			return 0
		}
		usage(os.Stdout)
		return 0
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "-h", "--help", "help":
		usage(os.Stdout)
		return 0
	case "version", "--version", "-v":
		fmt.Print(version.String())
		return 0
	case "service":
		return runService()
	case "run":
		return cmdRun(rest)
	case "check":
		return cmdCheck(rest)
	case "install":
		return cmdInstall(rest)
	case "uninstall":
		return cmdUninstall(rest)
	case "repair":
		fmt.Println("Repairing the permissions under the AWGSocks data directory:")
		return report(service.RepairPermissions())
	case "start":
		return report(service.StartService())
	case "stop":
		return report(service.StopService())
	case "restart":
		return report(service.RestartService())
	case "status":
		return cmdStatus(rest)
	case "reload":
		return cmdPipe(ipc.CmdReload)
	case "reconnect":
		return cmdPipe(ipc.CmdReconnect)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		usage(os.Stderr)
		return 2
	}
}

// helperScripts are the operator scripts shipped beside the executable, in the
// order someone needs them.
var helperScripts = []struct{ name, what string }{
	{"service-install.bat", "install the service and start it"},
	{"service-start.bat", "start a service that is already installed"},
	{"service-stop.bat", "stop the tunnel and close the proxy port"},
	{"service-status.bat", "show the tunnel, the proxy, and a leak check"},
	{"service-config.bat", "change settings and apply them"},
	{"service-uninstall.bat", "remove the service and its data"},
}

// selfInvocation is how to name this executable in a command someone is meant
// to copy and run from the folder it sits in.
//
// The leading .\ is not decoration. PowerShell never looks in the current
// directory for an executable, so a bare awgsocks.exe is reported as an unknown
// command there, and cmd stops looking there too once
// NoDefaultCurrentDirectoryInExePath is set. The .\ form is found by both,
// unconditionally.
const selfInvocation = `.\awgsocks.exe`

// doubleClickHelp is what someone sees when they double click the executable in
// Explorer. They are not looking for a command reference at that point, they
// are looking for the thing to click instead.
//
// It lists only the scripts that are really there. The executable travels on its
// own easily enough, copied out of its folder or pulled alone from a release,
// and pointing at files that are not present would be worse than saying nothing.
func doubleClickHelp(w io.Writer, dir string) {
	fmt.Fprint(w, "awgsocks.exe: This is a command line program, so double clicking it does nothing on its own.\n\n")

	if present := helperScriptsIn(dir); len(present) > 0 {
		fmt.Fprint(w, "For everyday use, run one of the scripts sitting next to this file:\n\n")
		for _, s := range present {
			fmt.Fprintf(w, "  %-23s %s\n", s.name, s.what)
		}
		fmt.Fprint(w, "\nTo drive it by hand instead, open an Administrator prompt in this folder\nand run:\n\n  "+selfInvocation+" --help\n\n")
		return
	}

	fmt.Fprint(w, "Open an Administrator prompt in this folder and run:\n\n  "+selfInvocation+" --help\n\n")
}

// helperScriptsIn returns the helper scripts that exist in dir.
func helperScriptsIn(dir string) []struct{ name, what string } {
	if dir == "" {
		return nil
	}
	var present []struct{ name, what string }
	for _, s := range helperScripts {
		if _, err := os.Stat(filepath.Join(dir, s.name)); err == nil {
			present = append(present, s)
		}
	}
	return present
}

// exeDir is the folder the running executable sits in, or "" if that cannot be
// determined.
func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exe)
}

// waitForEnter holds open a console that would otherwise close the instant this
// returns, taking the message with it. It waits silently: the window staying
// put is the point, and a prompt line would only add noise to a message whose
// whole job is to be short. It returns on the first line, or straight away if
// there is nothing to read from.
func waitForEnter(r *os.File) {
	var scratch [1]byte
	for {
		n, err := r.Read(scratch[:])
		if err != nil || n == 0 || scratch[0] == '\n' {
			return
		}
	}
}

func usage(w *os.File) {
	fmt.Fprintf(w, `AWGSocks %s - an AmneziaWG userspace tunnel exposed as a local SOCKS5 proxy

Usage:
  awgsocks <command> [options]

Commands:
  version                      Print the version and the pinned upstream identities
  check --config <file>        Validate a configuration (dry run, sends no packets)
  install --config <file>      Install the Windows service
  uninstall [--purge]          Remove the Windows service
  start | stop | restart       Control the service
  status [--json]              Show service, tunnel and SOCKS5 state
  reload                       Reload the configuration without dropping a healthy tunnel
  reconnect                    Force a fresh AmneziaWG handshake
  repair                       Put the data directory permissions back as installed
  run [--config <file>]        Run in the foreground, for debugging

install options:
  --config <file>              AmneziaWG .conf file (required)
  --in-place                   Use the file where it is instead of copying it to ProgramData
  --socks <address>            SOCKS5 listen address (default %s)
  --log-level <level>          debug|info|warn|error (default %s)
  --no-autostart               Do not bring the tunnel up when the service starts
  --start                      Start the service once it is installed

Notes:
  - SOCKS5 binds a loopback address only and uses no authentication.
  - The Windows default route, gateway, system DNS and system proxy settings are
    never modified. This is not a system wide VPN.
  - install, uninstall, start, stop, restart, status, reload, reconnect and
    repair all require Administrator privileges.
  - Use repair if Explorer was allowed to "grant permanent access" to
    C:\ProgramData\AWGSocks. That hands the interactive user Full control of
    the directory the LocalSystem service runs from, which repair undoes.

`, version.Version, config.DefaultSocksListen, config.DefaultLogLevel)
}

func report(err error) int {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// service / run
// ---------------------------------------------------------------------------

func runService() int {
	app, _ := config.LoadApp("")
	level := logging.LevelInfo
	if app != nil {
		if l, err := logging.ParseLevel(app.LogLevel); err == nil {
			level = l
		}
	}
	log, err := logging.New(logging.Options{
		Dir:   config.LogDir(),
		Level: level,
	})
	if err != nil {
		// The service must keep running even if the log file cannot be opened.
		fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
	}
	defer log.Close()

	if err := service.RunService(log, ""); err != nil {
		log.Errorf("%v", err)
		return 1
	}
	return 0
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	confPath := fs.String("config", "", "AmneziaWG .conf file (empty uses the one named in config.json)")
	appPath := fs.String("app-config", "", "path to config.json")
	levelName := fs.String("log-level", "", "debug|info|warn|error")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	level := logging.LevelInfo
	if *levelName != "" {
		l, err := logging.ParseLevel(*levelName)
		if err != nil {
			return report(err)
		}
		level = l
	}

	log, err := logging.New(logging.Options{
		Dir:     config.LogDir(),
		Level:   level,
		Console: os.Stdout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
	}
	defer log.Close()

	// With --config given, point the runtime at a throwaway config.json so
	// that an arbitrary .conf can be used without touching the installed one.
	appCfgPath := *appPath
	if *confPath != "" {
		tmp, err := writeTempAppConfig(*confPath, *levelName)
		if err != nil {
			return report(err)
		}
		defer os.Remove(tmp)
		appCfgPath = tmp
	}

	mgr := service.NewManager(log, appCfgPath)
	if err := mgr.Start(); err != nil {
		log.Errorf("%v", err)
		return 1
	}

	fmt.Println("AWGSocks is running in the foreground. Press Ctrl+C to stop.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	fmt.Println("\nShutting down...")
	mgr.Stop()
	return 0
}

// writeTempAppConfig builds a throwaway config.json so that `run --config` can
// point at an arbitrary .conf without touching the installed configuration.
func writeTempAppConfig(confPath, level string) (string, error) {
	app := config.DefaultApp()
	app.ConfigPath = confPath
	if level != "" {
		app.LogLevel = level
	}
	if err := app.Normalize(); err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "awgsocks-*.json")
	if err != nil {
		return "", err
	}
	path := f.Name()
	f.Close()
	if err := app.Save(path); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

func cmdCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	confPath := fs.String("config", "", "AmneziaWG .conf file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path := *confPath
	if path == "" && fs.NArg() > 0 {
		path = fs.Arg(0)
	}
	if path == "" {
		if app, err := config.LoadApp(""); err == nil {
			path = app.ConfigPath
		} else {
			path = config.TunnelConfigPath()
		}
	}

	log, _ := logging.New(logging.Options{Level: logging.LevelError, Console: os.Stderr})
	defer log.Close()

	tun, err := config.LoadTunnel(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid configuration: %v\n", err)
		return 1
	}

	fmt.Printf("File           : %s\n", tun.Path)
	fmt.Printf("AWG generation : %s\n", tun.Generation)
	fmt.Printf("Tunnel address : %s\n", joinPrefixes(tun))
	fmt.Printf("DNS            : %s\n", joinAddrs(tun))
	fmt.Printf("MTU            : %d\n", tun.MTU)
	fmt.Printf("Endpoint       : %s\n", tun.Endpoint())
	if len(tun.AWGParams) > 0 {
		fmt.Printf("AWG parameters : %s\n", strings.Join(tun.AWGParams, ", "))
	} else {
		fmt.Printf("AWG parameters : none (plain WireGuard)\n")
	}
	for i := range tun.Config.Peers {
		p := &tun.Config.Peers[i]
		var allowed []string
		for _, a := range p.AllowedIPs {
			allowed = append(allowed, a.String())
		}
		fmt.Printf("Peer #%d        : AllowedIPs=%s, PresharedKey=%v\n",
			i+1, strings.Join(allowed, ","), !p.PresharedKey.IsZero())
	}
	for _, w := range tun.Warnings {
		fmt.Printf("WARNING        : %s\n", w)
	}

	// Dry run: the configuration is applied to a real AmneziaWG device, but
	// the device is never brought up and not a single packet is sent.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := awg.DryRun(ctx, log, tun); err != nil {
		fmt.Fprintf(os.Stderr, "\nUpstream validation failed: %v\n", err)
		return 1
	}

	fmt.Printf("\nResult         : valid. Accepted by %s.\n", version.AmneziaWGGoVersion)
	fmt.Printf("AllowedIPs note: 0.0.0.0/0 and ::/0 are accepted but are NEVER installed as Windows routes.\n")
	return 0
}

func joinPrefixes(t *config.Tunnel) string {
	var parts []string
	for _, p := range t.AddressPrefixes {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ", ")
}

func joinAddrs(t *config.Tunnel) string {
	if len(t.DNS) == 0 {
		return "none"
	}
	var parts []string
	for _, a := range t.DNS {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// install / uninstall
// ---------------------------------------------------------------------------

func cmdInstall(args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	confPath := fs.String("config", "", "AmneziaWG .conf file (required)")
	inPlace := fs.Bool("in-place", false, "use the configuration where it is instead of copying it")
	socksAddr := fs.String("socks", "", "SOCKS5 listen address")
	logLevel := fs.String("log-level", "", "debug|info|warn|error")
	noAuto := fs.Bool("no-autostart", false, "do not bring the tunnel up when the service starts")
	start := fs.Bool("start", false, "start the service once it is installed")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path := *confPath
	if path == "" && fs.NArg() > 0 {
		path = fs.Arg(0)
	}
	if *socksAddr != "" {
		if err := config.ValidateLoopbackListen(*socksAddr); err != nil {
			return report(err)
		}
	}
	return report(service.Install(service.InstallOptions{
		ConfigPath:      path,
		InPlace:         *inPlace,
		Socks5Listen:    *socksAddr,
		LogLevel:        *logLevel,
		AutoStartTunnel: !*noAuto,
		StartService:    *start,
	}))
}

func cmdUninstall(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	purge := fs.Bool("purge", false, "delete the whole data directory, including the AmneziaWG configuration")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	return report(service.Uninstall(*purge))
}

// ---------------------------------------------------------------------------
// status / pipe commands
// ---------------------------------------------------------------------------

func cmdPipe(cmd string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	resp, err := ipc.Call(ctx, cmd)
	if err != nil {
		if errors.Is(err, ipc.ErrNotRunning) {
			fmt.Fprintln(os.Stderr, "Error: the AWGSocks service is not running.")
			return 1
		}
		return report(err)
	}
	if !resp.OK {
		fmt.Fprintf(os.Stderr, "Error: %s\n", resp.Error)
		return 1
	}
	if resp.Message != "" {
		fmt.Println(resp.Message)
	}
	return 0
}

func cmdStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the status as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	scmState, scmErr := service.QueryState()
	if scmErr != nil || strings.TrimSpace(scmState) == "" {
		// When the SCM cannot be read, for instance without elevation or in
		// foreground mode, say plainly that the state is unknown.
		scmState = "SCM unreadable"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := ipc.Call(ctx, ipc.CmdStatus)
	if err != nil || resp == nil || !resp.OK || resp.Status == nil {
		if *asJSON {
			printJSON(map[string]any{
				"service": scmState,
				"error":   errString(err, resp),
			})
			return 1
		}
		fmt.Printf("Service state  : %s\n", scmState)
		if scmErr != nil {
			fmt.Printf("SCM error      : %v\n", scmErr)
		}
		fmt.Printf("Tunnel state   : unknown (the management pipe could not be reached)\n")
		if err != nil {
			fmt.Printf("Detail         : %v\n", err)
		}
		fmt.Printf("Note           : the status command requires Administrator privileges.\n")
		return 1
	}

	st := resp.Status
	st.Service = scmState
	if *asJSON {
		printJSON(st)
		return 0
	}
	printStatus(st)
	return 0
}

func errString(err error, resp *ipc.Response) string {
	if err != nil {
		return err.Error()
	}
	if resp != nil && resp.Error != "" {
		return resp.Error
	}
	return "unknown error"
}
