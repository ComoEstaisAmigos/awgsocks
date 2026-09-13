package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc/mgr"

	"github.com/ComoEstaisAmigos/awgsocks/internal/awg"
	"github.com/ComoEstaisAmigos/awgsocks/internal/config"
	"github.com/ComoEstaisAmigos/awgsocks/internal/logging"
	"github.com/ComoEstaisAmigos/awgsocks/internal/socks5"
)

const (
	testPrivateKey = "YK6ykvX+Ql0uI0NcocLtcl53xfgvWCs1xnfjLkKFEFc="
	testPublicKey  = "ODQSPx7PXqCrsYPrVSD8qzBo/GPPS7QzGr2w1FM0j0I="
)

// testTunnelConf uses the AmneziaWG 1.5 parameter class with an endpoint in
// TEST-NET-2, which is reserved for documentation and therefore unreachable.
// The tunnel comes up but never completes a handshake, which is exactly the
// state the fail-closed behaviour must handle.
const testTunnelConf = `[Interface]
PrivateKey = ` + testPrivateKey + `
Address = 10.66.66.2/32,fd42:42:42::2/128
DNS = 1.1.1.1

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
PublicKey = ` + testPublicKey + `
Endpoint = 198.51.100.10:54522
AllowedIPs = 0.0.0.0/0,::/0
`

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not find a free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func writeTestEnvironment(t *testing.T) (appPath, socksAddr string) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("AWGSOCKS_ROOT", root)

	confPath := filepath.Join(root, "client.conf")
	if err := os.WriteFile(confPath, []byte(testTunnelConf), 0o600); err != nil {
		t.Fatalf("could not write the configuration: %v", err)
	}

	socksAddr = fmt.Sprintf("127.0.0.1:%d", freeLoopbackPort(t))

	app := config.DefaultApp()
	app.ConfigPath = confPath
	app.Socks5Listen = socksAddr
	app.AutoStart = true
	if err := app.Normalize(); err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	appPath = filepath.Join(root, "config.json")
	if err := app.Save(appPath); err != nil {
		t.Fatalf("could not write config.json: %v", err)
	}
	return appPath, socksAddr
}

func portIsOpen(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// TestManagerLifecycle exercises the full runtime: start, status, graceful
// stop, and the guarantee that stopping releases the listening port.
func TestManagerLifecycle(t *testing.T) {
	appPath, socksAddr := writeTestEnvironment(t)

	log, err := logging.New(logging.Options{Level: logging.LevelError})
	if err != nil {
		t.Fatalf("could not create the logger: %v", err)
	}
	defer log.Close()

	mgr := NewManager(log, appPath)
	if err := mgr.Start(); err != nil {
		t.Fatalf("could not start the service: %v", err)
	}

	if !portIsOpen(socksAddr) {
		mgr.Stop()
		t.Fatalf("the SOCKS5 port is not open: %s", socksAddr)
	}

	st := mgr.Status()
	if st.Socks5.Listen != socksAddr || !st.Socks5.Listening {
		mgr.Stop()
		t.Fatalf("wrong SOCKS5 status: %+v", st.Socks5)
	}
	if !strings.Contains(st.Tunnel.Generation, "1.5") {
		mgr.Stop()
		t.Fatalf("the AWG generation was not reported: %q", st.Tunnel.Generation)
	}
	if st.Versions.AmneziaWGGo == "" || st.Versions.AmneziaWGCommit == "" {
		mgr.Stop()
		t.Fatal("the upstream version was not reported")
	}
	if !strings.Contains(st.Versions.Wintun, "not used") {
		mgr.Stop()
		t.Fatalf("the Wintun status was reported incorrectly: %q", st.Versions.Wintun)
	}

	mgr.Stop()

	if portIsOpen(socksAddr) {
		t.Fatal("the service stopped but the SOCKS5 port is still open: resource leak")
	}
	// Stopping twice must be safe.
	mgr.Stop()
}

// TestStatusNeverContainsKeyMaterial checks that nothing in the status report
// can carry a private key, preshared key or header protection key.
func TestStatusNeverContainsKeyMaterial(t *testing.T) {
	appPath, _ := writeTestEnvironment(t)

	log, err := logging.New(logging.Options{Level: logging.LevelError})
	if err != nil {
		t.Fatalf("could not create the logger: %v", err)
	}
	defer log.Close()

	mgr := NewManager(log, appPath)
	if err := mgr.Start(); err != nil {
		t.Fatalf("could not start the service: %v", err)
	}
	defer mgr.Stop()

	rendered := fmt.Sprintf("%+v", mgr.Status())
	for _, secret := range []string{
		testPrivateKey,
		"private_key",
		"preshared_key",
		"header_protection_key",
	} {
		if strings.Contains(rendered, secret) {
			t.Errorf("%q appears in the status output", secret)
		}
	}
}

// TestReloadKeepsHealthyTunnelOnInvalidConfig proves an invalid configuration
// never replaces a working tunnel.
func TestReloadKeepsHealthyTunnelOnInvalidConfig(t *testing.T) {
	appPath, socksAddr := writeTestEnvironment(t)

	log, err := logging.New(logging.Options{Level: logging.LevelError})
	if err != nil {
		t.Fatalf("could not create the logger: %v", err)
	}
	defer log.Close()

	mgr := NewManager(log, appPath)
	if err := mgr.Start(); err != nil {
		t.Fatalf("could not start the service: %v", err)
	}
	defer mgr.Stop()

	confPath := filepath.Join(config.RootDir(), "client.conf")
	if err := os.WriteFile(confPath, []byte(testTunnelConf+"\nZZ = 1\n"), 0o600); err != nil {
		t.Fatalf("could not write the broken configuration: %v", err)
	}

	if _, err := mgr.Reload(); err == nil {
		t.Fatal("a broken configuration was accepted")
	}
	if !portIsOpen(socksAddr) {
		t.Fatal("the SOCKS5 listener closed after a failed reload")
	}
	if st := mgr.Status(); !st.Socks5.Listening {
		t.Fatal("the service broke after a failed reload")
	}
}

// TestStopTunnelKeepsListenerOpen documents the fail-closed design: taking the
// tunnel down must not close the SOCKS5 port, so that clients receive an
// explicit SOCKS5 error rather than a connection refusal that some clients
// retry directly.
func TestStopTunnelKeepsListenerOpen(t *testing.T) {
	appPath, socksAddr := writeTestEnvironment(t)

	log, err := logging.New(logging.Options{Level: logging.LevelError})
	if err != nil {
		t.Fatalf("could not create the logger: %v", err)
	}
	defer log.Close()

	mgr := NewManager(log, appPath)
	if err := mgr.Start(); err != nil {
		t.Fatalf("could not start the service: %v", err)
	}
	defer mgr.Stop()

	if err := mgr.StopTunnel(); err != nil {
		t.Fatalf("could not stop the tunnel: %v", err)
	}
	if !portIsOpen(socksAddr) {
		t.Fatal("the SOCKS5 listener closed when the tunnel stopped")
	}
	if st := mgr.Status(); st.Tunnel.State != "stopped" {
		t.Fatalf("the tunnel state should be stopped, got %q", st.Tunnel.State)
	}

	if err := mgr.StartTunnel(); err != nil {
		t.Fatalf("could not restart the tunnel: %v", err)
	}
	if st := mgr.Status(); st.Tunnel.State == "stopped" {
		t.Fatal("the tunnel did not restart")
	}
}

// ---------------------------------------------------------------------------
// Reload: what it applies, and what it must refuse to pretend it applied
// ---------------------------------------------------------------------------

// startTestManager brings up a Manager against a temporary root and registers
// its teardown, so the reload tests below read as the edit they are testing.
func startTestManager(t *testing.T) (mgr *Manager, appPath, socksAddr string) {
	t.Helper()
	appPath, socksAddr = writeTestEnvironment(t)

	log, err := logging.New(logging.Options{Level: logging.LevelError})
	if err != nil {
		t.Fatalf("could not create the logger: %v", err)
	}
	t.Cleanup(func() { log.Close() })

	mgr = NewManager(log, appPath)
	if err := mgr.Start(); err != nil {
		t.Fatalf("could not start the service: %v", err)
	}
	t.Cleanup(mgr.Stop)
	return mgr, appPath, socksAddr
}

// editAppConfig rewrites config.json the way an operator editing the file by
// hand does: load, change one field, save.
func editAppConfig(t *testing.T, appPath string, edit func(*config.App)) {
	t.Helper()
	app, err := config.LoadApp(appPath)
	if err != nil {
		t.Fatalf("could not read config.json: %v", err)
	}
	edit(app)
	if err := app.Normalize(); err != nil {
		t.Fatalf("the edited configuration is invalid: %v", err)
	}
	if err := app.Save(appPath); err != nil {
		t.Fatalf("could not write config.json: %v", err)
	}
}

// TestReloadAppliesMaxConnections is the regression test for the bug this fix
// exists for: max_connections was only read inside the branch that handled a
// socks5_listen change, so editing it alone did nothing and reload still
// answered as though it had worked.
func TestReloadAppliesMaxConnections(t *testing.T) {
	mgr, appPath, socksAddr := startTestManager(t)

	if got := mgr.socks.MaxConns(); got != socks5.ResolveMaxConns(0) {
		t.Fatalf("unexpected starting cap: %d", got)
	}

	editAppConfig(t, appPath, func(a *config.App) { a.MaxConnections = 7 })

	msg, err := mgr.Reload()
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if got := mgr.socks.MaxConns(); got != 7 {
		t.Fatalf("max_connections was not applied, the listener still caps at %d", got)
	}
	if !strings.Contains(msg, "max_connections") {
		t.Errorf("the reload report did not mention max_connections:\n%s", msg)
	}
	// The address did not change, so the port must still be served after the
	// listener was swapped underneath it.
	if !portIsOpen(socksAddr) {
		t.Fatal("the SOCKS5 port is closed after the listener was rebuilt")
	}
}

// TestReloadAppliesUDPAssociate covers the same gap for the other setting that
// lives on the listener. Turning UDP off is the security-relevant direction, so
// it must not be quietly ignored.
func TestReloadAppliesUDPAssociate(t *testing.T) {
	mgr, appPath, socksAddr := startTestManager(t)

	if !mgr.socks.UDPAssociateEnabled() {
		t.Fatal("UDP ASSOCIATE should default to on")
	}

	off := false
	editAppConfig(t, appPath, func(a *config.App) { a.UDPAssociate = &off })

	msg, err := mgr.Reload()
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if mgr.socks.UDPAssociateEnabled() {
		t.Fatal("udp_associate was set to false but the listener still offers UDP ASSOCIATE")
	}
	if !strings.Contains(msg, "udp_associate") {
		t.Errorf("the reload report did not mention udp_associate:\n%s", msg)
	}
	if !portIsOpen(socksAddr) {
		t.Fatal("the SOCKS5 port is closed after the listener was rebuilt")
	}
}

// TestReloadRefusesToPretendAboutUDPBind covers the setting that genuinely
// cannot be applied to a running process, because the bind is chosen when the
// AmneziaWG device is built. The requirement is not that reload applies it, but
// that it never reports success as though it had.
func TestReloadRefusesToPretendAboutUDPBind(t *testing.T) {
	mgr, appPath, _ := startTestManager(t)

	before := mgr.tunnel.BindMode()

	editAppConfig(t, appPath, func(a *config.App) { a.UDPBind = "rio" })

	msg, err := mgr.Reload()
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if got := mgr.tunnel.BindMode(); got != before {
		t.Fatalf("the running tunnel changed bind without a restart: %v -> %v", before, got)
	}
	if !strings.Contains(msg, "udp_bind") {
		t.Fatalf("the reload report did not mention udp_bind at all:\n%s", msg)
	}
	if !strings.Contains(msg, "NOT applied") || !strings.Contains(msg, "restart") {
		t.Fatalf("the reload report did not say the change is not in force:\n%s", msg)
	}

	// docs/CONFIGURATION.md prints this exact message as the worked example of
	// a change reload cannot honour. Asserting it here keeps the documentation
	// from drifting away from the code silently.
	const documented = "no setting in config.json changed\n" +
		"the AmneziaWG configuration was re-applied and a fresh handshake was requested\n" +
		"NOT applied, run `awgsocks restart` for it to take effect: udp_bind std -> rio"
	if msg != documented {
		t.Errorf("the reload report no longer matches docs/CONFIGURATION.md\n got:\n%s\nwant:\n%s", msg, documented)
	}
}

// TestReloadAppliesLogRotation checks the rotation limits reach the open log
// file, which is possible precisely because they belong to the file and not to
// the device.
func TestReloadAppliesLogRotation(t *testing.T) {
	mgr, appPath, _ := startTestManager(t)

	editAppConfig(t, appPath, func(a *config.App) {
		a.LogMaxSizeMB = 3
		a.LogMaxFiles = 9
	})

	msg, err := mgr.Reload()
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	size, files := mgr.log.Rotation()
	if size != 3<<20 || files != 9 {
		t.Fatalf("rotation limits were not applied: size=%d files=%d", size, files)
	}
	if !strings.Contains(msg, "log_max_size_mb") {
		t.Errorf("the reload report did not mention the rotation change:\n%s", msg)
	}
}

// TestReloadReportsAutoStartAsDeferred distinguishes the third outcome: the
// value is stored and correct, it simply has nothing to do until the service
// starts again. Reporting it as applied would be a lie, reporting it as needing
// a restart would send someone to restart for no reason.
func TestReloadReportsAutoStartAsDeferred(t *testing.T) {
	mgr, appPath, _ := startTestManager(t)

	editAppConfig(t, appPath, func(a *config.App) { a.AutoStart = false })

	msg, err := mgr.Reload()
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if !strings.Contains(msg, "auto_start") {
		t.Fatalf("the reload report did not mention auto_start:\n%s", msg)
	}
	if !strings.Contains(msg, "next service start") {
		t.Fatalf("auto_start was not reported as deferred:\n%s", msg)
	}
	if strings.Contains(msg, "NOT applied") {
		t.Fatalf("auto_start was wrongly reported as requiring a restart:\n%s", msg)
	}
}

// TestReloadWithNoChangesSaysSo guards the other direction: a reload that
// changed nothing must not invent a list of things it did.
//
// It also pins the distinction that cost a round of this fix. Tunnel.Reload
// reports "the tunnel adopted this configuration", not "this configuration
// differed": it re-pushes UAPI and kicks a handshake even for a byte identical
// .conf. Folding that into the applied list made every reload claim a change.
func TestReloadWithNoChangesSaysSo(t *testing.T) {
	mgr, _, _ := startTestManager(t)

	msg, err := mgr.Reload()
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if !strings.Contains(msg, "no setting in config.json changed") {
		t.Fatalf("an unchanged reload did not say so:\n%s", msg)
	}
	if strings.Contains(msg, "applied:") {
		t.Fatalf("an unchanged reload claimed it applied something:\n%s", msg)
	}
	if strings.Contains(msg, "NOT applied") {
		t.Fatalf("an unchanged reload invented a restart requirement:\n%s", msg)
	}
	// The tunnel side is re-applied every time, and saying so is the point.
	if !strings.Contains(msg, "re-applied") {
		t.Errorf("the reload did not report the tunnel re-apply:\n%s", msg)
	}
}

// ---------------------------------------------------------------------------
// repair: which file gets which ACL
// ---------------------------------------------------------------------------

// recordingACLs captures the routing decision instead of touching real ACLs,
// so the test can assert it on any machine, elevated or not.
func recordingACLs(dirs, strict, readable *[]string) aclOps {
	return aclOps{
		ensureDir: func(p string) error { *dirs = append(*dirs, p); return nil },
		protect:   func(p string) error { *strict = append(*strict, p); return nil },
		readable:  func(p string) error { *readable = append(*readable, p); return nil },
	}
}

// TestRepairRoutesEachPathToTheRightACL is the test that matters for repair.
// Applying an ACL is already covered in internal/winsys; what is new here is
// deciding which file gets which, and both ways of getting it wrong are bad:
// the readable DACL on client.conf would publish a private key, and the strict
// one on config.json would restore the friction that sends people clicking
// "grant permanent access" in the first place.
func TestRepairRoutesEachPathToTheRightACL(t *testing.T) {
	root := t.TempDir()
	t.Setenv("AWGSOCKS_ROOT", root)

	confPath := filepath.Join(root, "client.conf")
	for _, f := range []string{confPath, filepath.Join(root, "awgsocks.exe")} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatalf("could not create %s: %v", f, err)
		}
	}
	if err := os.MkdirAll(config.LogDir(), 0o755); err != nil {
		t.Fatalf("could not create the log directory: %v", err)
	}
	app := config.DefaultApp()
	app.ConfigPath = confPath
	if err := app.Normalize(); err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if err := app.Save(config.AppConfigPath()); err != nil {
		t.Fatalf("could not write config.json: %v", err)
	}

	var dirs, strict, readable []string
	var out bytes.Buffer
	if err := repairPermissions(&out, recordingACLs(&dirs, &strict, &readable)); err != nil {
		t.Fatalf("repair failed: %v", err)
	}

	wantDirs := []string{root, config.LogDir()}
	if !reflect.DeepEqual(dirs, wantDirs) {
		t.Errorf("directories closed:\n got: %v\nwant: %v", dirs, wantDirs)
	}
	wantStrict := []string{confPath, filepath.Join(root, "awgsocks.exe")}
	if !reflect.DeepEqual(strict, wantStrict) {
		t.Errorf("files locked to SYSTEM and Administrators:\n got: %v\nwant: %v", strict, wantStrict)
	}
	wantReadable := []string{config.AppConfigPath()}
	if !reflect.DeepEqual(readable, wantReadable) {
		t.Errorf("files made user readable:\n got: %v\nwant: %v", readable, wantReadable)
	}
	for _, p := range readable {
		if strings.EqualFold(p, confPath) {
			t.Fatal("client.conf was made readable, which would publish the private key")
		}
	}
}

// TestRepairRefusesWhenNothingIsInstalled keeps repair from reporting success
// on a machine where there is nothing to repair.
func TestRepairRefusesWhenNothingIsInstalled(t *testing.T) {
	t.Setenv("AWGSOCKS_ROOT", filepath.Join(t.TempDir(), "absent"))

	var dirs, strict, readable []string
	var out bytes.Buffer
	err := repairPermissions(&out, recordingACLs(&dirs, &strict, &readable))
	if err == nil {
		t.Fatal("repair claimed success with no data directory")
	}
	if !strings.Contains(err.Error(), "nothing to repair") {
		t.Errorf("unhelpful error for a missing installation: %v", err)
	}
}

// TestRepairSkipsAnInPlaceConfigurationThatIsGone covers the --in-place
// install whose .conf was moved or deleted: repair must secure everything else
// rather than stopping at the first missing path.
func TestRepairSkipsAnInPlaceConfigurationThatIsGone(t *testing.T) {
	root := t.TempDir()
	t.Setenv("AWGSOCKS_ROOT", root)

	app := config.DefaultApp()
	app.ConfigPath = filepath.Join(t.TempDir(), "moved-away.conf")
	if err := app.Normalize(); err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if err := app.Save(config.AppConfigPath()); err != nil {
		t.Fatalf("could not write config.json: %v", err)
	}

	var dirs, strict, readable []string
	var out bytes.Buffer
	if err := repairPermissions(&out, recordingACLs(&dirs, &strict, &readable)); err != nil {
		t.Fatalf("repair stopped at a missing configuration: %v", err)
	}
	if len(strict) != 0 {
		t.Errorf("a path that does not exist was secured: %v", strict)
	}
	if len(readable) != 1 {
		t.Errorf("config.json was not secured: %v", readable)
	}
}

// ---------------------------------------------------------------------------
// Start at boot: no delay, and a tunnel that cannot come up yet is retried
// ---------------------------------------------------------------------------

// TestServiceIsNotDelayedStart is the regression test for the report that the
// service did not start after a reboot. It did, 126 seconds later, because it
// was registered as delayed automatic start, and for those two minutes every
// program launched at logon found the proxy port closed.
func TestServiceIsNotDelayedStart(t *testing.T) {
	cfg := serviceConfig()
	if cfg.StartType != mgr.StartAutomatic {
		t.Errorf("the service must start automatically, got start type %d", cfg.StartType)
	}
	if cfg.DelayedAutoStart {
		t.Error("the service is registered as delayed start, which keeps the proxy port closed for about two minutes after boot")
	}
}

// shrinkRetry makes the start retry fast enough to observe in a test.
func shrinkRetry(t *testing.T, min, max time.Duration) {
	t.Helper()
	oldMin, oldMax := startRetryMin, startRetryMax
	startRetryMin, startRetryMax = min, max
	t.Cleanup(func() { startRetryMin, startRetryMax = oldMin, oldMax })
}

// startManagerWithStarter brings a Manager up with its tunnel start replaced,
// so a test can make the first attempts fail the way they do at boot when the
// network is not usable yet.
func startManagerWithStarter(t *testing.T, starter func(context.Context, *awg.Tunnel) error, configure ...func(*Manager)) (*Manager, string) {
	t.Helper()
	appPath, socksAddr := writeTestEnvironment(t)

	log, err := logging.New(logging.Options{Level: logging.LevelError})
	if err != nil {
		t.Fatalf("could not create the logger: %v", err)
	}
	t.Cleanup(func() { log.Close() })

	m := NewManager(log, appPath)
	m.startTunnel = starter
	for _, c := range configure {
		c(m)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("could not start the service: %v", err)
	}
	t.Cleanup(m.Stop)
	return m, socksAddr
}

// failFirst returns a starter that fails n times, as an unresolvable hostname
// endpoint does before the network is up, and then starts the real tunnel.
func failFirst(n int32, calls *atomic.Int32) func(context.Context, *awg.Tunnel) error {
	return func(ctx context.Context, tun *awg.Tunnel) error {
		if calls.Add(1) <= n {
			return errors.New("simulated: the endpoint cannot be resolved yet")
		}
		return tun.Start(ctx)
	}
}

func waitFor(t *testing.T, within time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", within, what)
}

// TestAutoStartRetriesATunnelThatCouldNotStart is the defect the delayed start
// had been hiding. A failed first start used to be final: the service kept its
// SOCKS5 port open, refused every request, and never tried again.
func TestAutoStartRetriesATunnelThatCouldNotStart(t *testing.T) {
	shrinkRetry(t, 10*time.Millisecond, 50*time.Millisecond)

	var calls atomic.Int32
	m, socksAddr := startManagerWithStarter(t, failFirst(2, &calls))

	// The proxy has to be answering before the tunnel is, so programs get an
	// explicit refusal rather than a closed port while the network comes up.
	if !portIsOpen(socksAddr) {
		t.Fatal("the SOCKS5 port is closed while the tunnel is being retried")
	}

	waitFor(t, 5*time.Second, "the tunnel to come up after two failed starts", func() bool {
		return m.tunnel.Running()
	})
	if got := calls.Load(); got < 3 {
		t.Fatalf("the tunnel is up after %d start attempts, expected the third to succeed", got)
	}
	waitFor(t, time.Second, "the retry to finish", func() bool { return !m.RetryPending() })
}

// TestStopTunnelCancelsPendingRetry keeps an explicit stop from being undone.
// Without it a retry still waiting to bring the tunnel up would do so moments
// after someone had taken it down on purpose.
func TestStopTunnelCancelsPendingRetry(t *testing.T) {
	shrinkRetry(t, 10*time.Millisecond, 20*time.Millisecond)

	var calls atomic.Int32
	m, _ := startManagerWithStarter(t, failFirst(1<<30, &calls))

	waitFor(t, time.Second, "a retry to be pending", m.RetryPending)
	if err := m.StopTunnel(); err != nil {
		t.Fatalf("StopTunnel failed: %v", err)
	}
	if m.RetryPending() {
		t.Fatal("a retry is still pending after the tunnel was stopped on purpose")
	}

	settled := calls.Load()
	time.Sleep(200 * time.Millisecond)
	if extra := calls.Load() - settled; extra > 1 {
		t.Fatalf("%d more start attempts were made after the tunnel was stopped", extra)
	}
	if m.tunnel.Running() {
		t.Fatal("the tunnel came up after it was stopped on purpose")
	}
}

// TestNetworkChangeWakesRetry covers the reason the retry listens for address
// changes: an address appearing is the moment the network has arrived, and
// waiting out a backoff of up to a minute from there would be pointless.
func TestNetworkChangeWakesRetry(t *testing.T) {
	shrinkRetry(t, time.Hour, time.Hour)

	var calls atomic.Int32
	m, _ := startManagerWithStarter(t, failFirst(1, &calls))

	waitFor(t, time.Second, "a retry to be pending", m.RetryPending)
	time.Sleep(50 * time.Millisecond)
	if m.tunnel.Running() {
		t.Fatal("the tunnel came up without being woken, so this test proves nothing")
	}

	m.wakeRetry()
	waitFor(t, 5*time.Second, "the woken retry to bring the tunnel up", func() bool {
		return m.tunnel.Running()
	})
}
