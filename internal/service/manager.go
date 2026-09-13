// Package service contains the AWGSocks runtime and its Windows service
// integration.
//
// The runtime owns three things and nothing else:
//
//   - the userspace AmneziaWG tunnel (internal/awg)
//   - the loopback-only SOCKS5 listener (internal/socks5)
//   - the admin-only management pipe (internal/ipc)
//
// It never modifies Windows routing, the default gateway, system DNS or the
// system proxy settings, so starting and stopping AWGSocks cannot change how
// the rest of the machine reaches the Internet.
package service

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ComoEstaisAmigos/awgsocks/internal/awg"
	"github.com/ComoEstaisAmigos/awgsocks/internal/config"
	"github.com/ComoEstaisAmigos/awgsocks/internal/ipc"
	"github.com/ComoEstaisAmigos/awgsocks/internal/logging"
	"github.com/ComoEstaisAmigos/awgsocks/internal/socks5"
	"github.com/ComoEstaisAmigos/awgsocks/internal/version"
	"github.com/ComoEstaisAmigos/awgsocks/internal/winsys"
)

// networkChangeDebounce collapses the burst of address-change notifications
// Windows emits when an adapter comes up.
const networkChangeDebounce = 2 * time.Second

// startRetryMin and startRetryMax bound how often a tunnel that could not be
// brought up when the service started is tried again. They are variables only
// so that tests can shrink them.
//
// The case they exist for is boot. The service starts with the other automatic
// services, which can be before the network is usable, and an Endpoint given
// as a hostname cannot be resolved until it is. Without a retry that first
// failure was final: the SOCKS5 port stayed open refusing every request, and
// nothing tried again until someone restarted the service by hand.
var (
	startRetryMin = time.Second
	startRetryMax = time.Minute
)

// Manager is the AWGSocks runtime.
type Manager struct {
	log        *logging.Logger
	appCfgPath string

	mu      sync.Mutex
	app     *config.App
	tunCfg  *config.Tunnel
	tunnel  *awg.Tunnel
	socks   *socks5.Server
	pipe    *ipc.Server
	watcher *winsys.NetworkWatcher
	started time.Time
	running bool

	// ctx lives as long as the running service. Work started from a shorter
	// lived caller, such as a reload over the pipe, is bound to it instead.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// tunnelWanted records whether the tunnel is meant to be up: auto_start or
	// an explicit start says yes, an explicit stop says no. A pause leaves it
	// alone, which is how the end of a pause knows whether to bring the tunnel
	// back.
	tunnelWanted bool

	// pausedBy is set while the tunnel's own configuration is connected through
	// another client on this machine, and conflictMu serialises the checks that
	// set and clear it. See conflict.go for why the tunnel steps aside.
	pausedBy      *hostAddress
	conflictMu    sync.Mutex
	listAddresses func() ([]hostAddress, error)

	// startMu serialises every attempt to bring the tunnel up. Tunnel.Start
	// checks whether it is running before it builds the device and only records
	// that it is afterwards, so two unserialised callers, the retry loop and a
	// manual start over the pipe, could both build one.
	startMu sync.Mutex

	// retryCancel is non-nil while a start retry is pending, and retryWake
	// nudges it to try at once instead of waiting out its delay.
	retryCancel context.CancelFunc
	retryGen    uint64
	retryWake   chan struct{}

	// startTunnel is how an attempt is made. It is Tunnel.Start in production
	// and a seam for tests that need the first attempts to fail.
	startTunnel func(ctx context.Context, t *awg.Tunnel) error
}

// NewManager creates a runtime that will read its application configuration
// from appCfgPath (empty selects the default location).
func NewManager(log *logging.Logger, appCfgPath string) *Manager {
	return &Manager{
		log:           log,
		appCfgPath:    appCfgPath,
		retryWake:     make(chan struct{}, 1),
		startTunnel:   func(ctx context.Context, t *awg.Tunnel) error { return t.Start(ctx) },
		listAddresses: hostAddresses,
	}
}

// pausedError is what any attempt to bring the tunnel up returns during a
// pause, so that a manual start explains itself instead of silently doing
// nothing, and so that the retry loop can tell a pause from a failure.
type pausedError struct{ by hostAddress }

func (e pausedError) Error() string {
	return fmt.Sprintf("the tunnel is paused because its configuration is connected on the Windows adapter %s, "+
		"and two clients using one key take the session from each other; it resumes when that adapter disconnects",
		e.by)
}

// Start loads configuration and brings up the tunnel, the SOCKS5 listener and
// the management pipe.
//
// The SOCKS5 listener is started even when the tunnel fails to come up. That is
// deliberate: a client then receives an explicit SOCKS5 "network unreachable"
// reply instead of silently falling through to a direct connection.
func (m *Manager) Start() error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return errors.New("the service is already running")
	}
	m.mu.Unlock()

	app, err := config.LoadApp(m.appCfgPath)
	if err != nil {
		return err
	}
	if lvl, err := logging.ParseLevel(app.LogLevel); err == nil {
		m.log.SetLevel(lvl)
	}
	m.log.Infof("%s starting", version.Short())
	m.log.Infof("configuration: %s", app.ConfigPath)

	tunCfg, err := config.LoadTunnel(app.ConfigPath)
	if err != nil {
		return err
	}
	for _, w := range tunCfg.Warnings {
		m.log.Warnf("configuration warning: %s", w)
	}

	bindMode, err := awg.ParseBindMode(app.UDPBind)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())

	tunnel := awg.NewWithBind(m.log, tunCfg, bindMode)
	socksSrv := socks5.NewWithOptions(m.log, tunnel, app.Socks5Listen, app.MaxConnections, app.UDPEnabled())
	pipeSrv := ipc.NewServer(m.log, m)

	m.mu.Lock()
	m.app = app
	m.tunCfg = tunCfg
	m.tunnel = tunnel
	m.socks = socksSrv
	m.pipe = pipeSrv
	m.ctx = ctx
	m.cancel = cancel
	m.started = time.Now()
	m.running = true
	m.tunnelWanted = app.AutoStart
	m.mu.Unlock()

	if app.AutoStart {
		// Checked before the first handshake, not after: the service can start
		// while the same configuration is already connected elsewhere, and one
		// handshake is enough to take the session from that client.
		m.checkConflict()
		if err := m.startTunnelOnce(ctx); err != nil {
			var paused pausedError
			if !errors.As(err, &paused) {
				// The tunnel failed to come up. SOCKS5 still listens and
				// refuses every request explicitly, so nothing leaks silently,
				// and the attempt is repeated rather than abandoned.
				m.log.Errorf("could not start the AmneziaWG tunnel, retrying: %v", err)
				m.retryStart(ctx)
			}
		}
	} else {
		m.log.Infof("auto_start is off: the tunnel is idle, start it with `awgsocks reconnect`")
	}

	if err := socksSrv.Start(); err != nil {
		m.log.Errorf("could not start the SOCKS5 listener: %v", err)
		cancel()
		tunnel.Stop()
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
		return err
	}

	if err := pipeSrv.Start(); err != nil {
		// The proxy keeps working without the management channel.
		m.log.Errorf("could not start the management pipe: %v", err)
	}

	m.startNetworkWatcher(ctx)

	m.log.Infof("AWGSocks ready: SOCKS5 %s -> AmneziaWG %s", socksSrv.Addr(), tunCfg.Endpoint())
	m.log.Infof("Windows routing untouched: default gateway, system DNS and system proxy settings were not modified")
	return nil
}

// startNetworkWatcher reacts to Windows address changes by rebinding the
// AmneziaWG UDP socket. It only observes; it changes no network setting.
func (m *Manager) startNetworkWatcher(ctx context.Context) {
	watcher := winsys.NewNetworkWatcher()
	if err := watcher.Start(); err != nil {
		m.log.Warnf("could not register for network change notifications: %v (handshake monitoring still drives reconnects)", err)
		return
	}
	m.mu.Lock()
	m.watcher = watcher
	m.mu.Unlock()

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		var timer *time.Timer
		var timerC <-chan time.Time
		for {
			select {
			case <-ctx.Done():
				if timer != nil {
					timer.Stop()
				}
				return
			case <-watcher.Events():
				m.networkChanged()
				if timer == nil {
					timer = time.NewTimer(networkChangeDebounce)
				} else {
					timer.Reset(networkChangeDebounce)
				}
				timerC = timer.C
			case <-timerC:
				timerC = nil
				m.networkSettled()
			}
		}
	}()
}

// networkChanged runs on every address notification, before the debounce.
//
// The conflict check cannot wait for the burst to settle. The address that
// reveals another client using this configuration is assigned as that client
// connects, and networkSettled would otherwise answer it two seconds later with
// a handshake that takes the session away from it.
func (m *Manager) networkChanged() {
	m.checkConflict()
}

// networkSettled runs once a burst of address notifications has gone quiet.
func (m *Manager) networkSettled() {
	if m.checkConflict() {
		return
	}
	m.log.Infof("a Windows address changed, reopening the AmneziaWG socket")
	m.mu.Lock()
	t := m.tunnel
	m.mu.Unlock()
	if t != nil && t.Running() {
		t.Reconnect()
	} else {
		// An address appearing is exactly the moment a tunnel that could not
		// start for want of a network might now succeed.
		m.wakeRetry()
	}
}

// startTunnelOnce makes one serialised attempt to bring the tunnel up. It is a
// no-op when the tunnel is already running, which is what lets the retry loop
// and a manual start race harmlessly.
func (m *Manager) startTunnelOnce(ctx context.Context) error {
	m.startMu.Lock()
	defer m.startMu.Unlock()

	m.mu.Lock()
	tunnel := m.tunnel
	pausedBy := m.pausedBy
	m.mu.Unlock()
	if tunnel == nil {
		return errors.New("the service is not running")
	}
	// Read under startMu, the lock pause stops the tunnel under, so an attempt
	// either sees the pause or finishes before pause stops what it built.
	if pausedBy != nil {
		return pausedError{by: *pausedBy}
	}
	if tunnel.Running() {
		return nil
	}
	return m.startTunnel(ctx, tunnel)
}

// checkConflict pauses the tunnel when its own configuration has appeared on a
// Windows adapter, and resumes it once that adapter no longer holds it. It
// reports whether the tunnel is paused afterwards.
func (m *Manager) checkConflict() bool {
	m.conflictMu.Lock()
	defer m.conflictMu.Unlock()

	m.mu.Lock()
	tunCfg, tunnel, list, was := m.tunCfg, m.tunnel, m.listAddresses, m.pausedBy
	m.mu.Unlock()
	if tunCfg == nil || tunnel == nil || list == nil {
		return false
	}

	host, err := list()
	if err != nil {
		// Neither pausing nor resuming on a failed read: keeping the current
		// state is the only choice that is right whichever way it would have
		// gone.
		m.log.Warnf("could not read the Windows adapter addresses, leaving the tunnel as it is: %v", err)
		return was != nil
	}

	hit, found := configConflict(tunCfg.AddressPrefixes, host)
	switch {
	case found && was == nil:
		m.pause(hit)
		return true
	case found:
		m.mu.Lock()
		m.pausedBy = &hit
		m.mu.Unlock()
		return true
	case was != nil:
		m.resume(*was)
	}
	return false
}

// pause takes the tunnel down and keeps it down until resume. The SOCKS5
// listener stays up and refuses requests, exactly as it does for any other
// tunnel that is not running, so nothing is sent outside the tunnel meanwhile.
func (m *Manager) pause(hit hostAddress) {
	m.log.Warnf("this AmneziaWG configuration is also connected on the Windows adapter %s; "+
		"pausing the tunnel so the two clients stop taking the session from each other, "+
		"the proxy refuses requests until that adapter disconnects", hit)
	m.mu.Lock()
	m.pausedBy = &hit
	tunnel := m.tunnel
	m.mu.Unlock()

	m.cancelRetry()
	m.startMu.Lock()
	tunnel.Stop()
	m.startMu.Unlock()
}

// resume ends a pause, and brings the tunnel back only if it is still meant to
// be running. It goes through the retry loop, bound to the service rather than
// to whoever noticed the change, so a start that fails is tried again.
func (m *Manager) resume(was hostAddress) {
	m.mu.Lock()
	m.pausedBy = nil
	wanted := m.tunnelWanted
	ctx := m.ctx
	m.mu.Unlock()

	if !wanted || ctx == nil {
		m.log.Infof("the configuration is no longer connected on the Windows adapter %s; "+
			"the tunnel stays down, as it was not meant to be running", was)
		return
	}
	m.log.Infof("the configuration is no longer connected on the Windows adapter %s, resuming the tunnel", was)
	m.retryStart(ctx)
}

// PausedBy reports the adapter the tunnel is paused for, if it is paused.
func (m *Manager) PausedBy() (hostAddress, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pausedBy == nil {
		return hostAddress{}, false
	}
	return *m.pausedBy, true
}

// retryStart keeps trying to bring the tunnel up in the background, backing
// off from startRetryMin to startRetryMax, until it succeeds, the service
// stops, or someone stops the tunnel on purpose.
func (m *Manager) retryStart(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	m.mu.Lock()
	if m.retryCancel != nil {
		m.retryCancel()
	}
	m.retryGen++
	gen := m.retryGen
	m.retryCancel = cancel
	m.mu.Unlock()

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer m.clearRetry(gen, cancel)

		delay := startRetryMin
		for attempt := 2; ; attempt++ {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-m.retryWake:
				timer.Stop()
			case <-timer.C:
			}

			m.mu.Lock()
			tunnel := m.tunnel
			m.mu.Unlock()
			if tunnel != nil && tunnel.Running() {
				// Brought up by a manual start in the meantime.
				return
			}

			err := m.startTunnelOnce(ctx)
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				m.log.Infof("the AmneziaWG tunnel came up on attempt %d", attempt)
				return
			}
			var paused pausedError
			if errors.As(err, &paused) {
				// Not a failure to back off from: the end of the pause starts
				// a retry of its own.
				return
			}

			if delay *= 2; delay > startRetryMax {
				delay = startRetryMax
			}
			m.log.Warnf("could not start the AmneziaWG tunnel on attempt %d, next attempt within %s: %v",
				attempt, delay, err)
		}
	}()
}

// wakeRetry asks a pending retry to try now. It never blocks: a wake that is
// already queued covers this one.
func (m *Manager) wakeRetry() {
	select {
	case m.retryWake <- struct{}{}:
	default:
	}
}

// cancelRetry abandons a pending retry.
func (m *Manager) cancelRetry() {
	m.mu.Lock()
	cancel := m.retryCancel
	m.retryCancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// clearRetry forgets a retry that has finished, unless a newer one has
// replaced it in the meantime.
//
// The generation is what tells them apart. Comparing the cancel functions
// would not: every function context.WithCancel returns shares one code
// pointer and differs only in its closure, so a finishing old retry would
// match, and erase, the record of its replacement.
func (m *Manager) clearRetry(gen uint64, cancel context.CancelFunc) {
	cancel()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.retryGen == gen {
		m.retryCancel = nil
	}
}

// RetryPending reports whether the tunnel is waiting to be retried.
func (m *Manager) RetryPending() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.retryCancel != nil
}

// Stop shuts the runtime down in the reverse order it was started, so that no
// new SOCKS5 session can be accepted while the tunnel is being torn down.
func (m *Manager) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false
	cancel := m.cancel
	pipeSrv := m.pipe
	socksSrv := m.socks
	tunnel := m.tunnel
	watcher := m.watcher
	m.cancel = nil
	m.mu.Unlock()

	m.log.Infof("AWGSocks shutting down")

	if pipeSrv != nil {
		pipeSrv.Stop()
	}
	if socksSrv != nil {
		socksSrv.Stop()
	}
	if watcher != nil {
		watcher.Stop()
	}
	if cancel != nil {
		cancel()
	}
	m.wg.Wait()
	if tunnel != nil {
		tunnel.Stop()
	}
	m.log.Infof("AWGSocks stopped, no resources left behind")
}

// OnPowerResume is called by the service control handler when Windows resumes
// from sleep or hibernation.
func (m *Manager) OnPowerResume() {
	m.mu.Lock()
	t := m.tunnel
	m.mu.Unlock()
	if t != nil && t.Running() {
		m.log.Infof("the system resumed from sleep, reconnecting AmneziaWG")
		t.Reconnect()
	}
}

// OnPowerSuspend is called when Windows is about to suspend.
func (m *Manager) OnPowerSuspend() {
	m.log.Infof("the system is entering sleep")
}

// ---------------------------------------------------------------------------
// ipc.Handler
// ---------------------------------------------------------------------------

// reloadReport records what a reload did and, more importantly, what it
// deliberately did not do.
//
// Three outcomes are possible for a setting that changed on disk, and the
// operator needs to be able to tell them apart:
//
//	applied      in force now
//	atNextStart  stored, and correct, but with nothing to do until a restart
//	needsRestart changed on disk and NOT in force, a restart is required
type reloadReport struct {
	applied      []string
	atNextStart  []string
	needsRestart []string
	sessionsCut  bool

	// tunnelReapplied records the one thing a reload always does regardless of
	// whether anything differs: it pushes the .conf to the device again and
	// asks for a fresh handshake. It is reported separately from applied,
	// because listing it there would make every reload look like a change.
	tunnelReapplied bool
}

func (r reloadReport) String() string {
	var lines []string
	if len(r.applied) > 0 {
		lines = append(lines, "applied: "+strings.Join(r.applied, ", "))
	} else {
		lines = append(lines, "no setting in config.json changed")
	}
	if r.sessionsCut {
		lines = append(lines, "the SOCKS5 listener was rebuilt, so proxy sessions that were open are now closed")
	}
	if r.tunnelReapplied {
		lines = append(lines, "the AmneziaWG configuration was re-applied and a fresh handshake was requested")
	}
	if len(r.atNextStart) > 0 {
		lines = append(lines, "takes effect at the next service start: "+strings.Join(r.atNextStart, ", "))
	}
	if len(r.needsRestart) > 0 {
		lines = append(lines, "NOT applied, run `awgsocks restart` for it to take effect: "+strings.Join(r.needsRestart, ", "))
	}
	return strings.Join(lines, "\n")
}

// Reload re-reads both configuration files and applies them without dropping a
// healthy tunnel. An invalid configuration leaves the running tunnel untouched.
//
// It returns a human readable account of what happened, which the management
// pipe hands straight back to `awgsocks reload`. That account is the point of
// the signature: not every field in config.json can be applied to a running
// process, and answering "configuration reloaded" to a change that was silently
// dropped is worse than refusing it, because the operator walks away believing
// the new value is in force.
func (m *Manager) Reload() (string, error) {
	m.mu.Lock()
	app := m.app
	tunnel := m.tunnel
	socksSrv := m.socks
	m.mu.Unlock()
	if tunnel == nil {
		return "", errors.New("the service is not running")
	}

	newApp, err := config.LoadApp(m.appCfgPath)
	if err != nil {
		return "", fmt.Errorf("the application configuration is invalid, keeping the current settings: %w", err)
	}
	newTun, err := config.LoadTunnel(newApp.ConfigPath)
	if err != nil {
		return "", fmt.Errorf("the tunnel configuration is invalid, keeping the running tunnel: %w", err)
	}
	for _, w := range newTun.Warnings {
		m.log.Warnf("configuration warning: %s", w)
	}

	var rep reloadReport

	if lvl, err := logging.ParseLevel(newApp.LogLevel); err == nil {
		if app != nil && !strings.EqualFold(newApp.LogLevel, app.LogLevel) {
			rep.applied = append(rep.applied, "log_level")
		}
		m.log.SetLevel(lvl)
	}

	// Rotation limits belong to the open log file, not to the device, so they
	// can be changed in place.
	if app != nil && (newApp.LogMaxSizeMB != app.LogMaxSizeMB || newApp.LogMaxFiles != app.LogMaxFiles) {
		m.log.SetRotation(int64(newApp.LogMaxSizeMB)<<20, newApp.LogMaxFiles)
		rep.applied = append(rep.applied, "log_max_size_mb, log_max_files")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	changed, err := tunnel.Reload(ctx, newTun)
	if err != nil {
		return "", err
	}
	rep.tunnelReapplied = changed
	// Record the new configuration as soon as the tunnel adopts it, so the
	// status report matches reality even if the listener swap below fails.
	m.mu.Lock()
	m.tunCfg = newTun
	m.mu.Unlock()
	// A new .conf can carry a different tunnel address, which can start or end
	// a conflict with a client connected on this machine.
	m.checkConflict()

	// The SOCKS5 listener carries three settings, and none of them can be
	// changed on a running server: the accept loop sizes its semaphore from
	// max_connections and a channel's capacity is fixed once created. So any of
	// the three changing means building a new server, which closes the sessions
	// on the old one. That cost is reported rather than hidden.
	if app != nil && socksSrv != nil {
		var why []string
		if newApp.Socks5Listen != app.Socks5Listen {
			why = append(why, fmt.Sprintf("socks5_listen %s -> %s", app.Socks5Listen, newApp.Socks5Listen))
		}
		if want := socks5.ResolveMaxConns(newApp.MaxConnections); want != socksSrv.MaxConns() {
			why = append(why, fmt.Sprintf("max_connections %d -> %d", socksSrv.MaxConns(), want))
		}
		if newApp.UDPEnabled() != socksSrv.UDPAssociateEnabled() {
			why = append(why, fmt.Sprintf("udp_associate %t -> %t", socksSrv.UDPAssociateEnabled(), newApp.UDPEnabled()))
		}
		if len(why) > 0 {
			m.log.Infof("reload: rebuilding the SOCKS5 listener (%s)", strings.Join(why, "; "))
			newSocks := socks5.NewWithOptions(m.log, tunnel, newApp.Socks5Listen, newApp.MaxConnections, newApp.UDPEnabled())

			if newApp.Socks5Listen != app.Socks5Listen {
				// A different address can be bound while the old listener is
				// still serving, so the new one is proved first and a failure
				// costs nothing.
				if err := newSocks.Start(); err != nil {
					return "", fmt.Errorf("could not bind the new SOCKS5 address, keeping the previous listener: %w", err)
				}
				socksSrv.Stop()
			} else {
				// Same address: Windows will not let two sockets bind one TCP
				// address, so the old listener has to release the port first.
				// There is no way back if the second bind fails, because Stop
				// latches a server closed for good, so the error says plainly
				// that the proxy is down rather than implying a rollback.
				socksSrv.Stop()
				if err := newSocks.Start(); err != nil {
					m.mu.Lock()
					m.socks = newSocks
					m.mu.Unlock()
					return "", fmt.Errorf("the SOCKS5 listener was closed to apply the new settings and %s could not be bound again, the proxy is down until `awgsocks restart`: %w", newApp.Socks5Listen, err)
				}
			}

			m.mu.Lock()
			m.socks = newSocks
			m.mu.Unlock()
			rep.applied = append(rep.applied, why...)
			rep.sessionsCut = true
			changed = true
		}
	}

	// udp_bind is fixed when the AmneziaWG device is built, so honouring a
	// change would mean tearing the tunnel down and handshaking again. Reload
	// promises not to do that, so it says so instead of pretending.
	if app != nil && newApp.UDPBind != app.UDPBind {
		rep.needsRestart = append(rep.needsRestart,
			fmt.Sprintf("udp_bind %s -> %s", app.UDPBind, newApp.UDPBind))
		m.log.Warnf("reload: udp_bind changed to %q but the running tunnel still uses %q, restart the service to apply it",
			newApp.UDPBind, app.UDPBind)
	}

	// auto_start only decides what happens when the service comes up, so it is
	// stored correctly and simply has nothing to do now.
	if app != nil && newApp.AutoStart != app.AutoStart {
		rep.atNextStart = append(rep.atNextStart, fmt.Sprintf("auto_start %t -> %t", app.AutoStart, newApp.AutoStart))
	}

	m.mu.Lock()
	m.app = newApp
	m.mu.Unlock()

	if !changed {
		m.log.Infof("reload: nothing changed")
	}
	return rep.String(), nil
}

// Reconnect forces a fresh AmneziaWG handshake, starting the tunnel first when
// it is not running.
func (m *Manager) Reconnect() error {
	m.mu.Lock()
	tunnel := m.tunnel
	m.mu.Unlock()
	if tunnel == nil {
		return errors.New("the service is not running")
	}
	if !tunnel.Running() {
		return m.StartTunnel()
	}
	tunnel.Reconnect()
	return nil
}

// StartTunnel brings the tunnel up when it is stopped.
func (m *Manager) StartTunnel() error {
	m.mu.Lock()
	tunnel := m.tunnel
	m.mu.Unlock()
	if tunnel == nil {
		return errors.New("the service is not running")
	}
	m.mu.Lock()
	m.tunnelWanted = true
	m.mu.Unlock()
	if tunnel.Running() {
		return nil
	}
	// A pending automatic retry is left alone on purpose. If this attempt
	// fails because the network is still missing, cancelling the retry would
	// leave nothing to try again once it arrives.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	return m.startTunnelOnce(ctx)
}

// StopTunnel takes the tunnel down while leaving the SOCKS5 listener bound, so
// that clients receive an explicit failure instead of a direct connection.
func (m *Manager) StopTunnel() error {
	m.mu.Lock()
	tunnel := m.tunnel
	m.mu.Unlock()
	if tunnel == nil {
		return errors.New("the service is not running")
	}
	// Stopping is a statement that the tunnel should be down, so a retry that
	// is still waiting to bring it up must not override it a moment later, and
	// neither may the end of a pause.
	m.mu.Lock()
	m.tunnelWanted = false
	m.mu.Unlock()
	m.cancelRetry()
	m.startMu.Lock()
	tunnel.Stop()
	m.startMu.Unlock()
	return nil
}

// Status builds the full status report.
func (m *Manager) Status() *ipc.Status {
	m.mu.Lock()
	app := m.app
	tunCfg := m.tunCfg
	tunnel := m.tunnel
	socksSrv := m.socks
	started := m.started
	running := m.running
	pausedBy := m.pausedBy
	m.mu.Unlock()

	st := &ipc.Status{
		Service: "running",
		Versions: ipc.VersionStatus{
			AWGSocks:         version.Version,
			AmneziaWGGo:      version.AmneziaWGGoVersion,
			AmneziaWGCommit:  version.AmneziaWGGoCommit,
			AWGParser:        version.AmneziaWGWindowsVersion,
			AWGParserCommit:  version.AmneziaWGWindowsCommit,
			Wintun:           version.WintunStatus,
			GoVersion:        runtime.Version(),
			SystemRouteState: "untouched (this is not a system wide VPN)",
			UDPBind:          "std (conn.NewStdNetBind)",
		},
	}
	if !running {
		st.Service = "stopped"
	}
	if !started.IsZero() {
		st.Uptime = time.Since(started).Round(time.Second).String()
	}
	if app != nil {
		st.ConfigPath = app.ConfigPath
	}

	if tunCfg != nil {
		st.Tunnel.Generation = tunCfg.Generation
		st.Tunnel.MTU = tunCfg.MTU
		for _, p := range tunCfg.AddressPrefixes {
			st.Tunnel.Addresses = append(st.Tunnel.Addresses, p.String())
		}
		for _, d := range tunCfg.DNS {
			st.Tunnel.DNS = append(st.Tunnel.DNS, d.String())
		}
		st.Warnings = tunCfg.Warnings
	}

	if tunnel != nil {
		st.Versions.UDPBind = tunnel.BindDescription()
		st.Tunnel.State = tunnel.State().String()
		st.Tunnel.Reconnects = tunnel.Reconnects()
		st.Tunnel.LastError = tunnel.LastError()
		st.Tunnel.StartedAt = tunnel.StartedAt()
		if pausedBy != nil {
			st.Tunnel.PausedBy = pausedBy.String()
		}
		ds := tunnel.DNSStats()
		st.Tunnel.DNSCache = ipc.DNSCacheStatus{
			Hits:      ds.Hits,
			Misses:    ds.Misses,
			Coalesced: ds.Coalesced,
			Entries:   ds.Entries,
		}
		if stats, err := tunnel.Stats(); err == nil {
			st.Tunnel.Endpoint = stats.Endpoint
			st.Tunnel.LastHandshake = stats.LastHandshake
			st.Tunnel.TxBytes = stats.TxBytes
			st.Tunnel.RxBytes = stats.RxBytes
			st.Tunnel.AWGParams = stats.AWGParams
			if len(stats.Peers) > 0 {
				st.Tunnel.AllowedIPs = stats.Peers[0].AllowedIPs
			}
		} else if tunCfg != nil {
			st.Tunnel.Endpoint = tunCfg.Endpoint()
		}
	}

	if socksSrv != nil {
		s := socksSrv.Stats()
		st.Socks5 = ipc.SocksStatus{
			Listen:    s.Listen,
			Listening: s.Listening,
			Active:    s.Active,
			Total:     s.Total,
			Rejected:  s.Rejected,
			Failed:    s.Failed,
			BytesUp:   s.BytesToPeer,
			BytesDown: s.BytesToUser,

			UDPEnabled:       s.UDPEnabled,
			UDPAssociations:  s.UDPAssociations,
			UDPDatagramsUp:   s.UDPDatagramsUp,
			UDPDatagramsDown: s.UDPDatagramsDown,
			UDPDropped:       s.UDPDropped,
			UDPBytesUp:       s.UDPBytesUp,
			UDPBytesDown:     s.UDPBytesDown,
		}
	} else if app != nil {
		st.Socks5.Listen = app.Socks5Listen
	}

	return st
}
