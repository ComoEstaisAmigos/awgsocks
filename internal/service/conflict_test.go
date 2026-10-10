package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ComoEstaisAmigos/awgsocks/internal/awg"
	"github.com/ComoEstaisAmigos/awgsocks/internal/config"
)

// TestMain keeps every test in this package away from the real adapters.
//
// testTunnelConf uses 10.66.66.2, the first client address common WireGuard
// install scripts hand out. A VPN connected on the machine running the tests
// can hold exactly that address, and reading the real adapters would then
// pause every tunnel these tests start. The tests that exercise the pause
// supply adapters of their own.
func TestMain(m *testing.M) {
	hostAddresses = func() ([]hostAddress, error) { return nil, nil }
	os.Exit(m.Run())
}

// fakeAdapters stands in for the Windows adapter list.
type fakeAdapters struct {
	mu   sync.Mutex
	list []hostAddress
}

func (f *fakeAdapters) set(list ...hostAddress) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.list = list
}

func (f *fakeAdapters) read() ([]hostAddress, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]hostAddress(nil), f.list...), nil
}

func withAdapters(f *fakeAdapters) func(*Manager) {
	return func(m *Manager) { m.listAddresses = f.read }
}

func countingStarter(calls *atomic.Int32) func(context.Context, *awg.Tunnel) error {
	return func(ctx context.Context, tun *awg.Tunnel) error {
		calls.Add(1)
		return tun.Start(ctx)
	}
}

// amneziaVPN is what the AmneziaVPN app looked like on the machine this was
// found on, connected with the same .conf the service was installed from: a
// Wintun adapter named AmneziaVPN holding the Address line of that file.
var amneziaVPN = hostAddress{Adapter: "AmneziaVPN", Addr: netip.MustParseAddr("10.66.66.2")}

func TestConfigConflictFindsTheTunnelAddressOnAnAdapter(t *testing.T) {
	tunnel := []netip.Prefix{
		netip.MustParsePrefix("10.66.66.2/32"),
		netip.MustParsePrefix("fd42:42:42::2/128"),
	}
	cases := []struct {
		name    string
		host    []hostAddress
		adapter string
	}{
		{name: "no adapters"},
		{
			name: "unrelated addresses, including a neighbour in the same tunnel subnet",
			host: []hostAddress{
				{Adapter: "Ethernet", Addr: netip.MustParseAddr("192.0.2.10")},
				{Adapter: "Other VPN", Addr: netip.MustParseAddr("10.66.66.3")},
				{Adapter: "Loopback", Addr: netip.MustParseAddr("::1")},
			},
		},
		{
			name:    "the IPv4 tunnel address",
			host:    []hostAddress{{Adapter: "Ethernet", Addr: netip.MustParseAddr("192.0.2.10")}, amneziaVPN},
			adapter: "AmneziaVPN",
		},
		{
			name:    "only the IPv6 tunnel address",
			host:    []hostAddress{{Adapter: "WireGuard", Addr: netip.MustParseAddr("fd42:42:42::2")}},
			adapter: "WireGuard",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hit, found := configConflict(tunnel, c.host)
			if found != (c.adapter != "") || hit.Adapter != c.adapter {
				t.Fatalf("got %v found=%t, want adapter %q", hit, found, c.adapter)
			}
		})
	}
}

// TestSystemHostAddressesReadsTheRealAdapters proves the production reader
// parses what Windows returns, using the one address every machine has.
func TestSystemHostAddressesReadsTheRealAdapters(t *testing.T) {
	host, err := systemHostAddresses()
	if err != nil {
		t.Fatalf("could not read the adapters: %v", err)
	}
	for _, h := range host {
		if h.Addr == netip.MustParseAddr("127.0.0.1") {
			return
		}
	}
	t.Fatalf("127.0.0.1 is not among the %d addresses read: %v", len(host), host)
}

// TestSystemHostAddressesSeesALiveTunnelAdapter is the check against a real
// VPN client, which no automated run can provide. With a client connected, set
// AWGSOCKS_LIVE_TUNNEL_ADDRESS to the Address it was configured with and this
// test requires the production reader to find it on an adapter.
func TestSystemHostAddressesSeesALiveTunnelAdapter(t *testing.T) {
	want := os.Getenv("AWGSOCKS_LIVE_TUNNEL_ADDRESS")
	if want == "" {
		t.Skip("set AWGSOCKS_LIVE_TUNNEL_ADDRESS with a VPN client connected to run this")
	}
	prefix, err := netip.ParsePrefix(want)
	if err != nil {
		addr, aerr := netip.ParseAddr(want)
		if aerr != nil {
			t.Fatalf("AWGSOCKS_LIVE_TUNNEL_ADDRESS is neither an address nor a prefix: %q", want)
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	host, err := systemHostAddresses()
	if err != nil {
		t.Fatalf("could not read the adapters: %v", err)
	}
	hit, found := configConflict([]netip.Prefix{prefix}, host)
	if !found {
		t.Fatalf("%s is on no adapter that is up; read %v", want, host)
	}
	t.Logf("found on adapter %s", hit)
}

// socksConnectReply sends one SOCKS5 CONNECT to an IP literal and returns the
// reply code, which is how a paused tunnel shows itself to a program.
func socksConnectReply(t *testing.T, socksAddr string) byte {
	t.Helper()
	c, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("could not reach the proxy: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(c, greeting); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte{5, 1, 0, 1, 192, 0, 2, 1, 0, 80}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("no SOCKS5 reply: %v", err)
	}
	return reply[1]
}

// TestTunnelPausesWhileItsConfigurationIsConnectedElsewhere is the reported
// failure: the AmneziaVPN app connected with the same .conf while the service
// ran, and every program on the machine kept losing its connection, including
// ones that never used the proxy, until the service was uninstalled.
func TestTunnelPausesWhileItsConfigurationIsConnectedElsewhere(t *testing.T) {
	adapters := &fakeAdapters{}
	var calls atomic.Int32
	m, socksAddr := startManagerWithStarter(t, countingStarter(&calls), withAdapters(adapters))
	if !m.tunnel.Running() {
		t.Fatal("the tunnel did not come up with nothing in conflict, so this test proves nothing")
	}

	adapters.set(amneziaVPN)
	m.networkChanged()

	if m.tunnel.Running() {
		t.Fatal("the tunnel is still running while the same configuration is connected on another adapter")
	}
	by, paused := m.PausedBy()
	if !paused || by.Adapter != "AmneziaVPN" {
		t.Fatalf("PausedBy = %v, %t; want the AmneziaVPN adapter", by, paused)
	}
	if st := m.Status(); !strings.Contains(st.Tunnel.PausedBy, "AmneziaVPN") {
		t.Fatalf("status does not say why the tunnel is down: %+v", st.Tunnel)
	}

	// Paused is not the same as gone: the port stays open and refuses, so a
	// program cannot mistake the pause for a proxy that does not exist and go
	// direct.
	if !portIsOpen(socksAddr) {
		t.Fatal("the SOCKS5 port closed during the pause")
	}
	if rep := socksConnectReply(t, socksAddr); rep != 0x03 {
		t.Fatalf("a request during the pause got SOCKS5 reply %#x, want 0x03 network unreachable", rep)
	}

	// Nor can anyone talk it back up while the other client is connected.
	before := calls.Load()
	var pe pausedError
	if err := m.StartTunnel(); !errors.As(err, &pe) {
		t.Fatalf("StartTunnel during the pause returned %v, want the pause explained", err)
	}
	if m.tunnel.Running() || calls.Load() != before {
		t.Fatal("a manual start brought the tunnel up during the pause")
	}
}

func TestTunnelResumesWhenTheOtherClientDisconnects(t *testing.T) {
	shrinkRetry(t, 10*time.Millisecond, 50*time.Millisecond)

	adapters := &fakeAdapters{}
	var calls atomic.Int32
	m, _ := startManagerWithStarter(t, countingStarter(&calls), withAdapters(adapters))

	adapters.set(amneziaVPN)
	m.networkChanged()
	if m.tunnel.Running() {
		t.Fatal("the tunnel did not pause, so this test proves nothing")
	}

	adapters.set()
	m.networkChanged()
	if _, paused := m.PausedBy(); paused {
		t.Fatal("still paused after the adapter lost the address")
	}
	waitFor(t, 5*time.Second, "the tunnel to come back after the other client disconnected", m.tunnel.Running)
}

// TestServiceStartSendsNoHandshakeWhileTheConfigurationIsConnectedElsewhere
// covers boot order: the other client can connect first, and a single start,
// which handshakes straight away, is enough to take its session.
func TestServiceStartSendsNoHandshakeWhileTheConfigurationIsConnectedElsewhere(t *testing.T) {
	shrinkRetry(t, 10*time.Millisecond, 50*time.Millisecond)

	adapters := &fakeAdapters{}
	adapters.set(amneziaVPN)
	var calls atomic.Int32
	m, socksAddr := startManagerWithStarter(t, countingStarter(&calls), withAdapters(adapters))

	time.Sleep(100 * time.Millisecond)
	if n := calls.Load(); n != 0 {
		t.Fatalf("the tunnel was started %d times while the configuration was connected elsewhere", n)
	}
	if _, paused := m.PausedBy(); !paused {
		t.Fatal("the service started without recording the pause")
	}
	if !portIsOpen(socksAddr) {
		t.Fatal("the SOCKS5 port is closed while paused at start")
	}

	// The settled half of a notification must also end the pause, since that
	// is the only half a burst of notifications is guaranteed to reach.
	adapters.set()
	m.networkSettled()
	waitFor(t, 5*time.Second, "the tunnel to come up once the other client disconnected", m.tunnel.Running)
}

// TestSettledNetworkChangeNeverHandshakesIntoAConflict covers the other half
// of the watcher: a conflict first seen once the notifications settle must
// pause the tunnel, not reconnect it, which would handshake straight into the
// session the other client holds.
func TestSettledNetworkChangeNeverHandshakesIntoAConflict(t *testing.T) {
	adapters := &fakeAdapters{}
	var calls atomic.Int32
	m, _ := startManagerWithStarter(t, countingStarter(&calls), withAdapters(adapters))
	reconnects := m.tunnel.Reconnects()

	adapters.set(amneziaVPN)
	m.networkSettled()

	if m.tunnel.Running() {
		t.Fatal("the tunnel kept running into the conflict")
	}
	if got := m.tunnel.Reconnects(); got != reconnects {
		t.Fatalf("the settled notification reconnected the tunnel (%d -> %d reconnects)", reconnects, got)
	}
}

// TestStopDuringAPauseIsNotUndoneWhenItEnds keeps the end of a pause from
// overriding someone who took the tunnel down on purpose in the meantime.
func TestStopDuringAPauseIsNotUndoneWhenItEnds(t *testing.T) {
	shrinkRetry(t, 10*time.Millisecond, 20*time.Millisecond)

	adapters := &fakeAdapters{}
	var calls atomic.Int32
	m, _ := startManagerWithStarter(t, countingStarter(&calls), withAdapters(adapters))

	adapters.set(amneziaVPN)
	m.networkChanged()
	if err := m.StopTunnel(); err != nil {
		t.Fatalf("StopTunnel failed: %v", err)
	}
	before := calls.Load()

	adapters.set()
	m.networkChanged()
	time.Sleep(200 * time.Millisecond)
	if m.tunnel.Running() || calls.Load() != before || m.RetryPending() {
		t.Fatal("the end of the pause brought back a tunnel that had been stopped on purpose")
	}
}

// TestAPendingRetryStopsForAPause makes sure the boot retry cannot keep
// handshaking into a conflict that appears while it is still trying.
func TestAPendingRetryStopsForAPause(t *testing.T) {
	shrinkRetry(t, 10*time.Millisecond, 20*time.Millisecond)

	adapters := &fakeAdapters{}
	var calls atomic.Int32
	m, _ := startManagerWithStarter(t, failFirst(1<<30, &calls), withAdapters(adapters))
	waitFor(t, time.Second, "a retry to be pending", m.RetryPending)

	adapters.set(amneziaVPN)
	m.networkChanged()
	if m.RetryPending() {
		t.Fatal("a retry is still pending during the pause")
	}
	settled := calls.Load()
	time.Sleep(200 * time.Millisecond)
	if extra := calls.Load() - settled; extra > 1 {
		t.Fatalf("%d start attempts were made during the pause", extra)
	}
}

// TestAnUnrelatedTunnelAdapterDoesNotPause is the other side of the bargain: a
// different VPN connected at the same time is not a conflict, even one whose
// server hands out addresses from the same default subnet.
func TestAnUnrelatedTunnelAdapterDoesNotPause(t *testing.T) {
	adapters := &fakeAdapters{}
	adapters.set(
		hostAddress{Adapter: "Ethernet", Addr: netip.MustParseAddr("192.0.2.10")},
		hostAddress{Adapter: "Other VPN", Addr: netip.MustParseAddr("10.66.66.3")},
	)
	var calls atomic.Int32
	m, _ := startManagerWithStarter(t, countingStarter(&calls), withAdapters(adapters))

	m.networkChanged()
	m.networkSettled()
	if _, paused := m.PausedBy(); paused || !m.tunnel.Running() {
		t.Fatal("an adapter holding a different address paused the tunnel")
	}
}

// TestReloadPausesForAnAddressAlreadyConnectedElsewhere covers a .conf edited
// to the configuration another client on the machine is already using.
func TestReloadPausesForAnAddressAlreadyConnectedElsewhere(t *testing.T) {
	adapters := &fakeAdapters{}
	other := hostAddress{Adapter: "AmneziaVPN", Addr: netip.MustParseAddr("10.66.66.9")}
	adapters.set(other)
	var calls atomic.Int32
	m, _ := startManagerWithStarter(t, countingStarter(&calls), withAdapters(adapters))
	if _, paused := m.PausedBy(); paused {
		t.Fatal("paused before the configuration changed, so this test proves nothing")
	}

	confPath := filepath.Join(config.RootDir(), "client.conf")
	edited := strings.Replace(testTunnelConf, "Address = 10.66.66.2/32", "Address = 10.66.66.9/32", 1)
	if err := os.WriteFile(confPath, []byte(edited), 0o600); err != nil {
		t.Fatalf("could not write the edited configuration: %v", err)
	}
	if _, err := m.Reload(); err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if by, paused := m.PausedBy(); !paused || by != other {
		t.Fatalf("PausedBy after reload = %v, %t; want %v", by, paused, other)
	}
	if m.tunnel.Running() {
		t.Fatal("the tunnel runs with a configuration connected elsewhere")
	}
}
