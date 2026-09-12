package awg

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ComoEstaisAmigos/awgsocks/internal/config"
	"github.com/ComoEstaisAmigos/awgsocks/internal/logging"
)

const (
	testPrivateKey = "YK6ykvX+Ql0uI0NcocLtcl53xfgvWCs1xnfjLkKFEFc="
	testPublicKey  = "ODQSPx7PXqCrsYPrVSD8qzBo/GPPS7QzGr2w1FM0j0I="
	testPreshared  = "0FMxkxJzb9ChYNbL8pktnkTYiGbTKvpzsKaZZXNY5lY="
)

// userConfig is the AmneziaWG 1.5 configuration class AWGSocks must support.
const userConfig = `[Interface]
PrivateKey = ` + testPrivateKey + `
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
PublicKey = ` + testPublicKey + `
PresharedKey = ` + testPreshared + `
Endpoint = 198.51.100.10:54522
AllowedIPs = 0.0.0.0/0,::/0
`

func testLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l, err := logging.New(logging.Options{Level: logging.LevelError})
	if err != nil {
		t.Fatalf("could not create the logger: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func loadUserConfig(t *testing.T) *config.Tunnel {
	t.Helper()
	tun, err := config.ParseTunnel([]byte(userConfig), filepath.Join(t.TempDir(), "client.conf"))
	if err != nil {
		t.Fatalf("could not parse the configuration: %v", err)
	}
	return tun
}

// TestDryRunAcceptsUserConfiguration proves the pinned upstream AmneziaWG
// implementation really accepts the user configuration class, including the
// H1-H4 range syntax, without sending a packet.
func TestDryRunAcceptsUserConfiguration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := DryRun(ctx, testLogger(t), loadUserConfig(t)); err != nil {
		t.Fatalf("upstream rejected the configuration: %v", err)
	}
}

func TestDryRunRejectsOverlappingHeaders(t *testing.T) {
	// Feed overlapping H ranges straight to the upstream device, bypassing
	// configuration validation, to see that it rejects them.
	tun := loadUserConfig(t)
	tun.Config.Interface.ResponsePacketMagicHeader = "301745500-401745600"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := DryRun(ctx, testLogger(t), tun)
	if err == nil {
		t.Fatal("upstream accepted overlapping H ranges")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "overlap") {
		t.Logf("upstream error: %v", err)
	}
}

func TestTunnelStartsAndFailsClosed(t *testing.T) {
	cfg := loadUserConfig(t)
	tun := New(testLogger(t), cfg)

	// Every egress attempt must fail before the tunnel is up.
	if _, err := tun.DialTCP(context.Background(), netip.MustParseAddrPort("93.184.216.34:80")); !errors.Is(err, ErrTunnelDown) {
		t.Fatalf("expected ErrTunnelDown while the tunnel is down, got %v", err)
	}
	if _, err := tun.LookupHost(context.Background(), "example.com"); !errors.Is(err, ErrTunnelDown) {
		t.Fatalf("expected ErrTunnelDown while the tunnel is down, got %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := tun.Start(ctx); err != nil {
		t.Fatalf("could not start the tunnel: %v", err)
	}
	defer tun.Stop()

	if !tun.Running() {
		t.Fatal("the tunnel should be running")
	}
	if _, err := tun.Stats(); err != nil {
		t.Fatalf("could not read the statistics: %v", err)
	}

	// The endpoint is unreachable, so no handshake completes. The egress
	// attempt must then time out rather than leak.
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()
	_, err := tun.DialTCP(dialCtx, netip.MustParseAddrPort("93.184.216.34:80"))
	if err == nil {
		t.Fatal("a connection was made without a handshake")
	}
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("expected ErrNotReady, got %v", err)
	}
}

func TestStoppedTunnelReleasesEverything(t *testing.T) {
	cfg := loadUserConfig(t)
	tun := New(testLogger(t), cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := tun.Start(ctx); err != nil {
		t.Fatalf("could not start the tunnel: %v", err)
	}
	tun.Stop()

	if tun.Running() {
		t.Fatal("the tunnel still reports as running after being stopped")
	}
	if tun.State() != StateStopped {
		t.Fatalf("the state should be stopped, got %v", tun.State())
	}
	if _, err := tun.Stats(); !errors.Is(err, ErrTunnelDown) {
		t.Fatalf("expected ErrTunnelDown from a stopped tunnel, got %v", err)
	}
	// Stopping twice must be safe.
	tun.Stop()
}

func TestLookupHostWithoutDNSFails(t *testing.T) {
	text := strings.Replace(userConfig, "DNS = 1.1.1.1,1.0.0.1\n", "", 1)
	cfg, err := config.ParseTunnel([]byte(text), filepath.Join(t.TempDir(), "client.conf"))
	if err != nil {
		t.Fatalf("could not parse the configuration: %v", err)
	}
	tun := New(testLogger(t), cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := tun.Start(ctx); err != nil {
		t.Fatalf("could not start the tunnel: %v", err)
	}
	defer tun.Stop()

	if tun.HasDNS() {
		t.Fatal("no DNS should have been configured")
	}
	if _, err := tun.LookupHost(context.Background(), "example.com"); !errors.Is(err, ErrNoDNS) {
		t.Fatalf("expected ErrNoDNS, got %v", err)
	}
}

func TestParseUAPIGetDropsSecrets(t *testing.T) {
	raw := strings.Join([]string{
		"private_key=60aeb292f5fe425d2e23435ca1c2ed725e77c5f82f582b35c677e32e42851057",
		"listen_port=51820",
		"jc=10",
		"jmin=50",
		"jmax=1000",
		"s1=150",
		"h1=301745575-401745574",
		"public_key=3834123f1ecf5ea0abb183eb5520fcab3068fc63cf4bb4331abdb0d453348f42",
		"preshared_key=d0533193127 36fd0a160d6cbf2992d9e44d88866d32afa73b0a699657358e656",
		"endpoint=198.51.100.10:54522",
		"last_handshake_time_sec=1700000000",
		"last_handshake_time_nsec=500",
		"tx_bytes=1234",
		"rx_bytes=5678",
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
		"errno=0",
		"",
	}, "\n")

	st, err := parseUAPIGet(raw)
	if err != nil {
		t.Fatalf("could not parse the UAPI output: %v", err)
	}
	if st.ListenPort != 51820 {
		t.Errorf("wrong listen_port: %d", st.ListenPort)
	}
	if st.AWGParams["jc"] != "10" || st.AWGParams["h1"] != "301745575-401745574" {
		t.Errorf("the AWG parameters were not preserved: %v", st.AWGParams)
	}
	if len(st.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(st.Peers))
	}
	p := st.Peers[0]
	if p.Endpoint != "198.51.100.10:54522" || p.TxBytes != 1234 || p.RxBytes != 5678 {
		t.Errorf("wrong peer fields: %+v", p)
	}
	if p.LastHandshake.Unix() != 1700000000 {
		t.Errorf("wrong handshake timestamp: %v", p.LastHandshake)
	}
	if len(p.AllowedIPs) != 2 {
		t.Errorf("AllowedIPs was not preserved: %v", p.AllowedIPs)
	}

	// No secret may appear in any field.
	for _, secret := range []string{"private_key", "preshared_key", "header_protection_key"} {
		if _, ok := st.AWGParams[secret]; ok {
			t.Errorf("%s leaked into the status output", secret)
		}
	}
}

func TestEndpointNeedsResolution(t *testing.T) {
	cfg := loadUserConfig(t)
	if endpointNeedsResolution(cfg) {
		t.Error("a literal IP endpoint should need no re-resolution")
	}
	cfg.Config.Peers[0].Endpoint.Host = "vpn.example.com"
	if !endpointNeedsResolution(cfg) {
		t.Error("a hostname endpoint should need re-resolution")
	}
}

func TestStackEqual(t *testing.T) {
	a := loadUserConfig(t)
	b := loadUserConfig(t)
	if !stackEqual(a, b) {
		t.Fatal("identical configurations should compare equal")
	}
	b.MTU = 1380
	if stackEqual(a, b) {
		t.Fatal("an MTU change must force the stack to be rebuilt")
	}
}

// allowedNetIdents mirrors the SOCKS5 guard: the tunnel package must not open
// a direct connection to a SOCKS destination either. The only socket it is
// allowed to create is the AmneziaWG UDP endpoint socket, which is created by
// the upstream conn package, not here.
var allowedNetIdents = map[string]bool{
	"Conn":       true, // interface type
	"PacketConn": true, // interface type
	"DNSError":   true, // type used for error classification
}

func TestTunnelPackageHasNoDirectDial(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("could not read the directory: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("could not parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != "net" {
				return true
			}
			if !allowedNetIdents[sel.Sel.Name] {
				t.Errorf("%s: net.%s is forbidden: egress may only go through the netstack",
					fset.Position(sel.Pos()), sel.Sel.Name)
			}
			return true
		})
	}
}
