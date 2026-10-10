// Package e2e proves the complete AWGSocks data path end to end.
//
// The test stands up a second, independent AmneziaWG device on loopback and
// uses it as a real AmneziaWG server. The client side is the production
// AWGSocks stack, unmodified: config parser, tunnel, SOCKS5 listener.
//
//	SOCKS5 client
//	  -> 127.0.0.1:<socks port>          AWGSocks SOCKS5 listener
//	  -> awg.Tunnel.DialTCP              gVisor userspace TCP/IP stack
//	  -> AmneziaWG device (client)       Noise + Jc/Jmin/Jmax + S1-S4 + H1-H4
//	  -> UDP 127.0.0.1:<server port>     regular Windows UDP socket
//	  -> AmneziaWG device (server)       de-obfuscates and decrypts
//	  -> gVisor userspace stack (server) delivers to the in-tunnel HTTP server
//
// Because both devices apply the AmneziaWG obfuscation independently, the test
// can only pass if the obfuscation parameters are genuinely in effect and
// interoperable: a standard WireGuard implementation on either side would see
// unknown message types and drop every packet.
package e2e

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
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

	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"github.com/ComoEstaisAmigos/awgsocks/internal/awg"
	"github.com/ComoEstaisAmigos/awgsocks/internal/config"
	"github.com/ComoEstaisAmigos/awgsocks/internal/logging"
	"github.com/ComoEstaisAmigos/awgsocks/internal/socks5"
)

// The AmneziaWG obfuscation parameters under test. These are the exact values
// from the AWGSocks requirements: an AmneziaWG 1.5 class configuration with
// junk packets, per-message-type random prefixes and H1-H4 ranges.
const (
	paramJc   = 10
	paramJmin = 50
	paramJmax = 1000
	paramS1   = 150
	paramS2   = 135
	paramS3   = 107
	paramS4   = 43
	paramH1   = "301745575-401745574"
	paramH2   = "876826554-976826553"
	paramH3   = "1337755454-1437755454"
	paramH4   = "1776593183-1876593183"
)

const (
	serverV4 = "10.66.66.1"
	clientV4 = "10.66.66.2"
	serverV6 = "fd42:42:42::1"
	clientV6 = "fd42:42:42::2"

	httpPort = 8080
	dnsPort  = 53
	testHost = "test.awgsocks.invalid"
)

type keyPair struct {
	private string // base64
	public  string // base64
}

func (k keyPair) privateHex() string { return b64ToHex(k.private) }
func (k keyPair) publicHex() string  { return b64ToHex(k.public) }

func b64ToHex(s string) string {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(raw)
}

// newKeyPair generates a Curve25519 key pair in the WireGuard encoding.
func newKeyPair(t testing.TB) keyPair {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatalf("could not generate a key: %v", err)
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("could not derive the public key: %v", err)
	}
	return keyPair{
		private: base64.StdEncoding.EncodeToString(priv[:]),
		public:  base64.StdEncoding.EncodeToString(pub),
	}
}

func newPresharedKey(t testing.TB) string {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatalf("could not generate the preshared key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

func testLogger(t testing.TB) *logging.Logger {
	t.Helper()
	opts := logging.Options{Level: logging.LevelError}
	if os.Getenv("AWGSOCKS_TEST_DEBUG") != "" {
		opts.Level = logging.LevelDebug
		opts.Console = os.Stderr
	}
	l, err := logging.New(opts)
	if err != nil {
		t.Fatalf("could not create the logger: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// ---------------------------------------------------------------------------
// AmneziaWG server side
// ---------------------------------------------------------------------------

type awgServer struct {
	dev  *device.Device
	tnet *netstack.Net
	port int
}

// startServer brings up an AmneziaWG server on loopback with the obfuscation
// parameters under test, and serves HTTP and DNS from inside its tunnel.
func startServer(t testing.TB, serverKeys, clientKeys keyPair, psk string) *awgServer {
	t.Helper()
	return startServerOnPort(t, serverKeys, clientKeys, psk, 0)
}

// startServerOnPort is startServer with the UDP port chosen in advance, so a
// client can be configured, and started, before the server exists. Zero lets
// the operating system choose.
func startServerOnPort(t testing.TB, serverKeys, clientKeys keyPair, psk string, listenPort int) *awgServer {
	t.Helper()

	tunDev, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(serverV4), netip.MustParseAddr(serverV6)},
		nil,
		1420,
	)
	if err != nil {
		t.Fatalf("could not create the server network stack: %v", err)
	}

	dev := device.NewDevice(tunDev, conn.NewDefaultBind(),
		logging.DeviceLogger(testLogger(t), "awg-server: "))

	uapi := strings.Join([]string{
		"private_key=" + serverKeys.privateHex(),
		fmt.Sprintf("listen_port=%d", listenPort),
		fmt.Sprintf("jc=%d", paramJc),
		fmt.Sprintf("jmin=%d", paramJmin),
		fmt.Sprintf("jmax=%d", paramJmax),
		fmt.Sprintf("s1=%d", paramS1),
		fmt.Sprintf("s2=%d", paramS2),
		fmt.Sprintf("s3=%d", paramS3),
		fmt.Sprintf("s4=%d", paramS4),
		"h1=" + paramH1,
		"h2=" + paramH2,
		"h3=" + paramH3,
		"h4=" + paramH4,
		"public_key=" + clientKeys.publicHex(),
		"preshared_key=" + b64ToHex(psk),
		"replace_allowed_ips=true",
		"allowed_ip=" + clientV4 + "/32",
		"allowed_ip=" + clientV6 + "/128",
		"",
	}, "\n")

	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		t.Fatalf("could not apply the server configuration: %v", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		t.Fatalf("could not bring the server device up: %v", err)
	}
	t.Cleanup(dev.Close)

	// Read back the UDP port the operating system assigned.
	state, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("could not read the server state: %v", err)
	}
	port := 0
	for _, line := range strings.Split(state, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			fmt.Sscanf(v, "%d", &port)
		}
	}
	if port == 0 {
		t.Fatal("could not determine the server UDP port")
	}

	s := &awgServer{dev: dev, tnet: tnet, port: port}

	// The upstream TUN reader captures S4 as zero while the device is being
	// created and then blocks in tun.Read, so the first packet out of the
	// tunnel goes without the S4 prefix and the peer does not recognise it.
	// awg.buildDevice does the same on the client side; one packet is
	// sacrificed here for the server, otherwise the first UDP reply is lost.
	if c, err := tnet.DialUDPAddrPort(netip.AddrPort{},
		netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), 9)); err == nil {
		c.Write([]byte{0})
		c.Close()
	}

	s.serveHTTP(t)
	s.serveDNS(t)
	return s
}

// serveHTTP runs a minimal HTTP server inside the server tunnel. Its body
// contains a marker that can only be observed by a client that really reached
// the far side of the AmneziaWG tunnel.
func (s *awgServer) serveHTTP(t testing.TB) {
	t.Helper()
	for _, addr := range []string{serverV4, serverV6} {
		ln, err := s.tnet.ListenTCPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(addr), httpPort))
		if err != nil {
			t.Fatalf("could not open the in-tunnel HTTP listener on %s: %v", addr, err)
		}
		t.Cleanup(func() { ln.Close() })
		go func(ln net.Listener, addr string) {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					br := bufio.NewReader(c)
					// Read the request line and the headers.
					for {
						line, err := br.ReadString('\n')
						if err != nil {
							return
						}
						if strings.TrimSpace(line) == "" {
							break
						}
					}
					body := "AWGSOCKS-TUNNEL-OK from " + addr
					fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
						len(body), body)
				}(c)
			}
		}(ln, addr)
	}
}

// serveDNS runs a minimal DNS responder inside the server tunnel, so that the
// remote-DNS behaviour of the SOCKS5 front end can be observed. It answers only
// the test hostname, which proves the query really arrived here rather than at
// the Windows resolver.
func (s *awgServer) serveDNS(t testing.TB) {
	t.Helper()
	pc, err := s.tnet.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(serverV4), dnsPort))
	if err != nil {
		t.Fatalf("could not open the in-tunnel DNS listener: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp, qtype, err := answerDNS(buf[:n])
			if err != nil || resp == nil {
				continue
			}
			// Swallow the reply instead of sending it, to model the datagram
			// that goes missing under load.
			if qtype == dnsmessage.TypeA && dnsDropA.Load() > 0 {
				dnsDropA.Add(-1)
				continue
			}
			pc.WriteTo(resp, from)
		}
	}()
}

// dnsDropA makes the in-tunnel responder swallow that many A replies before it
// starts answering normally.
//
// It reproduces the failure that made TestRemoteDNSThroughTunnel flaky: the
// resolver asks A and AAAA at once, an authoritative empty AAAA reads as "no
// such host", and losing the A reply leaves that as the only answer. Tests set
// it before building a harness and reset it afterwards; nothing here runs in
// parallel.
var dnsDropA atomic.Int32

// answerDNS builds an A-record response for the test hostname, and an
// authoritative empty answer for anything else, which is what a real server
// returns when a name exists but the requested type does not. It also reports
// the query type so the caller can decide whether to send the reply at all.
func answerDNS(query []byte) ([]byte, dnsmessage.Type, error) {
	var p dnsmessage.Parser
	header, err := p.Start(query)
	if err != nil {
		return nil, 0, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, 0, err
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               header.ID,
		Response:         true,
		Authoritative:    true,
		RecursionDesired: header.RecursionDesired,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, q.Type, err
	}
	if err := b.Question(q); err != nil {
		return nil, q.Type, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, q.Type, err
	}

	name := strings.TrimSuffix(q.Name.String(), ".")
	if strings.EqualFold(name, testHost) && q.Type == dnsmessage.TypeA {
		err = b.AResource(dnsmessage.ResourceHeader{
			Name:  q.Name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   60,
		}, dnsmessage.AResource{A: netip.MustParseAddr(serverV4).As4()})
		if err != nil {
			return nil, q.Type, err
		}
	}
	out, err := b.Finish()
	return out, q.Type, err
}

// ---------------------------------------------------------------------------
// AWGSocks client side
// ---------------------------------------------------------------------------

func clientConfigText(clientKeys, serverKeys keyPair, psk string, serverPort int, withDNS bool) string {
	dnsLine := ""
	if withDNS {
		dnsLine = "DNS = " + serverV4 + "\n"
	}
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32,%s/128
%s
Jc = %d
Jmin = %d
Jmax = %d

S1 = %d
S2 = %d
S3 = %d
S4 = %d

H1 = %s
H2 = %s
H3 = %s
H4 = %s

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = 127.0.0.1:%d
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 5
`,
		clientKeys.private, clientV4, clientV6, dnsLine,
		paramJc, paramJmin, paramJmax,
		paramS1, paramS2, paramS3, paramS4,
		paramH1, paramH2, paramH3, paramH4,
		serverKeys.public, psk, serverPort)
}

type harness struct {
	server *awgServer
	tunnel *awg.Tunnel
	socks  *socks5.Server
}

func startHarness(t testing.TB, withDNS bool) *harness {
	t.Helper()
	return startHarnessWithBind(t, withDNS, awg.BindStd)
}

// startHarnessWithBind builds the full client stack using the given upstream
// UDP bind implementation, so both bind modes are covered end to end.
func startHarnessWithBind(t testing.TB, withDNS bool, bind awg.BindMode) *harness {
	return startHarnessWithNetstack(t, withDNS, bind, awg.NetstackUpstream)
}

// startHarnessWithNetstack keeps the production test harness intact while
// allowing benchmark-only netstack handoff experiments to use the identical
// SOCKS5, AmneziaWG and loopback-server path.
func startHarnessWithNetstack(t testing.TB, withDNS bool, bind awg.BindMode, netstackMode awg.NetstackMode) *harness {
	t.Helper()

	clientKeys := newKeyPair(t)
	serverKeys := newKeyPair(t)
	psk := newPresharedKey(t)

	server := startServer(t, serverKeys, clientKeys, psk)

	text := clientConfigText(clientKeys, serverKeys, psk, server.port, withDNS)
	cfg, err := config.ParseTunnel([]byte(text), filepath.Join(t.TempDir(), "client.conf"))
	if err != nil {
		t.Fatalf("could not parse the client configuration: %v", err)
	}

	log := testLogger(t)
	tunnel := awg.NewWithBindAndNetstack(log, cfg, bind, netstackMode)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := tunnel.Start(ctx); err != nil {
		t.Fatalf("could not start the client tunnel: %v", err)
	}
	t.Cleanup(tunnel.Stop)

	srv := socks5.New(log, tunnel, "127.0.0.1:0", 0)
	if err := srv.Start(); err != nil {
		t.Fatalf("could not open the SOCKS5 listener: %v", err)
	}
	t.Cleanup(srv.Stop)

	waitConnected(t, tunnel)
	return &harness{server: server, tunnel: tunnel, socks: srv}
}

func waitConnected(t testing.TB, tunnel *awg.Tunnel) {
	t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		if tunnel.State() == awg.StateConnected {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	stats, _ := tunnel.Stats()
	t.Fatalf("the AmneziaWG handshake did not complete within 25 seconds (state=%v, last error=%q, last handshake=%v)",
		tunnel.State(), tunnel.LastError(), stats.LastHandshake)
}

// ---------------------------------------------------------------------------
// Minimal SOCKS5 client, equivalent to curl --proxy socks5h://...
// ---------------------------------------------------------------------------

func socksDial(proxyAddr string, atyp byte, addr []byte, port uint16) (net.Conn, byte, error) {
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, 0, err
	}
	c.SetDeadline(time.Now().Add(30 * time.Second))

	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		c.Close()
		return nil, 0, err
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil {
		c.Close()
		return nil, 0, err
	}
	if greet[1] != 0x00 {
		c.Close()
		return nil, 0, errors.New("the proxy refused an unauthenticated connection")
	}

	req := []byte{0x05, 0x01, 0x00, atyp}
	req = append(req, addr...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, 0, err
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		c.Close()
		return nil, 0, err
	}
	skip := 4
	if head[3] == 0x04 {
		skip = 16
	}
	if _, err := io.ReadFull(c, make([]byte, skip+2)); err != nil {
		c.Close()
		return nil, 0, err
	}
	if head[1] != 0x00 {
		c.Close()
		return nil, head[1], fmt.Errorf("SOCKS5 reply code %d", head[1])
	}
	return c, 0x00, nil
}

func socksHTTPGet(t *testing.T, proxyAddr string, atyp byte, addr []byte, port uint16, hostHeader string) string {
	t.Helper()
	c, _, err := socksDial(proxyAddr, atyp, addr, port)
	if err != nil {
		t.Fatalf("could not establish the SOCKS5 connection: %v", err)
	}
	defer c.Close()

	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostHeader)
	raw, err := io.ReadAll(c)
	if err != nil && len(raw) == 0 {
		t.Fatalf("could not read the reply: %v", err)
	}
	return string(raw)
}

func ipv4Bytes(addr string) []byte {
	b := netip.MustParseAddr(addr).As4()
	return b[:]
}

func ipv6Bytes(addr string) []byte {
	b := netip.MustParseAddr(addr).As16()
	return b[:]
}

func domainBytes(host string) []byte {
	return append([]byte{byte(len(host))}, host...)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestDataPathIPv4 proves a SOCKS5 CONNECT to an IPv4 destination is carried by
// the AmneziaWG tunnel all the way to the far side, with real payload data.
func TestDataPathIPv4(t *testing.T) {
	h := startHarness(t, false)

	body := socksHTTPGet(t, h.socks.Addr(), 0x01, ipv4Bytes(serverV4), httpPort, serverV4)
	if !strings.Contains(body, "AWGSOCKS-TUNNEL-OK from "+serverV4) {
		t.Fatalf("no reply from the far side of the tunnel:\n%s", body)
	}

	stats, err := h.tunnel.Stats()
	if err != nil {
		t.Fatalf("could not read the statistics: %v", err)
	}
	if stats.TxBytes == 0 || stats.RxBytes == 0 {
		t.Fatalf("no data flowed through the tunnel: tx=%d rx=%d", stats.TxBytes, stats.RxBytes)
	}
	if stats.LastHandshake.IsZero() {
		t.Fatal("no handshake was recorded")
	}
	t.Logf("carried over AmneziaWG: tx=%d bytes, rx=%d bytes", stats.TxBytes, stats.RxBytes)
}

// TestDataPathIPv6 proves the same for an IPv6 destination inside the tunnel.
func TestDataPathIPv6(t *testing.T) {
	h := startHarness(t, false)

	body := socksHTTPGet(t, h.socks.Addr(), 0x04, ipv6Bytes(serverV6), httpPort, "["+serverV6+"]")
	if !strings.Contains(body, "AWGSOCKS-TUNNEL-OK from "+serverV6) {
		t.Fatalf("no reply from the IPv6 destination:\n%s", body)
	}
}

// TestRemoteDNSThroughTunnel proves ATYP=DOMAINNAME is resolved by the DNS
// server named in the AmneziaWG configuration, reached through the tunnel.
// The hostname is in the .invalid TLD, so the Windows resolver could never
// answer it: a successful connection can only mean the query went through the
// tunnel.
func TestRemoteDNSThroughTunnel(t *testing.T) {
	h := startHarness(t, true)

	body := socksHTTPGet(t, h.socks.Addr(), 0x03, domainBytes(testHost), httpPort, testHost)
	if !strings.Contains(body, "AWGSOCKS-TUNNEL-OK") {
		t.Fatalf("no tunnel reply via the hostname:\n%s", body)
	}
}

// TestSystemResolverIsNeverUsed confirms the Windows resolver plays no part in
// SOCKS5 hostname handling: with in-tunnel DNS removed from the configuration,
// a hostname request must fail rather than be resolved by Windows.
func TestSystemResolverIsNeverUsed(t *testing.T) {
	h := startHarness(t, false) // no DNS line

	// The Windows resolver would resolve example.com without trouble, which
	// is exactly what must not happen here.
	_, rep, err := socksDial(h.socks.Addr(), 0x03, domainBytes("example.com"), 443)
	if err == nil {
		t.Fatal("a hostname request succeeded without in-tunnel DNS: the system resolver may have been used")
	}
	if rep != 0x04 {
		t.Fatalf("expected host unreachable (0x04), got %d", rep)
	}
}

// TestFailsClosedWhenTunnelStops is the leak test: once the AmneziaWG tunnel is
// stopped, a SOCKS5 request must fail. It must never be completed over the
// default Windows network path.
func TestFailsClosedWhenTunnelStops(t *testing.T) {
	h := startHarness(t, false)

	// First confirm the connection really works while the tunnel is up.
	body := socksHTTPGet(t, h.socks.Addr(), 0x01, ipv4Bytes(serverV4), httpPort, serverV4)
	if !strings.Contains(body, "AWGSOCKS-TUNNEL-OK") {
		t.Fatalf("precondition failed: no reply while the tunnel was up:\n%s", body)
	}

	h.tunnel.Stop()

	// The same request must now fail. So must a request to a genuinely
	// reachable destination, a loopback HTTP server, which is the proof that
	// no direct socket is opened.
	direct := startPlainHTTPServer(t)
	cases := []struct {
		name string
		atyp byte
		addr []byte
		port uint16
	}{
		{"in-tunnel destination", 0x01, ipv4Bytes(serverV4), httpPort},
		{"a genuinely reachable loopback server", 0x01, ipv4Bytes("127.0.0.1"), direct},
	}
	for _, c := range cases {
		conn, rep, err := socksDial(h.socks.Addr(), c.atyp, c.addr, c.port)
		if err == nil {
			conn.Close()
			t.Fatalf("%s: a connection was established while the tunnel was down, which is a leak", c.name)
		}
		if rep != 0x03 {
			t.Fatalf("%s: expected network unreachable (0x03), got %d", c.name, rep)
		}
	}

	// The SOCKS5 listener must stay open so that clients get an explicit
	// error rather than a connection refusal.
	if !h.socks.Listening() {
		t.Fatal("the SOCKS5 listener must not close when the tunnel stops")
	}
}

// startPlainHTTPServer runs a plain loopback HTTP server that is reachable
// without any tunnel. It exists so the leak test can prove that even a trivially
// reachable destination is refused once the tunnel is down.
func startPlainHTTPServer(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start the direct server: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nDIRECT"))
			c.Close()
		}
	}()
	ap, _ := netip.ParseAddrPort(ln.Addr().String())
	return ap.Port()
}

// TestConcurrentConnections exercises many simultaneous SOCKS5 sessions over
// one tunnel, which is the qBittorrent workload.
func TestConcurrentConnections(t *testing.T) {
	h := startHarness(t, false)

	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, _, err := socksDial(h.socks.Addr(), 0x01, ipv4Bytes(serverV4), httpPort)
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", serverV4)
			raw, _ := io.ReadAll(c)
			if !strings.Contains(string(raw), "AWGSOCKS-TUNNEL-OK") {
				errs <- fmt.Errorf("unexpected reply: %q", string(raw))
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent connection error: %v", err)
	}

	stats := h.socks.Stats()
	if stats.Total < n {
		t.Errorf("expected %d connections, counter says %d", n, stats.Total)
	}
	// The server side session goroutine finishes shortly after the client
	// closes, so wait for the counter to settle.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.socks.Stats().Active == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("the active counter should be zero once every connection closed, got %d",
		h.socks.Stats().Active)
}

// TestLargeTransfer moves a payload larger than the tunnel MTU, proving
// fragmentation and reassembly work through the userspace stack.
func TestLargeTransfer(t *testing.T) {
	h := startHarness(t, false)

	ln, err := h.server.tnet.ListenTCPAddrPort(
		netip.AddrPortFrom(netip.MustParseAddr(serverV4), 9000))
	if err != nil {
		t.Fatalf("could not open the in-tunnel echo listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()

	c, _, err := socksDial(h.socks.Addr(), 0x01, ipv4Bytes(serverV4), 9000)
	if err != nil {
		t.Fatalf("could not establish the SOCKS5 connection: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second))

	payload := make([]byte, 512*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("could not generate the payload: %v", err)
	}

	go func() {
		c.Write(payload)
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("the large transfer did not complete: %v", err)
	}
	for i := range payload {
		if payload[i] != got[i] {
			t.Fatalf("the data is corrupted at byte %d", i)
		}
	}
	t.Logf("%d bytes carried intact over the AmneziaWG tunnel", len(payload))
}

// TestReconnectRecoversHandshake proves the reconnect path rebinds the UDP
// socket and re-establishes the AmneziaWG session.
func TestReconnectRecoversHandshake(t *testing.T) {
	h := startHarness(t, false)

	before, err := h.tunnel.Stats()
	if err != nil {
		t.Fatalf("could not read the statistics: %v", err)
	}

	h.tunnel.Reconnect()
	waitConnected(t, h.tunnel)

	body := socksHTTPGet(t, h.socks.Addr(), 0x01, ipv4Bytes(serverV4), httpPort, serverV4)
	if !strings.Contains(body, "AWGSOCKS-TUNNEL-OK") {
		t.Fatalf("no data flows after the reconnect:\n%s", body)
	}
	if h.tunnel.Reconnects() == 0 {
		t.Error("the reconnect counter did not move")
	}
	t.Logf("last handshake before the reconnect: %v", before.LastHandshake)
}

// TestDataPathWithWindowsRIOBind runs the same data path over the Windows
// Registered I/O bind, which is what "udp_bind": "rio" selects. It keeps the
// non-default path covered.
func TestDataPathWithWindowsRIOBind(t *testing.T) {
	h := startHarnessWithBind(t, false, awg.BindRIO)

	if got := h.tunnel.BindMode(); got != awg.BindRIO {
		t.Fatalf("expected the rio bind, got %s", got)
	}
	body := socksHTTPGet(t, h.socks.Addr(), 0x01, ipv4Bytes(serverV4), httpPort, serverV4)
	if !strings.Contains(body, "AWGSOCKS-TUNNEL-OK from "+serverV4) {
		t.Fatalf("no tunnel reply over the RIO bind:\n%s", body)
	}
}

// TestExperimentalNetstackModesDataPath verifies that each isolated
// tun/netstack handoff experiment still carries a SOCKS5 TCP CONNECT through
// the complete AmneziaWG path. The normal production tests above remain on
// NetstackUpstream.
func TestExperimentalNetstackModesDataPath(t *testing.T) {
	for _, mode := range []awg.NetstackMode{
		awg.NetstackBuffered,
		awg.NetstackBatched,
		awg.NetstackBatchedBuffered,
	} {
		t.Run(string(mode), func(t *testing.T) {
			h := startHarnessWithNetstack(t, false, awg.BindStd, mode)
			body := socksHTTPGet(t, h.socks.Addr(), 0x01, ipv4Bytes(serverV4), httpPort, serverV4)
			if !strings.Contains(body, "AWGSOCKS-TUNNEL-OK from "+serverV4) {
				t.Fatalf("no tunnel reply with %s netstack adapter:\n%s", mode, body)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// UDP ASSOCIATE
// ---------------------------------------------------------------------------

// udpAssociate performs a SOCKS5 UDP ASSOCIATE and returns the control
// connection plus the relay address to send datagrams to.
func udpAssociate(t *testing.T, proxyAddr string) (net.Conn, netip.AddrPort) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("could not connect to the proxy: %v", err)
	}
	c.SetDeadline(time.Now().Add(30 * time.Second))

	c.Write([]byte{0x05, 0x01, 0x00})
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatalf("could not read the greeting reply: %v", err)
	}
	c.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		t.Fatalf("could not read the reply header: %v", err)
	}
	n := 4
	if head[3] == 0x04 {
		n = 16
	}
	rest := make([]byte, n+2)
	if _, err := io.ReadFull(c, rest); err != nil {
		t.Fatalf("could not read the reply address: %v", err)
	}
	if head[1] != 0x00 {
		c.Close()
		t.Fatalf("UDP ASSOCIATE was rejected, reply code %d", head[1])
	}
	addr, _ := netip.AddrFromSlice(rest[:n])
	return c, netip.AddrPortFrom(addr.Unmap(), binary.BigEndian.Uint16(rest[n:]))
}

func socksUDPHeader(dst netip.AddrPort) []byte {
	out := []byte{0, 0, 0}
	b := dst.Addr().As4()
	out = append(out, 0x01)
	out = append(out, b[:]...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], dst.Port())
	return append(out, p[:]...)
}

// TestUDPThroughTunnel proves that SOCKS5 UDP ASSOCIATE carries datagrams over
// real AmneziaWG, which is what BitTorrent DHT and UDP trackers need in order
// not to bypass the tunnel.
func TestUDPThroughTunnel(t *testing.T) {
	h := startHarness(t, false)

	// A UDP echo service on the far side of the tunnel.
	pc, err := h.server.tnet.ListenUDPAddrPort(
		netip.AddrPortFrom(netip.MustParseAddr(serverV4), 7000))
	if err != nil {
		t.Fatalf("could not open the in-tunnel UDP listener: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(append([]byte("AWGSOCKS-UDP-OK:"), buf[:n]...), from)
		}
	}()

	control, relay := udpAssociate(t, h.socks.Addr())
	defer control.Close()
	if !relay.Addr().IsLoopback() {
		t.Fatalf("the UDP relay is bound outside loopback: %s", relay)
	}

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not open the client socket: %v", err)
	}
	defer client.Close()

	target := netip.AddrPortFrom(netip.MustParseAddr(serverV4), 7000)
	msg := append(socksUDPHeader(target), []byte("ping")...)
	if _, err := client.WriteTo(msg, net.UDPAddrFromAddrPort(relay)); err != nil {
		t.Fatalf("could not send the datagram: %v", err)
	}

	client.SetReadDeadline(time.Now().Add(20 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		st := h.socks.Stats()
		t.Fatalf("no UDP reply through the tunnel: %v (sent=%d received=%d dropped=%d)",
			err, st.UDPDatagramsUp, st.UDPDatagramsDown, st.UDPDropped)
	}
	if !strings.Contains(string(buf[:n]), "AWGSOCKS-UDP-OK:ping") {
		t.Fatalf("unexpected UDP reply: %q", buf[:n])
	}

	stats := h.socks.Stats()
	if stats.UDPDatagramsUp == 0 || stats.UDPDatagramsDown == 0 {
		t.Fatalf("the UDP counters did not move: %+v", stats)
	}
	t.Logf("UDP over AmneziaWG: %d sent, %d received",
		stats.UDPDatagramsUp, stats.UDPDatagramsDown)
}

// TestUDPFailsClosedWhenTunnelStops proves the UDP path is fail-closed too:
// once the tunnel is down, a UDP ASSOCIATE must be refused rather than quietly
// relaying datagrams over the default network.
func TestUDPFailsClosedWhenTunnelStops(t *testing.T) {
	h := startHarness(t, false)
	h.tunnel.Stop()

	c, err := net.DialTimeout("tcp", h.socks.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("could not connect to the proxy: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))

	c.Write([]byte{0x05, 0x01, 0x00})
	io.ReadFull(c, make([]byte, 2))
	c.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		t.Fatalf("could not read the reply: %v", err)
	}
	if head[1] == 0x00 {
		t.Fatal("UDP ASSOCIATE was accepted while the tunnel was down, which risks a leak")
	}
	if head[1] != 0x03 {
		t.Fatalf("expected network unreachable (0x03), got %d", head[1])
	}
}

// TestInTunnelDNSSurvivesALostResponse is the regression test for the flake
// that took CI down, reproduced deterministically instead of waiting for load
// to produce it.
//
// The resolver asks for A and AAAA together and reports the first error either
// lane returns. The server answers AAAA for this name authoritatively and
// empty, which the netstack resolver reports as "no such host". Drop the A
// reply and that not-found is all that is left, so the name looks like it does
// not exist. AWGSocks used to believe that on the first attempt and return
// SOCKS5 host unreachable for a name that resolves perfectly well.
func TestInTunnelDNSSurvivesALostResponse(t *testing.T) {
	dnsDropA.Store(1)
	t.Cleanup(func() { dnsDropA.Store(0) })

	h := startHarness(t, true)

	body := socksHTTPGet(t, h.socks.Addr(), 0x03, domainBytes(testHost), httpPort, testHost)
	if !strings.Contains(body, "AWGSOCKS-TUNNEL-OK") {
		t.Fatalf("a single lost DNS reply made the hostname permanently unresolvable:\n%s", body)
	}
	if left := dnsDropA.Load(); left != 0 {
		t.Fatalf("the test never dropped an A reply, so it proved nothing (%d left)", left)
	}
}

// socksGetAsync performs the same request as socksHTTPGet from a goroutine,
// where t.Fatalf is not allowed, and reports what happened instead.
func socksGetAsync(proxyAddr string, atyp byte, addr []byte, port uint16, hostHeader string) (body string, rep byte, err error) {
	c, rep, err := socksDial(proxyAddr, atyp, addr, port)
	if err != nil {
		return "", rep, err
	}
	defer c.Close()
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostHeader)
	raw, rerr := io.ReadAll(c)
	if rerr != nil && len(raw) == 0 {
		return "", rep, rerr
	}
	return string(raw), rep, nil
}

// TestRequestBeforeTheNetworkArrivesIsHeldNotRefused reproduces what a program
// launched at logon runs into. On the machine this was measured on the service
// started at +5 s, qBittorrent at +13 s while Windows still reported the
// network as being identified, and the network was usable at +16 s. A request
// that arrives in that window must wait for the tunnel and then succeed, not be
// refused because it came a few seconds too early.
//
// The server does not exist yet when the request is sent, so no handshake is
// possible, which is what a missing network looks like from the client. It
// appears three seconds later.
func TestRequestBeforeTheNetworkArrivesIsHeldNotRefused(t *testing.T) {
	clientKeys := newKeyPair(t)
	serverKeys := newKeyPair(t)
	psk := newPresharedKey(t)

	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not reserve a UDP port: %v", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()

	cfg, err := config.ParseTunnel([]byte(clientConfigText(clientKeys, serverKeys, psk, port, true)),
		filepath.Join(t.TempDir(), "client.conf"))
	if err != nil {
		t.Fatalf("could not parse the client configuration: %v", err)
	}
	log := testLogger(t)
	tunnel := awg.NewWithBind(log, cfg, awg.BindStd)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := tunnel.Start(ctx); err != nil {
		t.Fatalf("could not start the client tunnel: %v", err)
	}
	t.Cleanup(tunnel.Stop)

	srv := socks5.New(log, tunnel, "127.0.0.1:0", 0)
	if err := srv.Start(); err != nil {
		t.Fatalf("could not open the SOCKS5 listener: %v", err)
	}
	t.Cleanup(srv.Stop)

	type result struct {
		body string
		rep  byte
		err  error
		took time.Duration
	}
	done := make(chan result, 1)
	sent := time.Now()
	go func() {
		body, rep, err := socksGetAsync(srv.Addr(), 0x03, domainBytes(testHost), httpPort, testHost)
		done <- result{body, rep, err, time.Since(sent)}
	}()

	time.Sleep(3 * time.Second)
	select {
	case r := <-done:
		t.Fatalf("the request finished before any server existed, after %s (reply %d): %v", r.took, r.rep, r.err)
	default:
	}
	startServerOnPort(t, serverKeys, clientKeys, psk, port)

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("a request sent before the network arrived was refused after %s (SOCKS5 reply %d): %v", r.took, r.rep, r.err)
		}
		if !strings.Contains(r.body, "AWGSOCKS-TUNNEL-OK") {
			t.Fatalf("no tunnel reply after %s:\n%s", r.took, r.body)
		}
		t.Logf("held for %s, then served", r.took.Round(100*time.Millisecond))
	case <-time.After(25 * time.Second):
		t.Fatal("the request neither succeeded nor failed within 25 seconds of being sent")
	}
}
