package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ComoEstaisAmigos/awgsocks/internal/awg"
	"github.com/ComoEstaisAmigos/awgsocks/internal/logging"
)

// fakeDialer stands in for the AmneziaWG tunnel. In a test it is allowed to use
// a real socket, because the "remote" end is a loopback echo server.
type fakeDialer struct {
	dialErr   error
	lookupErr error
	hasDNS    bool
	resolved  []netip.Addr
	remote    netip.AddrPort
	lastDial  netip.AddrPort
	udpErr    error
	udpIPv6   bool

	// delay holds DialTCP and ListenUDP back, the way a tunnel still waiting
	// for its first handshake does.
	delay time.Duration
}

// wait sleeps for delay unless ctx ends first.
func (f *fakeDialer) wait(ctx context.Context) error {
	if f.delay <= 0 {
		return nil
	}
	select {
	case <-time.After(f.delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *fakeDialer) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	if err := f.wait(ctx); err != nil {
		return nil, err
	}
	f.lastDial = addr
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", f.remote.String())
}

func (f *fakeDialer) LookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if f.lookupErr != nil {
		return nil, f.lookupErr
	}
	return f.resolved, nil
}

func (f *fakeDialer) HasDNS() bool { return f.hasDNS }

// ListenUDP stands in for an in-tunnel UDP socket. In a test it is allowed to
// be a real loopback socket, because the "remote" side is local too.
func (f *fakeDialer) ListenUDP(ctx context.Context, ipv6 bool) (net.PacketConn, error) {
	if err := f.wait(ctx); err != nil {
		return nil, err
	}
	if f.udpErr != nil {
		return nil, f.udpErr
	}
	if ipv6 && !f.udpIPv6 {
		return nil, errors.New("no IPv6 in this tunnel")
	}
	host := "127.0.0.1:0"
	if ipv6 {
		host = "[::1]:0"
	}
	return net.ListenPacket("udp", host)
}

func testLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l, err := logging.New(logging.Options{Level: logging.LevelError})
	if err != nil {
		t.Fatalf("could not create the logger: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// startEcho runs a loopback TCP echo server used as the tunnel destination.
func startEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start the echo server: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
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
	ap, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("could not parse the echo address: %v", err)
	}
	return ap
}

func startServer(t *testing.T, d Dialer) *Server {
	t.Helper()
	s := New(testLogger(t), d, "127.0.0.1:0", 0)
	if err := s.Start(); err != nil {
		t.Fatalf("could not start the SOCKS5 server: %v", err)
	}
	t.Cleanup(s.Stop)
	return s
}

// socksConnect performs a full SOCKS5 CONNECT and returns the reply code.
func socksConnect(t *testing.T, serverAddr string, atyp byte, addr []byte, port uint16) (net.Conn, byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", serverAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("could not connect to the proxy: %v", err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("could not write the greeting: %v", err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil {
		t.Fatalf("could not read the greeting reply: %v", err)
	}
	if greet[0] != 0x05 || greet[1] != 0x00 {
		t.Fatalf("unexpected greeting reply: %v", greet)
	}

	req := []byte{0x05, 0x01, 0x00, atyp}
	req = append(req, addr...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		t.Fatalf("could not write the request: %v", err)
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		t.Fatalf("could not read the reply header: %v", err)
	}
	var rest int
	switch head[3] {
	case atypIPv4:
		rest = 4
	case atypIPv6:
		rest = 16
	default:
		rest = 4
	}
	if _, err := io.ReadFull(c, make([]byte, rest+2)); err != nil {
		t.Fatalf("could not read the reply address: %v", err)
	}
	return c, head[1]
}

func TestConnectIPv4ThroughTunnel(t *testing.T) {
	echo := startEcho(t)
	d := &fakeDialer{remote: echo}
	s := startServer(t, d)

	target := netip.MustParseAddr("10.1.2.3")
	b := target.As4()
	c, rep := socksConnect(t, s.Addr(), atypIPv4, b[:], 443)
	defer c.Close()
	if rep != repSuccess {
		t.Fatalf("expected success, got reply code %d", rep)
	}
	if d.lastDial.Addr() != target || d.lastDial.Port() != 443 {
		t.Fatalf("the dialer was called with the wrong target: %v", d.lastDial)
	}

	msg := []byte("awgsocks")
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("could not write data: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("could not read data: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("the relay corrupted the data: %q", got)
	}
}

func TestConnectIPv6ThroughTunnel(t *testing.T) {
	echo := startEcho(t)
	d := &fakeDialer{remote: echo}
	s := startServer(t, d)

	target := netip.MustParseAddr("2001:db8::1")
	b := target.As16()
	c, rep := socksConnect(t, s.Addr(), atypIPv6, b[:], 80)
	defer c.Close()
	if rep != repSuccess {
		t.Fatalf("expected success, got reply code %d", rep)
	}
	if d.lastDial.Addr() != target {
		t.Fatalf("wrong IPv6 target: %v", d.lastDial)
	}
}

func TestHostnameResolvedInsideTunnel(t *testing.T) {
	echo := startEcho(t)
	resolved := netip.MustParseAddr("203.0.113.7")
	d := &fakeDialer{remote: echo, hasDNS: true, resolved: []netip.Addr{resolved}}
	s := startServer(t, d)

	host := []byte("example.com")
	addr := append([]byte{byte(len(host))}, host...)
	c, rep := socksConnect(t, s.Addr(), atypDomain, addr, 443)
	defer c.Close()
	if rep != repSuccess {
		t.Fatalf("expected success, got reply code %d", rep)
	}
	if d.lastDial.Addr() != resolved {
		t.Fatalf("the hostname did not connect to the in-tunnel DNS result: %v", d.lastDial)
	}
}

func TestHostnameRejectedWithoutTunnelDNS(t *testing.T) {
	d := &fakeDialer{remote: netip.MustParseAddrPort("127.0.0.1:1"), hasDNS: false}
	s := startServer(t, d)

	host := []byte("example.com")
	addr := append([]byte{byte(len(host))}, host...)
	c, rep := socksConnect(t, s.Addr(), atypDomain, addr, 443)
	defer c.Close()
	if rep != repHostUnreachable {
		t.Fatalf("expected host unreachable without DNS, got %d", rep)
	}
	if d.lastDial.IsValid() {
		t.Fatal("the dialer must not be called when there is no in-tunnel DNS")
	}
}

func TestTunnelDownFailsInsteadOfLeaking(t *testing.T) {
	d := &fakeDialer{remote: netip.MustParseAddrPort("127.0.0.1:1"), dialErr: awg.ErrTunnelDown}
	s := startServer(t, d)

	target := netip.MustParseAddr("10.1.2.3")
	b := target.As4()
	c, rep := socksConnect(t, s.Addr(), atypIPv4, b[:], 443)
	defer c.Close()
	if rep != repNetworkUnreachable {
		t.Fatalf("expected network unreachable while the tunnel is down, got %d", rep)
	}
}

func TestHandshakeStaleFailsClosed(t *testing.T) {
	d := &fakeDialer{remote: netip.MustParseAddrPort("127.0.0.1:1"), dialErr: awg.ErrNotReady}
	s := startServer(t, d)

	b := netip.MustParseAddr("10.1.2.3").As4()
	c, rep := socksConnect(t, s.Addr(), atypIPv4, b[:], 443)
	defer c.Close()
	if rep != repNetworkUnreachable {
		t.Fatalf("expected network unreachable without a handshake, got %d", rep)
	}
}

func TestBindCommandNotSupported(t *testing.T) {
	d := &fakeDialer{remote: netip.MustParseAddrPort("127.0.0.1:1")}
	s := startServer(t, d)

	c, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatalf("could not connect to the proxy: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte{0x05, 0x01, 0x00})
	io.ReadFull(c, make([]byte, 2))

	c.Write([]byte{0x05, cmdBind, 0x00, atypIPv4, 127, 0, 0, 1, 0x00, 0x50})
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		t.Fatalf("could not read the reply: %v", err)
	}
	if head[1] != repCommandNotSupported {
		t.Fatalf("expected 0x07 for BIND, got %d", head[1])
	}
}

func TestAuthenticationMethodsRejectedWhenNoAuthMissing(t *testing.T) {
	d := &fakeDialer{remote: netip.MustParseAddrPort("127.0.0.1:1")}
	s := startServer(t, d)

	c, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatalf("could not connect to the proxy: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	// Offer only the username/password method.
	c.Write([]byte{0x05, 0x01, 0x02})
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("could not read the reply: %v", err)
	}
	if resp[1] != methodNoAcceptable {
		t.Fatalf("expected 0xFF, got %d", resp[1])
	}
}

func TestNonLoopbackListenRejected(t *testing.T) {
	d := &fakeDialer{}
	for _, addr := range []string{"0.0.0.0:10808", "[::]:10808", "192.168.1.10:10808"} {
		s := New(testLogger(t), d, addr, 0)
		if err := s.Start(); err == nil {
			s.Stop()
			t.Fatalf("the address %s should have been rejected", addr)
		}
	}
}

func TestReplyForErrorMapping(t *testing.T) {
	cases := []struct {
		err  error
		want byte
	}{
		{awg.ErrTunnelDown, repNetworkUnreachable},
		{awg.ErrNotReady, repNetworkUnreachable},
		{awg.ErrNoDNS, repHostUnreachable},
		{context.DeadlineExceeded, repHostUnreachable},
		{errors.New("connection refused"), repConnectionRefused},
		{errors.New("something unrecognised"), repHostUnreachable},
	}
	for _, c := range cases {
		if got := replyForError(c.err, repHostUnreachable); got != c.want {
			t.Errorf("%v: expected %d, got %d", c.err, c.want, got)
		}
	}
}
