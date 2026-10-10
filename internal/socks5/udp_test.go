package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ComoEstaisAmigos/awgsocks/internal/awg"
)

// udpAssociate performs the SOCKS5 greeting and a UDP ASSOCIATE request,
// returning the control connection, the relay address and the reply code.
func udpAssociate(t *testing.T, serverAddr string) (net.Conn, netip.AddrPort, byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", serverAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("could not connect to the proxy: %v", err)
	}
	c.SetDeadline(time.Now().Add(15 * time.Second))

	c.Write([]byte{socksVersion, 0x01, methodNoAuth})
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatalf("could not read the greeting reply: %v", err)
	}

	// The client declares an unspecified source, which is what real clients send.
	c.Write([]byte{socksVersion, cmdUDPAssociate, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		t.Fatalf("could not read the reply header: %v", err)
	}
	n := 4
	if head[3] == atypIPv6 {
		n = 16
	}
	rest := make([]byte, n+2)
	if _, err := io.ReadFull(c, rest); err != nil {
		t.Fatalf("could not read the reply address: %v", err)
	}
	if head[1] != repSuccess {
		return c, netip.AddrPort{}, head[1]
	}
	addr, _ := netip.AddrFromSlice(rest[:n])
	return c, netip.AddrPortFrom(addr.Unmap(), binary.BigEndian.Uint16(rest[n:])), head[1]
}

// startUDPEcho runs a loopback UDP echo server standing in for a remote peer.
func startUDPEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start the UDP echo server: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	ap, _ := netip.ParseAddrPort(pc.LocalAddr().String())
	return ap
}

// TestUDPAssociateRelaysDatagrams is the behaviour BitTorrent DHT needs: a
// datagram goes out through the tunnel and the reply comes back wrapped in a
// SOCKS5 UDP header naming its source.
func TestUDPAssociateRelaysDatagrams(t *testing.T) {
	echo := startUDPEcho(t)
	d := &fakeDialer{remote: netip.MustParseAddrPort("127.0.0.1:1")}
	s := startServer(t, d)

	control, relay, rep := udpAssociate(t, s.Addr())
	defer control.Close()
	if rep != repSuccess {
		t.Fatalf("UDP ASSOCIATE failed, reply code %d", rep)
	}
	if !relay.Addr().IsLoopback() {
		t.Fatalf("the UDP relay bound outside loopback: %s", relay)
	}

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not open the client socket: %v", err)
	}
	defer client.Close()

	payload := []byte("ping")
	datagram := buildUDPHeader(nil, echo)
	datagram = append(datagram, payload...)
	if _, err := client.WriteTo(datagram, net.UDPAddrFromAddrPort(relay)); err != nil {
		t.Fatalf("could not send the datagram: %v", err)
	}

	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 2048)
	n, from, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no reply received: %v", err)
	}
	if fromAP, _ := netip.ParseAddrPort(from.String()); fromAP != relay {
		t.Fatalf("the reply came from the wrong address: %s", from)
	}

	dst, got, err := parseUDPHeader(buf[:n])
	if err != nil {
		t.Fatalf("could not parse the reply header: %v", err)
	}
	if netip.AddrPortFrom(dst.addr, dst.port) != echo {
		t.Fatalf("wrong reply source: %v:%d, expected %s", dst.addr, dst.port, echo)
	}
	if string(got) != "echo:ping" {
		t.Fatalf("wrong reply body: %q", got)
	}

	st := s.Stats()
	if !st.UDPEnabled || st.UDPDatagramsUp == 0 || st.UDPDatagramsDown == 0 {
		t.Fatalf("the UDP counters are not as expected: %+v", st)
	}
}

func TestUDPAssociateDisabled(t *testing.T) {
	d := &fakeDialer{remote: netip.MustParseAddrPort("127.0.0.1:1")}
	s := NewWithOptions(testLogger(t), d, "127.0.0.1:0", 0, false)
	if err := s.Start(); err != nil {
		t.Fatalf("could not start the server: %v", err)
	}
	defer s.Stop()

	c, _, rep := udpAssociate(t, s.Addr())
	defer c.Close()
	if rep != repCommandNotSupported {
		t.Fatalf("expected 0x07 while UDP is disabled, got %d", rep)
	}
}

// TestUDPAssociateFailsWhenTunnelDown proves the association is refused rather
// than silently accepted when the tunnel cannot carry it. UDP has no way to
// report the failure later, so it has to surface here.
func TestUDPAssociateFailsWhenTunnelDown(t *testing.T) {
	d := &fakeDialer{remote: netip.MustParseAddrPort("127.0.0.1:1"), udpErr: awg.ErrTunnelDown}
	s := startServer(t, d)

	c, _, rep := udpAssociate(t, s.Addr())
	defer c.Close()
	if rep != repNetworkUnreachable {
		t.Fatalf("expected 0x03 while the tunnel is down, got %d", rep)
	}
}

// TestUDPRelayClosesWithControlConnection covers the RFC 1928 lifetime rule.
func TestUDPRelayClosesWithControlConnection(t *testing.T) {
	d := &fakeDialer{remote: netip.MustParseAddrPort("127.0.0.1:1")}
	s := startServer(t, d)

	control, relay, rep := udpAssociate(t, s.Addr())
	if rep != repSuccess {
		t.Fatalf("UDP ASSOCIATE failed: %d", rep)
	}
	if s.Stats().UDPAssociations != 1 {
		t.Fatalf("expected 1 active association, got %d", s.Stats().UDPAssociations)
	}

	control.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.Stats().UDPAssociations == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s.Stats().UDPAssociations != 0 {
		t.Fatal("the association should close when the control connection closes")
	}

	// The relay socket must be gone, but "gone" lands a moment after the counter
	// drops. handleUDPAssociate defers relay.Close() before it defers the counter
	// decrement, and deferred calls run last in first out, so the counter reaches
	// zero while Close is still waiting on the relay's reader goroutines. Poll the
	// bind instead of assuming the port is free the instant the association stops
	// being counted. A fast machine wins that race by accident; CI did not.
	deadline = time.Now().Add(5 * time.Second)
	var lastErr error
	for {
		pc, err := net.ListenPacket("udp", relay.String())
		if err == nil {
			pc.Close()
			return
		}
		lastErr = err
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the relay socket is still bound 5s after the control connection closed: %v", lastErr)
}

// TestUDPRelayRefusesNonLoopbackReply closes the one gap the AST leak guard
// cannot see: a loopback-bound UDP socket can still send anywhere.
func TestUDPRelayRefusesNonLoopbackReply(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("could not open the socket: %v", err)
	}
	defer pc.Close()
	guard := &loopbackPacketConn{UDPConn: pc}

	if _, err := guard.WriteToUDPAddrPort([]byte("x"), netip.MustParseAddrPort("8.8.8.8:53")); !errors.Is(err, ErrNonLoopbackTarget) {
		t.Fatalf("a non-loopback target should have been rejected, got %v", err)
	}
	if _, err := guard.WriteToUDPAddrPort([]byte("x"), netip.MustParseAddrPort("192.168.1.5:53")); !errors.Is(err, ErrNonLoopbackTarget) {
		t.Fatalf("a LAN target should have been rejected, got %v", err)
	}
	// A loopback destination stays allowed.
	if _, err := guard.WriteToUDPAddrPort([]byte("x"), netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 9)); err != nil {
		t.Fatalf("a loopback target should have been accepted: %v", err)
	}
}

func TestParseUDPHeader(t *testing.T) {
	v4 := append([]byte{0, 0, 0, atypIPv4, 10, 1, 2, 3, 0x01, 0xBB}, []byte("data")...)
	dst, payload, err := parseUDPHeader(v4)
	if err != nil || dst.addr.String() != "10.1.2.3" || dst.port != 443 || string(payload) != "data" {
		t.Fatalf("the IPv4 header was parsed wrongly: %v %v %q %v", dst.addr, dst.port, payload, err)
	}

	v6hdr := []byte{0, 0, 0, atypIPv6}
	v6hdr = append(v6hdr, netip.MustParseAddr("2001:db8::1").AsSlice()...)
	v6hdr = append(v6hdr, 0x00, 0x35)
	dst, payload, err = parseUDPHeader(append(v6hdr, []byte("q")...))
	if err != nil || dst.addr.String() != "2001:db8::1" || dst.port != 53 || string(payload) != "q" {
		t.Fatalf("the IPv6 header was parsed wrongly: %v %v %q %v", dst.addr, dst.port, payload, err)
	}

	name := "tracker.example.com"
	dom := append([]byte{0, 0, 0, atypDomain, byte(len(name))}, name...)
	dom = append(dom, 0x1A, 0xE1)
	dst, _, err = parseUDPHeader(append(dom, []byte("x")...))
	if err != nil || dst.host != name || dst.port != 6881 {
		t.Fatalf("the domain header was parsed wrongly: %q %d %v", dst.host, dst.port, err)
	}

	bad := []struct {
		name string
		in   []byte
	}{
		{"too short", []byte{0, 0}},
		{"RSV is not zero", []byte{1, 0, 0, atypIPv4, 1, 2, 3, 4, 0, 80}},
		{"fragmented", []byte{0, 0, 1, atypIPv4, 1, 2, 3, 4, 0, 80}},
		{"truncated IPv4", []byte{0, 0, 0, atypIPv4, 1, 2}},
		{"unknown ATYP", []byte{0, 0, 0, 0x09, 1, 2, 3, 4, 0, 80}},
		{"zero port", []byte{0, 0, 0, atypIPv4, 1, 2, 3, 4, 0, 0}},
		{"empty domain name", []byte{0, 0, 0, atypDomain, 0, 0, 80}},
	}
	for _, c := range bad {
		if _, _, err := parseUDPHeader(c.in); err == nil {
			t.Errorf("%s: expected an error", c.name)
		}
	}
}

func TestBuildUDPHeaderRoundTrip(t *testing.T) {
	for _, s := range []string{"203.0.113.9:6881", "[2001:db8::5]:53"} {
		src := netip.MustParseAddrPort(s)
		pkt := append(buildUDPHeader(nil, src), []byte("body")...)
		dst, payload, err := parseUDPHeader(pkt)
		if err != nil {
			t.Fatalf("%s: could not parse: %v", s, err)
		}
		if netip.AddrPortFrom(dst.addr, dst.port) != src || string(payload) != "body" {
			t.Fatalf("%s: round trip is broken: %v:%d %q", s, dst.addr, dst.port, payload)
		}
	}
}

// TestListenersAreLoopbackOnly backs the claim made in noleak_test.go that both
// bind calls in this package use a loopback address.
func TestListenersAreLoopbackOnly(t *testing.T) {
	d := &fakeDialer{remote: netip.MustParseAddrPort("127.0.0.1:1")}
	s := startServer(t, d)

	tcpAddr, err := netip.ParseAddrPort(s.Addr())
	if err != nil {
		t.Fatalf("could not parse the TCP address: %v", err)
	}
	if !tcpAddr.Addr().IsLoopback() {
		t.Fatalf("the TCP listener is outside loopback: %s", tcpAddr)
	}

	control, relay, rep := udpAssociate(t, s.Addr())
	defer control.Close()
	if rep != repSuccess {
		t.Fatalf("UDP ASSOCIATE failed: %d", rep)
	}
	if !relay.Addr().IsLoopback() {
		t.Fatalf("the UDP relay bound outside loopback: %s", relay)
	}
}

// shortenTimeouts makes the negotiation deadline expire well before the tunnel
// wait does, so the situation can be exercised in milliseconds instead of the
// ten and fifteen seconds it takes in production.
func shortenTimeouts(t *testing.T, negotiation, dial time.Duration) {
	t.Helper()
	oldNegotiation, oldDial := handshakeTimeout, dialTimeout
	handshakeTimeout, dialTimeout = negotiation, dial
	t.Cleanup(func() { handshakeTimeout, dialTimeout = oldNegotiation, oldDial })
}

// TestUDPAssociateOutlastsTheNegotiationDeadline pins what a program started at
// logon relies on: a UDP ASSOCIATE sent while the tunnel still waits for its
// first handshake is held and then granted, even when the wait outlasts the ten
// second negotiation deadline set when the client connected.
//
// The handler clears that deadline only after it replies, which looks like it
// would lose the reply. It does not, because reply sets its own write deadline,
// and this test was written while suspecting otherwise and passed before any
// change was made. It stays so that the guarantee cannot be broken quietly,
// for instance by a reply path that stops refreshing its deadline. Losing the
// association would take every DHT query and UDP tracker with it.
func TestUDPAssociateOutlastsTheNegotiationDeadline(t *testing.T) {
	shortenTimeouts(t, 200*time.Millisecond, 5*time.Second)

	d := &fakeDialer{remote: netip.MustParseAddrPort("127.0.0.1:1"), delay: 600 * time.Millisecond}
	s := startServer(t, d)

	c, relay, rep := udpAssociate(t, s.Addr())
	defer c.Close()
	if rep != repSuccess {
		t.Fatalf("UDP ASSOCIATE failed after waiting longer than the negotiation deadline, reply %d", rep)
	}
	if !relay.IsValid() || !relay.Addr().IsLoopback() {
		t.Fatalf("the association returned an unusable relay address: %v", relay)
	}
}

// TestConnectOutlastsTheNegotiationDeadline pins the same guarantee for CONNECT,
// so the two paths cannot drift apart.
func TestConnectOutlastsTheNegotiationDeadline(t *testing.T) {
	shortenTimeouts(t, 200*time.Millisecond, 5*time.Second)

	echo := startEcho(t)
	d := &fakeDialer{remote: echo, delay: 600 * time.Millisecond}
	s := startServer(t, d)

	ip := echo.Addr().As4()
	c, rep := socksConnect(t, s.Addr(), atypIPv4, ip[:], echo.Port())
	defer c.Close()
	if rep != repSuccess {
		t.Fatalf("CONNECT failed after waiting longer than the negotiation deadline, reply %d", rep)
	}
}
