package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// UDP relay tuning.
const (
	// udpBufferSize is the largest datagram the relay will handle. It is the
	// maximum a UDP datagram can be; anything near it is fragmented by the
	// tunnel long before it gets here, but reading short would silently
	// truncate a client datagram, which is worse than allocating the buffer.
	udpBufferSize = 65535

	// udpIdleTimeout closes an association that has carried no datagram for
	// this long, even if the client left the control connection open.
	udpIdleTimeout = 5 * time.Minute
)

// errUDPFragmented is returned for datagrams that use the SOCKS5 fragmentation
// field. RFC 1928 allows a server to drop them, and no real client relies on it.
var errUDPFragmented = errors.New("fragmented SOCKS5 UDP datagrams are not supported")

// udpRelay carries datagrams between one SOCKS5 client and the tunnel.
//
// It behaves like a NAT: a single in-tunnel socket per address family serves
// every destination, and a reply is matched back to the client by the source
// address the tunnel reports. That is what BitTorrent DHT needs, where one
// client talks to hundreds of peers from one socket.
type udpRelay struct {
	srv *Server

	// client is the loopback-bound socket the SOCKS5 client sends to. It is
	// wrapped so that it can only ever reply to a loopback address.
	client *loopbackPacketConn

	// expect is the client address datagrams are accepted from. It may be
	// learned from the first datagram when the client did not declare one.
	expect   netip.AddrPort
	expectMu sync.Mutex

	mu     sync.Mutex
	tunnel map[bool]net.PacketConn // false = IPv4, true = IPv6

	lastActive atomic.Int64
	closed     atomic.Bool
	closeOnce  sync.Once
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
}

// handleUDPAssociate serves a UDP ASSOCIATE request.
//
// The relay lives exactly as long as the TCP control connection, which is what
// RFC 1928 requires and what lets a client tear the association down simply by
// closing the socket.
func (s *Server) handleUDPAssociate(client net.Conn, declared destination) {
	if !s.udpEnabled {
		s.log.Debugf("SOCKS5 UDP ASSOCIATE rejected: udp_associate is disabled (%s)", client.RemoteAddr())
		s.reply(client, repCommandNotSupported, netip.AddrPort{})
		return
	}

	// The client tells us which address it will send datagrams from. An
	// unspecified value is normal and means "decided by the first datagram".
	var expect netip.AddrPort
	if declared.host == "" && declared.addr.IsValid() {
		expect = netip.AddrPortFrom(declared.addr.Unmap(), declared.port)
	}

	relay, err := s.newUDPRelay(expect)
	if err != nil {
		s.statFailed.Add(1)
		s.log.Errorf("SOCKS5 UDP relay could not be created: %v", err)
		s.reply(client, repGeneralFailure, netip.AddrPort{})
		return
	}
	defer relay.Close()

	// Open the in-tunnel socket now rather than on the first datagram, so that
	// a client is never told an association exists when the tunnel cannot
	// carry it. UDP has no way to report that failure later.
	if err := relay.warmUp(); err != nil {
		s.statFailed.Add(1)
		s.log.Warnf("SOCKS5 UDP ASSOCIATE failed: %v", err)
		s.reply(client, replyForError(err, repNetworkUnreachable), netip.AddrPort{})
		return
	}

	// The association exists from the moment the relay is usable, so the
	// counter is raised before the reply. Raising it afterwards would let a
	// client observe a working relay that status still reports as absent.
	s.statUDPAssoc.Add(1)
	defer s.statUDPAssoc.Add(-1)

	bound := relay.LocalAddrPort()
	if err := s.reply(client, repSuccess, bound); err != nil {
		s.log.Debugf("could not write the UDP ASSOCIATE reply: %v", err)
		return
	}
	s.log.Debugf("SOCKS5 UDP association open: client %s, relay %s", client.RemoteAddr(), bound)

	// The control connection carries no further data. Holding it open is the
	// association's lifetime, so block until the client closes it or the
	// service shuts the connection down.
	client.SetDeadline(time.Time{})
	io.Copy(io.Discard, client)
	s.log.Debugf("SOCKS5 UDP association closed: client %s", client.RemoteAddr())
}

// warmUp opens the in-tunnel socket for whichever address family the tunnel
// carries, so that failures surface while the client is still listening.
func (r *udpRelay) warmUp() error {
	var firstErr error
	for _, ipv6 := range []bool{false, true} {
		if _, err := r.tunnelConn(ipv6); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return nil
	}
	return firstErr
}

// newUDPRelay binds the loopback relay socket and starts the client pump.
//
// declared is the address the client said it would send from, taken from the
// UDP ASSOCIATE request. Clients commonly send an unspecified address there, in
// which case the first datagram decides.
func (s *Server) newUDPRelay(declared netip.AddrPort) (*udpRelay, error) {
	// Loopback only, exactly like the TCP listener: a UDP relay reachable from
	// the network would be an open, unauthenticated tunnel egress.
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, fmt.Errorf("could not open the UDP relay socket: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	r := &udpRelay{
		srv:    s,
		client: &loopbackPacketConn{UDPConn: pc},
		expect: declared,
		tunnel: make(map[bool]net.PacketConn),
		ctx:    ctx,
		cancel: cancel,
	}
	r.touch()

	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		r.pumpFromClient()
	}()
	go func() {
		defer r.wg.Done()
		r.watchIdle()
	}()
	return r, nil
}

// LocalAddrPort is the address the client must send its datagrams to.
func (r *udpRelay) LocalAddrPort() netip.AddrPort {
	if a, ok := r.client.LocalAddr().(*net.UDPAddr); ok {
		addr, _ := netip.AddrFromSlice(a.IP)
		return netip.AddrPortFrom(addr.Unmap(), uint16(a.Port))
	}
	return netip.AddrPort{}
}

func (r *udpRelay) touch() { r.lastActive.Store(time.Now().UnixNano()) }

// Close tears the association down and releases every socket it owns.
func (r *udpRelay) Close() {
	r.closeOnce.Do(func() {
		r.closed.Store(true)
		r.cancel()
		r.client.Close()

		r.mu.Lock()
		for _, c := range r.tunnel {
			c.Close()
		}
		r.tunnel = nil
		r.mu.Unlock()

		r.wg.Wait()
	})
}

// watchIdle closes an association that has gone quiet, so that a client which
// leaves the control connection open forever does not pin a tunnel socket.
func (r *udpRelay) watchIdle() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			last := time.Unix(0, r.lastActive.Load())
			if time.Since(last) > udpIdleTimeout {
				r.srv.log.Debugf("SOCKS5 UDP association closed after %s idle", udpIdleTimeout)
				go r.Close()
				return
			}
		}
	}
}

// pumpFromClient reads datagrams from the SOCKS5 client, strips the SOCKS5 UDP
// header and forwards the payload through the tunnel.
func (r *udpRelay) pumpFromClient() {
	buf := make([]byte, udpBufferSize)
	for {
		n, from, err := r.client.ReadFromUDPAddrPort(buf)
		if err != nil {
			if !r.closed.Load() {
				r.srv.log.Debugf("SOCKS5 UDP relay read error: %v", err)
			}
			return
		}
		r.touch()

		if !r.acceptFrom(from) {
			r.srv.statUDPDropped.Add(1)
			r.srv.log.Warnf("SOCKS5 UDP datagram from an unexpected source rejected: %s", from)
			continue
		}

		dst, payload, err := parseUDPHeader(buf[:n])
		if err != nil {
			r.srv.statUDPDropped.Add(1)
			r.srv.log.Debugf("SOCKS5 UDP header rejected: %v", err)
			continue
		}

		// The payload aliases buf, which the next read overwrites, so the
		// forward has to finish with it before looping. forward copies what it
		// needs before returning.
		r.forward(dst, payload)
	}
}

// acceptFrom enforces that only the associated client may use this relay. When
// the client declared no address, the first datagram claims the association.
func (r *udpRelay) acceptFrom(from netip.AddrPort) bool {
	if !from.Addr().Unmap().IsLoopback() {
		return false
	}
	r.expectMu.Lock()
	defer r.expectMu.Unlock()

	if !r.expect.IsValid() || r.expect.Addr().IsUnspecified() || r.expect.Port() == 0 {
		r.expect = from
		return true
	}
	return r.expect == from
}

// forward resolves the destination when needed and sends the payload through
// the tunnel.
func (r *udpRelay) forward(dst udpDestination, payload []byte) {
	target, ok := r.resolve(dst)
	if !ok {
		r.srv.statUDPDropped.Add(1)
		return
	}

	conn, err := r.tunnelConn(target.Addr().Is6())
	if err != nil {
		r.srv.statUDPDropped.Add(1)
		r.srv.log.Debugf("no in-tunnel UDP socket for %s: %v", target, err)
		return
	}

	n, err := conn.WriteTo(payload, net.UDPAddrFromAddrPort(target))
	if err != nil {
		r.srv.statUDPDropped.Add(1)
		r.srv.log.Debugf("could not send a UDP datagram to %s through the tunnel: %v", target, err)
		return
	}
	r.srv.statUDPSent.Add(1)
	r.srv.statUDPBytesUp.Add(uint64(n))
}

// resolve turns a SOCKS5 UDP destination into an address, using in-tunnel DNS
// for hostnames so that a UDP destination cannot leak a name to the system
// resolver either.
func (r *udpRelay) resolve(dst udpDestination) (netip.AddrPort, bool) {
	if dst.host == "" {
		return netip.AddrPortFrom(dst.addr.Unmap(), dst.port), true
	}
	if !r.srv.dialer.HasDNS() {
		r.srv.log.Warnf("UDP datagram to %s dropped: no in-tunnel DNS configured", dst.host)
		return netip.AddrPort{}, false
	}
	ctx, cancel := context.WithTimeout(r.ctx, resolveTimeout)
	addrs, err := r.srv.dialer.LookupHost(ctx, dst.host)
	cancel()
	if err != nil || len(addrs) == 0 {
		r.srv.log.Debugf("in-tunnel DNS lookup failed for UDP destination %s: %v", dst.host, err)
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addrs[0].Unmap(), dst.port), true
}

// tunnelConn returns the in-tunnel socket for the given family, opening it and
// starting its reply pump on first use.
func (r *udpRelay) tunnelConn(ipv6 bool) (net.PacketConn, error) {
	r.mu.Lock()
	if r.tunnel == nil {
		r.mu.Unlock()
		return nil, errors.New("relay is closed")
	}
	if c, ok := r.tunnel[ipv6]; ok {
		r.mu.Unlock()
		return c, nil
	}
	r.mu.Unlock()

	ctx, cancel := context.WithTimeout(r.ctx, dialTimeout)
	c, err := r.srv.dialer.ListenUDP(ctx, ipv6)
	cancel()
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	if r.tunnel == nil {
		r.mu.Unlock()
		c.Close()
		return nil, errors.New("relay is closed")
	}
	// Another datagram may have opened the same family in the meantime.
	if existing, ok := r.tunnel[ipv6]; ok {
		r.mu.Unlock()
		c.Close()
		return existing, nil
	}
	r.tunnel[ipv6] = c
	r.mu.Unlock()

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.pumpFromTunnel(c)
	}()
	return c, nil
}

// pumpFromTunnel reads replies arriving inside the tunnel, wraps each one in a
// SOCKS5 UDP header naming its source, and delivers it to the client.
func (r *udpRelay) pumpFromTunnel(conn net.PacketConn) {
	buf := make([]byte, udpBufferSize)
	out := make([]byte, 0, udpBufferSize)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if !r.closed.Load() {
				r.srv.log.Debugf("in-tunnel UDP read error: %v", err)
			}
			return
		}
		r.touch()

		src, ok := addrPortOf(from)
		if !ok {
			continue
		}

		r.expectMu.Lock()
		client := r.expect
		r.expectMu.Unlock()
		if !client.IsValid() || client.Port() == 0 {
			// Nothing has claimed the association yet, so there is nobody to
			// deliver to.
			continue
		}

		// Counted on arrival rather than on delivery, so that the number
		// reflects what the tunnel carried. A delivery failure is counted
		// separately as a drop.
		r.srv.statUDPReceived.Add(1)
		r.srv.statUDPBytesDown.Add(uint64(n))

		out = buildUDPHeader(out[:0], src)
		out = append(out, buf[:n]...)
		if _, err := r.client.WriteToUDPAddrPort(out, client); err != nil {
			r.srv.statUDPDropped.Add(1)
			if !r.closed.Load() {
				r.srv.log.Debugf("could not deliver a UDP reply to the client: %v", err)
			}
			continue
		}
	}
}

// ---------------------------------------------------------------------------
// SOCKS5 UDP header, RFC 1928 section 7
// ---------------------------------------------------------------------------

type udpDestination struct {
	host string // set for ATYP=DOMAINNAME
	addr netip.Addr
	port uint16
}

// parseUDPHeader splits a SOCKS5 UDP datagram into its destination and payload.
//
//	+-----+------+------+----------+----------+----------+
//	| RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+-----+------+------+----------+----------+----------+
//	|  2  |  1   |  1   | Variable |    2     | Variable |
//	+-----+------+------+----------+----------+----------+
func parseUDPHeader(b []byte) (udpDestination, []byte, error) {
	var dst udpDestination
	if len(b) < 4 {
		return dst, nil, errors.New("datagram shorter than the SOCKS5 UDP header")
	}
	if b[0] != 0 || b[1] != 0 {
		return dst, nil, errors.New("reserved bytes are not zero")
	}
	if b[2] != 0 {
		return dst, nil, errUDPFragmented
	}

	rest := b[4:]
	switch b[3] {
	case atypIPv4:
		if len(rest) < 4+2 {
			return dst, nil, errors.New("truncated IPv4 destination")
		}
		dst.addr = netip.AddrFrom4([4]byte(rest[:4]))
		rest = rest[4:]
	case atypIPv6:
		if len(rest) < 16+2 {
			return dst, nil, errors.New("truncated IPv6 destination")
		}
		dst.addr = netip.AddrFrom16([16]byte(rest[:16]))
		rest = rest[16:]
	case atypDomain:
		if len(rest) < 1 {
			return dst, nil, errors.New("truncated domain destination")
		}
		l := int(rest[0])
		if l == 0 {
			return dst, nil, errors.New("empty domain name")
		}
		if len(rest) < 1+l+2 {
			return dst, nil, errors.New("truncated domain destination")
		}
		host := string(rest[1 : 1+l])
		if a, err := netip.ParseAddr(host); err == nil {
			dst.addr = a.Unmap()
		} else {
			dst.host = host
		}
		rest = rest[1+l:]
	default:
		return dst, nil, fmt.Errorf("unsupported address type: %d", b[3])
	}

	dst.port = binary.BigEndian.Uint16(rest[:2])
	if dst.port == 0 {
		return dst, nil, errors.New("destination port is zero")
	}
	return dst, rest[2:], nil
}

// buildUDPHeader appends a SOCKS5 UDP header naming src to dst.
func buildUDPHeader(dst []byte, src netip.AddrPort) []byte {
	dst = append(dst, 0, 0, 0) // RSV, RSV, FRAG
	addr := src.Addr().Unmap()
	if addr.Is4() {
		b := addr.As4()
		dst = append(dst, atypIPv4)
		dst = append(dst, b[:]...)
	} else {
		b := addr.As16()
		dst = append(dst, atypIPv6)
		dst = append(dst, b[:]...)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], src.Port())
	return append(dst, port[:]...)
}

func addrPortOf(a net.Addr) (netip.AddrPort, bool) {
	switch v := a.(type) {
	case *net.UDPAddr:
		addr, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(addr.Unmap(), uint16(v.Port)), true
	default:
		ap, err := netip.ParseAddrPort(a.String())
		if err != nil {
			return netip.AddrPort{}, false
		}
		return ap, true
	}
}

// ---------------------------------------------------------------------------
// Loopback guard
// ---------------------------------------------------------------------------

// loopbackPacketConn is the client-facing UDP socket. Writing to a non-loopback
// address is refused.
//
// The socket is already bound to 127.0.0.1, so nothing outside the machine can
// reach it, but a bound socket can still send anywhere. This wrapper turns the
// "local only" property into something the code enforces rather than something
// the binding merely implies.
type loopbackPacketConn struct {
	*net.UDPConn
}

// ErrNonLoopbackTarget is returned when something tries to send a SOCKS5 UDP
// reply outside the local machine.
var ErrNonLoopbackTarget = errors.New("the SOCKS5 UDP relay may only reply to a loopback address")

func (c *loopbackPacketConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	if !addr.Addr().Unmap().IsLoopback() {
		return 0, ErrNonLoopbackTarget
	}
	return c.UDPConn.WriteToUDPAddrPort(b, addr)
}
