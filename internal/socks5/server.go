// Package socks5 implements the local, loopback-only SOCKS5 front end.
//
// # Egress policy
//
// This package contains no code that can reach the network on its own. Every
// outbound connection is created by the injected Dialer, which is the AmneziaWG
// userspace tunnel. There is deliberately no net.Dial, no net.Dialer and no
// http.Transport anywhere in this package, and a test enforces that (see
// noleak_test.go). When the tunnel is down, a SOCKS5 request fails with
// "network unreachable" instead of reaching the Internet over the default
// Windows network path.
//
// # Hostname handling
//
// A CONNECT request carrying ATYP=DOMAINNAME is resolved by Dialer.LookupHost,
// which queries only the DNS servers named in the AmneziaWG configuration, from
// inside the tunnel. This is socks5h behaviour: the Windows resolver is never
// used for SOCKS destinations.
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

	"github.com/ComoEstaisAmigos/awgsocks/internal/logging"
)

// SOCKS5 protocol constants.
const (
	socksVersion = 0x05

	methodNoAuth       = 0x00
	methodNoAcceptable = 0xFF

	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess              = 0x00
	repGeneralFailure       = 0x01
	repNetworkUnreachable   = 0x03
	repHostUnreachable      = 0x04
	repConnectionRefused    = 0x05
	repCommandNotSupported  = 0x07
	repAddrTypeNotSupported = 0x08
)

// Timeouts that tests need to shorten, which is the only reason they are
// variables.
//
// dialTimeout is deliberately longer than handshakeTimeout, so a request that
// arrives while the tunnel is still waiting for its first handshake outlives
// the negotiation deadline set when the client connected. That is safe for two
// reasons worth keeping: reply sets a fresh write deadline of its own before it
// writes, and both paths clear the negotiation deadline before they start
// reading from the client again.
var (
	// handshakeTimeout bounds the SOCKS5 greeting and request exchange.
	handshakeTimeout = 10 * time.Second
	// dialTimeout bounds one CONNECT attempt through the tunnel, including the
	// wait for a live AmneziaWG handshake. It is kept short enough that a
	// browser reports a clear error rather than appearing to hang.
	dialTimeout = 15 * time.Second
)

// Tuning.
const (
	// resolveTimeout bounds in-tunnel DNS resolution, including the retries the
	// tunnel performs for dropped DNS datagrams.
	resolveTimeout = 20 * time.Second
	// replyTimeout bounds writing the SOCKS5 reply back to the client.
	replyTimeout = 10 * time.Second
	// defaultMaxConns caps simultaneous SOCKS5 sessions.
	defaultMaxConns = 1024
	// relayBufferSize is the per-direction copy buffer.
	relayBufferSize = 32 * 1024
)

// Dialer is the egress the SOCKS5 server is allowed to use. It is implemented
// by the AmneziaWG tunnel.
type Dialer interface {
	// DialTCP opens a TCP connection to addr through the tunnel. It must fail
	// rather than use any other network path.
	DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	// LookupHost resolves host using only in-tunnel DNS servers.
	LookupHost(ctx context.Context, host string) ([]netip.Addr, error)
	// HasDNS reports whether in-tunnel DNS is configured at all.
	HasDNS() bool
	// ListenUDP opens an unconnected UDP socket inside the tunnel, for the
	// given address family. It backs SOCKS5 UDP ASSOCIATE.
	ListenUDP(ctx context.Context, ipv6 bool) (net.PacketConn, error)
}

// Stats is a snapshot of SOCKS5 server activity.
type Stats struct {
	Listen      string `json:"listen"`
	Listening   bool   `json:"listening"`
	Active      int64  `json:"active_connections"`
	Total       int64  `json:"total_connections"`
	Rejected    int64  `json:"rejected_connections"`
	Failed      int64  `json:"failed_connections"`
	BytesToPeer uint64 `json:"bytes_to_peer"`
	BytesToUser uint64 `json:"bytes_from_peer"`

	UDPEnabled       bool   `json:"udp_enabled"`
	UDPAssociations  int64  `json:"udp_associations"`
	UDPDatagramsUp   uint64 `json:"udp_datagrams_sent"`
	UDPDatagramsDown uint64 `json:"udp_datagrams_received"`
	UDPDropped       uint64 `json:"udp_datagrams_dropped"`
	UDPBytesUp       uint64 `json:"udp_bytes_sent"`
	UDPBytesDown     uint64 `json:"udp_bytes_received"`
}

// Server is the loopback-only SOCKS5 listener.
type Server struct {
	log      *logging.Logger
	dialer   Dialer
	listen   string
	maxConns int

	mu      sync.Mutex
	ln      net.Listener
	active  map[net.Conn]struct{}
	started bool

	closing atomic.Bool
	wg      sync.WaitGroup

	statActive   atomic.Int64
	statTotal    atomic.Int64
	statRejected atomic.Int64
	statFailed   atomic.Int64
	statTx       atomic.Uint64
	statRx       atomic.Uint64

	udpEnabled       bool
	statUDPAssoc     atomic.Int64
	statUDPSent      atomic.Uint64
	statUDPReceived  atomic.Uint64
	statUDPDropped   atomic.Uint64
	statUDPBytesUp   atomic.Uint64
	statUDPBytesDown atomic.Uint64
}

// ResolveMaxConns applies the documented default to a configured session cap.
//
// It is exported so that a caller comparing a new configuration against a
// running server compares the values actually in force. Without it an absent
// max_connections reads as 0 while the server runs at 1024, and every reload
// would look like a change.
func ResolveMaxConns(n int) int {
	if n <= 0 {
		return defaultMaxConns
	}
	return n
}

// New creates a SOCKS5 server with UDP ASSOCIATE enabled. listen must be a
// loopback address; maxConns of zero selects the default.
func New(log *logging.Logger, dialer Dialer, listen string, maxConns int) *Server {
	return NewWithOptions(log, dialer, listen, maxConns, true)
}

// NewWithOptions creates a SOCKS5 server, allowing UDP ASSOCIATE to be turned
// off.
//
// Turning it off is the more restrictive setting for the proxy itself, but it
// is usually the worse choice overall: a client that cannot send UDP through
// the proxy, such as a BitTorrent client doing DHT, normally sends it directly
// instead, outside the tunnel and from the real address.
func NewWithOptions(log *logging.Logger, dialer Dialer, listen string, maxConns int, udp bool) *Server {
	maxConns = ResolveMaxConns(maxConns)
	return &Server{
		log:        log,
		dialer:     dialer,
		listen:     listen,
		maxConns:   maxConns,
		active:     make(map[net.Conn]struct{}),
		udpEnabled: udp,
	}
}

// Start binds the listener and begins accepting connections.
func (s *Server) Start() error {
	ap, err := netip.ParseAddrPort(s.listen)
	if err != nil {
		return fmt.Errorf("invalid SOCKS5 listen address %q: %w", s.listen, err)
	}
	// Second line of defence: even if configuration validation were bypassed,
	// binding outside loopback is refused here.
	if !ap.Addr().IsLoopback() {
		return fmt.Errorf("SOCKS5 may only bind a loopback address, %q was rejected", s.listen)
	}

	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return fmt.Errorf("could not open the SOCKS5 listener on %s: %w", s.listen, err)
	}

	s.mu.Lock()
	s.ln = ln
	s.started = true
	s.mu.Unlock()

	s.log.Infof("SOCKS5 listener up on %s (no authentication, loopback only)", ln.Addr())

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop(ln)
	}()
	return nil
}

// MaxConns reports the concurrent session cap in force, with the default
// already resolved. Both fields below are written once at construction and
// never mutated, because the accept loop sizes its semaphore from MaxConns and
// a channel's capacity is fixed: changing either means building a new server.
func (s *Server) MaxConns() int { return s.maxConns }

// UDPAssociateEnabled reports whether this server offers UDP ASSOCIATE.
func (s *Server) UDPAssociateEnabled() bool { return s.udpEnabled }

// Addr reports the bound address, or the configured one when not started.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		return s.ln.Addr().String()
	}
	return s.listen
}

// Listening reports whether the listener is currently accepting.
func (s *Server) Listening() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started && !s.closing.Load()
}

// Stats returns a snapshot of server activity.
func (s *Server) Stats() Stats {
	return Stats{
		Listen:      s.Addr(),
		Listening:   s.Listening(),
		Active:      s.statActive.Load(),
		Total:       s.statTotal.Load(),
		Rejected:    s.statRejected.Load(),
		Failed:      s.statFailed.Load(),
		BytesToPeer: s.statTx.Load(),
		BytesToUser: s.statRx.Load(),

		UDPEnabled:       s.udpEnabled,
		UDPAssociations:  s.statUDPAssoc.Load(),
		UDPDatagramsUp:   s.statUDPSent.Load(),
		UDPDatagramsDown: s.statUDPReceived.Load(),
		UDPDropped:       s.statUDPDropped.Load(),
		UDPBytesUp:       s.statUDPBytesUp.Load(),
		UDPBytesDown:     s.statUDPBytesDown.Load(),
	}
}

// Stop stops accepting new connections and closes the ones still open, then
// waits for every session goroutine to finish.
func (s *Server) Stop() {
	if s.closing.Swap(true) {
		return
	}
	s.mu.Lock()
	ln := s.ln
	s.ln = nil
	conns := make([]net.Conn, 0, len(s.active))
	for c := range s.active {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	if ln != nil {
		ln.Close()
	}
	// Once accepting has stopped, existing sessions are closed so that the
	// service can shut down promptly instead of waiting on idle sockets.
	for _, c := range conns {
		c.Close()
	}
	s.wg.Wait()

	s.mu.Lock()
	s.started = false
	s.mu.Unlock()
	s.log.Infof("SOCKS5 listener closed")
}

func (s *Server) acceptLoop(ln net.Listener) {
	sem := make(chan struct{}, s.maxConns)
	// Back off briefly on a transient accept error rather than losing the
	// listener; errors that keep repeating mean it is genuinely broken and the
	// loop gives up.
	var consecutiveErrors int
	const maxConsecutiveErrors = 10

	for {
		c, err := ln.Accept()
		if err != nil {
			if s.closing.Load() {
				return
			}
			consecutiveErrors++
			if consecutiveErrors >= maxConsecutiveErrors {
				s.log.Errorf("SOCKS5 listener stopped after %d consecutive accept errors: %v",
					consecutiveErrors, err)
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			s.log.Warnf("SOCKS5 accept error (%d/%d): %v", consecutiveErrors, maxConsecutiveErrors, err)
			time.Sleep(time.Duration(consecutiveErrors) * 50 * time.Millisecond)
			continue
		}
		consecutiveErrors = 0

		// A connection from another machine is never served.
		if !isLoopbackConn(c) {
			s.statRejected.Add(1)
			s.log.Warnf("rejected a non-loopback SOCKS5 connection from %s", c.RemoteAddr())
			c.Close()
			continue
		}

		select {
		case sem <- struct{}{}:
		default:
			s.statRejected.Add(1)
			s.log.Warnf("concurrent connection limit (%d) reached, connection rejected", s.maxConns)
			c.Close()
			continue
		}

		s.trackConn(c)
		s.statTotal.Add(1)
		s.statActive.Add(1)
		s.wg.Add(1)
		go func(c net.Conn) {
			defer func() {
				<-sem
				s.statActive.Add(-1)
				s.untrackConn(c)
				c.Close()
				s.wg.Done()
			}()
			s.handle(c)
		}(c)
	}
}

func (s *Server) trackConn(c net.Conn) {
	s.mu.Lock()
	s.active[c] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) untrackConn(c net.Conn) {
	s.mu.Lock()
	delete(s.active, c)
	s.mu.Unlock()
}

func isLoopbackConn(c net.Conn) bool {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.Unmap().IsLoopback()
}

// handle runs one SOCKS5 session.
func (s *Server) handle(client net.Conn) {
	if err := client.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return
	}

	if err := s.negotiate(client); err != nil {
		s.log.Debugf("SOCKS5 negotiation failed for %s: %v", client.RemoteAddr(), err)
		return
	}

	cmd, dest, err := readRequest(client)
	if err != nil {
		s.log.Debugf("SOCKS5 request failed for %s: %v", client.RemoteAddr(), err)
		return
	}

	switch cmd {
	case cmdConnect:
		if dest.port == 0 {
			s.log.Debugf("SOCKS5 CONNECT rejected: destination port is zero (%s)", client.RemoteAddr())
			s.reply(client, repGeneralFailure, netip.AddrPort{})
			return
		}
	case cmdUDPAssociate:
		s.handleUDPAssociate(client, dest)
		return
	default:
		name := "unknown"
		if cmd == cmdBind {
			name = "BIND"
		}
		s.log.Debugf("unsupported SOCKS5 command %s from %s", name, client.RemoteAddr())
		s.reply(client, repCommandNotSupported, netip.AddrPort{})
		return
	}

	// The egress attempt carries its own timeouts. Without clearing the
	// negotiation deadline here, a slow attempt would let it expire and the
	// client would see a closed connection instead of a proper SOCKS5 reply.
	client.SetDeadline(time.Time{})

	remote, target, rep := s.connect(dest)
	if rep != repSuccess {
		s.statFailed.Add(1)
		s.reply(client, rep, netip.AddrPort{})
		return
	}
	defer remote.Close()

	if err := s.reply(client, repSuccess, target); err != nil {
		s.log.Debugf("could not write the SOCKS5 reply: %v", err)
		return
	}

	// No deadline during relaying: long lived connections such as torrents,
	// websockets and long polling must not be cut. The deadline was already
	// cleared above, so only one of the peers or a service shutdown ends it.
	s.log.Debugf("SOCKS5 connection established: %s -> %s through the tunnel", dest, target)
	s.relay(client, remote)
}

// negotiate performs the SOCKS5 method negotiation. Only "no authentication" is
// offered, matching the documented Firefox and qBittorrent setup.
func (s *Server) negotiate(c net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(c, header); err != nil {
		return fmt.Errorf("could not read the greeting: %w", err)
	}
	if header[0] != socksVersion {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}
	n := int(header[1])
	if n == 0 {
		return errors.New("the client offered no authentication method")
	}
	methods := make([]byte, n)
	if _, err := io.ReadFull(c, methods); err != nil {
		return fmt.Errorf("could not read the method list: %w", err)
	}
	for _, m := range methods {
		if m == methodNoAuth {
			_, err := c.Write([]byte{socksVersion, methodNoAuth})
			return err
		}
	}
	c.Write([]byte{socksVersion, methodNoAcceptable})
	return errors.New("the client does not support connecting without authentication")
}

// destination is a parsed SOCKS5 request target.
type destination struct {
	host string // hostname; when empty, addr is used
	addr netip.Addr
	port uint16
}

func (d destination) String() string {
	if d.host != "" {
		return net.JoinHostPort(d.host, fmt.Sprint(d.port))
	}
	return netip.AddrPortFrom(d.addr, d.port).String()
}

func readRequest(c net.Conn) (cmd byte, dest destination, err error) {
	header := make([]byte, 4)
	if _, err = io.ReadFull(c, header); err != nil {
		return 0, dest, fmt.Errorf("could not read the request header: %w", err)
	}
	if header[0] != socksVersion {
		return 0, dest, fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}
	cmd = header[1]

	switch header[3] {
	case atypIPv4:
		buf := make([]byte, 4)
		if _, err = io.ReadFull(c, buf); err != nil {
			return cmd, dest, fmt.Errorf("could not read the IPv4 destination: %w", err)
		}
		dest.addr = netip.AddrFrom4([4]byte(buf))
	case atypIPv6:
		buf := make([]byte, 16)
		if _, err = io.ReadFull(c, buf); err != nil {
			return cmd, dest, fmt.Errorf("could not read the IPv6 destination: %w", err)
		}
		dest.addr = netip.AddrFrom16([16]byte(buf))
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err = io.ReadFull(c, lenBuf); err != nil {
			return cmd, dest, fmt.Errorf("could not read the domain name length: %w", err)
		}
		if lenBuf[0] == 0 {
			return cmd, dest, errors.New("empty domain name")
		}
		name := make([]byte, lenBuf[0])
		if _, err = io.ReadFull(c, name); err != nil {
			return cmd, dest, fmt.Errorf("could not read the domain name: %w", err)
		}
		host := string(name)
		// Some clients put an IP in the domain field; treat it as an address.
		if a, perr := netip.ParseAddr(host); perr == nil {
			dest.addr = a.Unmap()
		} else {
			dest.host = host
		}
	default:
		// The stream cannot be resynchronised once the address type is unknown,
		// so a reply is written here and the caller closes the connection.
		writeReply(c, repAddrTypeNotSupported, netip.AddrPort{})
		return cmd, dest, fmt.Errorf("unsupported address type: %d", header[3])
	}

	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(c, portBuf); err != nil {
		return cmd, dest, fmt.Errorf("could not read the port: %w", err)
	}
	dest.port = binary.BigEndian.Uint16(portBuf)
	// Port zero is not rejected here: it is meaningless for CONNECT but
	// perfectly normal for UDP ASSOCIATE, where the client is describing the
	// address it will send from and usually does not know it yet. The CONNECT
	// path checks it instead.
	return cmd, dest, nil
}

// connect resolves the destination when needed and opens the tunnelled
// connection. It returns the SOCKS5 reply code to send on failure.
func (s *Server) connect(dest destination) (net.Conn, netip.AddrPort, byte) {
	var candidates []netip.Addr

	if dest.host != "" {
		if !s.dialer.HasDNS() {
			s.log.Warnf("hostname request for %s rejected: no in-tunnel DNS is configured, "+
				"and the system resolver will not be used", dest.host)
			return nil, netip.AddrPort{}, repHostUnreachable
		}
		ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
		addrs, err := s.dialer.LookupHost(ctx, dest.host)
		cancel()
		if err != nil {
			s.log.Debugf("in-tunnel DNS resolution failed for %s: %v", dest.host, err)
			return nil, netip.AddrPort{}, replyForError(err, repHostUnreachable)
		}
		candidates = addrs
	} else {
		candidates = []netip.Addr{dest.addr}
	}

	var lastErr error
	for _, a := range candidates {
		target := netip.AddrPortFrom(a.Unmap(), dest.port)
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		c, err := s.dialer.DialTCP(ctx, target)
		cancel()
		if err == nil {
			return c, target, repSuccess
		}
		lastErr = err
		s.log.Debugf("could not reach %s through the tunnel: %v", target, err)
	}

	if lastErr == nil {
		lastErr = errors.New("no destination address")
	}
	s.log.Warnf("SOCKS5 request for %s failed: %v", dest, lastErr)
	return nil, netip.AddrPort{}, replyForError(lastErr, repHostUnreachable)
}

// relay copies data in both directions until either side closes, propagating a
// half-close so that protocols relying on EOF keep working.
func (s *Server) relay(client, remote net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := copyBuffer(remote, client)
		s.statTx.Add(uint64(n))
		closeWrite(remote)
	}()
	go func() {
		defer wg.Done()
		n, _ := copyBuffer(client, remote)
		s.statRx.Add(uint64(n))
		closeWrite(client)
	}()

	wg.Wait()
}

func copyBuffer(dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, relayBufferSize)
	return io.CopyBuffer(dst, src, buf)
}

// halfCloser is implemented by both net.TCPConn and the gVisor gonet.TCPConn.
type halfCloser interface{ CloseWrite() error }

func closeWrite(c net.Conn) {
	if hc, ok := c.(halfCloser); ok {
		hc.CloseWrite()
		return
	}
	c.Close()
}

// reply writes a SOCKS5 reply under its own write deadline, so that a slow or
// stalled client cannot leave the session goroutine blocked forever.
func (s *Server) reply(c net.Conn, rep byte, bound netip.AddrPort) error {
	c.SetWriteDeadline(time.Now().Add(replyTimeout))
	err := writeReply(c, rep, bound)
	c.SetWriteDeadline(time.Time{})
	return err
}

// writeReply sends a SOCKS5 reply. bound may be the zero value for failures.
func writeReply(c net.Conn, rep byte, bound netip.AddrPort) error {
	buf := []byte{socksVersion, rep, 0x00}
	addr := bound.Addr()
	switch {
	case addr.Is4():
		b := addr.As4()
		buf = append(buf, atypIPv4)
		buf = append(buf, b[:]...)
	case addr.Is6():
		b := addr.As16()
		buf = append(buf, atypIPv6)
		buf = append(buf, b[:]...)
	default:
		buf = append(buf, atypIPv4, 0, 0, 0, 0)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], bound.Port())
	buf = append(buf, port[:]...)
	_, err := c.Write(buf)
	return err
}
