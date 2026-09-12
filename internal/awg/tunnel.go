// Package awg runs a real AmneziaWG client tunnel entirely in userspace and
// exposes it as a dialer.
//
// # Architecture
//
// AWGSocks never creates a Windows network adapter and never touches Windows
// routing. The tunnel is assembled from three upstream pieces:
//
//	netstack.CreateNetTUN   a gVisor userspace TCP/IP stack that presents itself
//	                        to the AmneziaWG device as a tun.Device. Packets
//	                        written to it are IP packets; packets read from it
//	                        are IP packets. Windows has no idea it exists.
//
//	device.NewDevice        the real AmneziaWG userspace implementation. It
//	                        performs Noise cryptography plus every AmneziaWG
//	                        obfuscation feature (Jc/Jmin/Jmax, S1-S4, H1-H4,
//	                        I1-I5, HeaderProtectionKey, ...). AWGSocks
//	                        reimplements none of it.
//
//	conn bind               a regular Windows UDP socket. This is the only
//	                        socket that touches the real network, and it reaches
//	                        the AmneziaWG endpoint over the machine's normal
//	                        default route, because that route is never modified.
//	                        See bind.go for the two upstream implementations.
//
// A SOCKS5 CONNECT becomes tunnel traffic like this:
//
//	SOCKS5 CONNECT
//	  -> Tunnel.DialTCP
//	  -> gVisor netstack opens a TCP connection from the tunnel-local address
//	  -> netstack emits IP packets into the AmneziaWG device
//	  -> AmneziaWG encrypts and obfuscates them
//	  -> conn bind sends them as UDP to the configured endpoint
//
// There is no net.Dial to the destination anywhere in this path, so there is no
// way for a SOCKS5 request to reach the Internet outside the tunnel.
package awg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"github.com/ComoEstaisAmigos/awgsocks/internal/config"
	"github.com/ComoEstaisAmigos/awgsocks/internal/dns"
	"github.com/ComoEstaisAmigos/awgsocks/internal/logging"
)

// State is the observable state of the tunnel.
type State int32

// Tunnel states.
const (
	StateStopped State = iota
	StateConnecting
	StateConnected
	StateReconnecting
	StateFailed
)

// String renders the state for CLI output.
func (s State) String() string {
	switch s {
	case StateStopped:
		return "stopped"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateReconnecting:
		return "reconnecting"
	case StateFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// Errors returned by the tunnel. Every one of them is a hard failure: the
// caller must not fall back to any other network path.
var (
	// ErrTunnelDown means the AmneziaWG tunnel is not running.
	ErrTunnelDown = errors.New("the AmneziaWG tunnel is not running")
	// ErrNotReady means the tunnel is running but has no live handshake.
	ErrNotReady = errors.New("the AmneziaWG handshake has not completed")
	// ErrNoDNS means the configuration defines no DNS server inside the tunnel.
	ErrNoDNS = errors.New("the configuration names no DNS server, so a hostname cannot be resolved inside the tunnel")
	// ErrNoRoute means the tunnel carries no address of the requested family.
	ErrNoRoute = errors.New("the tunnel carries no address of that family")
)

// Timing policy.
const (
	// handshakeStaleAfter matches WireGuard RejectAfterTime: once the newest
	// handshake is older than this, no keypair can carry traffic any more.
	handshakeStaleAfter = 180 * time.Second

	// superviseInterval is how often tunnel health is sampled.
	superviseInterval = time.Second

	// minBackoff and maxBackoff bound the reconnect backoff.
	minBackoff = 1 * time.Second
	maxBackoff = 60 * time.Second

	// uapiTimeout bounds the upstream ToUAPI call, which resolves a hostname
	// endpoint through the Windows resolver and retries internally.
	uapiTimeout = 45 * time.Second
)

// dnsAttemptTimeouts bounds each in-tunnel resolution attempt, growing like a
// stub resolver does. DNS runs over UDP inside the tunnel, so a dropped
// datagram is normal on a lossy link, and the upstream netstack resolver waits
// a fixed five seconds per server before retrying. Cutting the first attempt
// short turns a lost packet into a two second delay instead of five, and the
// growing budget still allows for a genuinely slow server.
var dnsAttemptTimeouts = []time.Duration{
	2 * time.Second,
	4 * time.Second,
	6 * time.Second,
}

// Tunnel owns the userspace AmneziaWG device and its network stack.
type Tunnel struct {
	log *logging.Logger

	mu       sync.RWMutex
	cfg      *config.Tunnel
	dev      *device.Device
	tnet     *netstack.Net
	peerKeys []device.NoisePublicKey
	ready    chan struct{}
	running  bool

	state      atomic.Int32
	lastErr    atomic.Pointer[string]
	reconnects atomic.Int64
	startedAt  atomic.Pointer[time.Time]

	kick   chan struct{}
	cancel context.CancelFunc
	wg     sync.WaitGroup

	bindMode     BindMode
	netstackMode NetstackMode
	resolver     *dns.Resolver
}

// New creates a stopped tunnel bound to the given configuration, using the
// default UDP bind. See NewWithBind to select one explicitly.
func New(log *logging.Logger, cfg *config.Tunnel) *Tunnel {
	return NewWithBind(log, cfg, BindStd)
}

// NewWithBind creates a stopped tunnel that will use the given upstream UDP
// bind implementation for the AmneziaWG endpoint socket.
func NewWithBind(log *logging.Logger, cfg *config.Tunnel, mode BindMode) *Tunnel {
	return NewWithBindAndNetstack(log, cfg, mode, NetstackUpstream)
}

// NewWithBindAndNetstack additionally selects the experimental network stack
// handoff. Only benchmarks and their correctness tests pass anything other
// than NetstackUpstream; nothing in the application can reach this.
func NewWithBindAndNetstack(log *logging.Logger, cfg *config.Tunnel, mode BindMode, netstackMode NetstackMode) *Tunnel {
	t := &Tunnel{
		log:          log,
		cfg:          cfg,
		ready:        make(chan struct{}),
		kick:         make(chan struct{}, 1),
		bindMode:     mode,
		netstackMode: netstackMode,
	}
	t.resolver = dns.New(t.lookupUncached)
	t.state.Store(int32(StateStopped))
	return t
}

// BindMode reports which upstream UDP bind the tunnel uses.
func (t *Tunnel) BindMode() BindMode { return t.bindMode }

// BindDescription renders the active UDP bind for status output.
func (t *Tunnel) BindDescription() string { return bindDescription(t.bindMode) }

// Config returns the configuration the tunnel is currently built from.
func (t *Tunnel) Config() *config.Tunnel {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.cfg
}

// State reports the current tunnel state.
func (t *Tunnel) State() State { return State(t.state.Load()) }

// LastError returns the most recent tunnel-level error message, if any.
func (t *Tunnel) LastError() string {
	if p := t.lastErr.Load(); p != nil {
		return *p
	}
	return ""
}

// Reconnects reports how many reconnect cycles have been performed.
func (t *Tunnel) Reconnects() int64 { return t.reconnects.Load() }

// StartedAt reports when the tunnel last came up, or the zero time.
func (t *Tunnel) StartedAt() time.Time {
	if p := t.startedAt.Load(); p != nil {
		return *p
	}
	return time.Time{}
}

func (t *Tunnel) setState(s State)    { t.state.Store(int32(s)) }
func (t *Tunnel) setError(msg string) { t.lastErr.Store(&msg) }
func (t *Tunnel) clearError()         { empty := ""; t.lastErr.Store(&empty) }

// Start brings the tunnel up: it creates the userspace network stack, creates
// the AmneziaWG device, applies the configuration over UAPI and starts the
// supervisor that keeps the handshake alive.
func (t *Tunnel) Start(ctx context.Context) error {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return errors.New("the tunnel is already running")
	}
	cfg := t.cfg
	t.mu.Unlock()

	if cfg == nil {
		return errors.New("no tunnel configuration has been loaded")
	}

	t.setState(StateConnecting)
	t.clearError()

	dev, tnet, keys, err := buildDevice(ctx, t.log, cfg, t.bindMode, t.netstackMode)
	if err != nil {
		t.setState(StateFailed)
		t.setError(err.Error())
		return err
	}

	superviseCtx, cancel := context.WithCancel(context.Background())

	t.mu.Lock()
	t.dev = dev
	t.tnet = tnet
	t.peerKeys = keys
	t.ready = make(chan struct{})
	t.running = true
	t.cancel = cancel
	t.mu.Unlock()

	// A new tunnel must not inherit answers resolved under the previous one.
	t.resolver.Flush()

	now := time.Now()
	t.startedAt.Store(&now)

	t.log.Infof("AmneziaWG tunnel up: endpoint=%s, tunnel address=%s, MTU=%d",
		cfg.Endpoint(), formatPrefixes(cfg.AddressPrefixes), cfg.MTU)
	t.log.Infof("AmneziaWG parameters: %s", describeParams(cfg))
	t.log.Infof("UDP endpoint socket: %s", bindDescription(t.bindMode))

	// Start a handshake straight away. WireGuard is lazy and will not begin
	// one until there is traffic, and the tunnel should be ready before the
	// first SOCKS5 request arrives rather than after it.
	t.kickHandshake()

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.supervise(superviseCtx)
	}()

	return nil
}

// buildDevice assembles the userspace stack and device for cfg without
// touching any shared Tunnel state, so it can also be used for dry runs.
func buildDevice(ctx context.Context, log *logging.Logger, cfg *config.Tunnel, mode BindMode, netstackMode NetstackMode) (*device.Device, *netstack.Net, []device.NoisePublicKey, error) {
	tunDev, tnet, err := netstack.CreateNetTUN(cfg.Addresses, cfg.DNS, cfg.MTU)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not create the userspace network stack: %w", err)
	}

	dev := device.NewDevice(wrapNetstackTUN(tunDev, netstackMode), newBind(mode), logging.DeviceLogger(log, "awg: "))

	uapi, err := toUAPI(ctx, cfg)
	if err != nil {
		dev.Close()
		return nil, nil, nil, err
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, nil, nil, fmt.Errorf("the AmneziaWG configuration could not be applied to the device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, nil, nil, fmt.Errorf("the AmneziaWG device could not be brought up: %w", err)
	}

	keys, err := peerKeys(cfg)
	if err != nil {
		dev.Close()
		return nil, nil, nil, err
	}

	primeTransportPadding(tnet, cfg, log)
	return dev, tnet, keys, nil
}

// primeTransportPadding sends one throwaway packet so that the first real
// packet is not lost.
//
// Upstream starts its TUN reader inside NewDevice, before any configuration
// exists. That loop reads S4 once per iteration and then blocks in
// tun.Read(..., offset), so the very first packet is framed with the padding
// that was in effect when the device was created, which is zero. It therefore
// goes out without the S4 prefix and the peer discards it as a message of
// unknown type. The next iteration re-reads S4 and every later packet is
// correct.
//
// TCP hides this: the lost packet is a SYN and the retransmission succeeds.
// UDP does not retransmit, so the first datagram of a DHT announce or a DNS
// query would simply vanish. Consuming that first read here with a packet
// nobody needs makes the cost a single discarded datagram at startup.
//
// The destination is in TEST-NET-1, which is reserved for documentation and
// routed nowhere, and the port is the discard service.
func primeTransportPadding(tnet *netstack.Net, cfg *config.Tunnel, log *logging.Logger) {
	if cfg.PerPacketPrefix() == 0 {
		// Without S4 there is no offset to go stale.
		return
	}

	discard := netip.MustParseAddr("192.0.2.1")
	if !cfg.HasFamily(false) {
		discard = netip.MustParseAddr("2001:db8::1")
	}

	c, err := tnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(discard, 9))
	if err != nil {
		log.Debugf("could not prime the transport padding: %v", err)
		return
	}
	defer c.Close()
	if _, err := c.Write([]byte{0}); err != nil {
		log.Debugf("could not write the transport padding priming packet: %v", err)
		return
	}
	log.Debugf("transport padding primed: one packet was discarded because it would have gone out without the S4 prefix")
}

// toUAPI converts the configuration using the official upstream writer. The
// upstream writer resolves a hostname endpoint through the Windows resolver and
// retries internally for up to 40 seconds, so it is run under a timeout.
func toUAPI(ctx context.Context, cfg *config.Tunnel) (string, error) {
	type result struct {
		uapi string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		uapi, err := cfg.Config.ToUAPI()
		ch <- result{uapi, err}
	}()

	timer := time.NewTimer(uapiTimeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		if r.err != nil {
			return "", fmt.Errorf("could not resolve the endpoint: %w", r.err)
		}
		return r.uapi, nil
	case <-timer.C:
		return "", errors.New("timed out resolving the endpoint")
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func peerKeys(cfg *config.Tunnel) ([]device.NoisePublicKey, error) {
	var keys []device.NoisePublicKey
	for i := range cfg.Config.Peers {
		var k device.NoisePublicKey
		if err := k.FromHex(cfg.Config.Peers[i].PublicKey.HexString()); err != nil {
			return nil, fmt.Errorf("peer #%d public key could not be converted: %w", i+1, err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// Stop tears the tunnel down and releases every resource it owns.
func (t *Tunnel) Stop() {
	t.mu.Lock()
	if !t.running {
		t.mu.Unlock()
		return
	}
	dev := t.dev
	cancel := t.cancel
	t.dev = nil
	t.tnet = nil
	t.running = false
	t.cancel = nil
	// Close the readiness channel so waiting callers fail immediately;
	// WaitReady rechecks the running flag when it sees a closed channel.
	select {
	case <-t.ready:
	default:
		close(t.ready)
	}
	t.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	t.wg.Wait()

	if dev != nil {
		// device.Close() also closes the netstack tun device, which releases
		// the gVisor stack and the UDP socket with it.
		dev.Close()
	}
	t.resolver.Flush()
	t.setState(StateStopped)
	t.log.Infof("AmneziaWG tunnel closed")
}

// Running reports whether the tunnel is up.
func (t *Tunnel) Running() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.running
}

// ---------------------------------------------------------------------------
// Readiness
// ---------------------------------------------------------------------------

// WaitReady blocks until the tunnel has a live AmneziaWG handshake, ctx expires,
// or the tunnel stops. It never succeeds while the tunnel is down, which is what
// makes a SOCKS5 request fail instead of leaking to the normal Internet.
func (t *Tunnel) WaitReady(ctx context.Context) error {
	for {
		t.mu.RLock()
		running := t.running
		ready := t.ready
		t.mu.RUnlock()

		if !running {
			return ErrTunnelDown
		}
		select {
		case <-ready:
			// The channel closed: either a handshake completed or the tunnel stopped.
			t.mu.RLock()
			stillRunning := t.running
			sameChan := t.ready == ready
			t.mu.RUnlock()
			if !stillRunning {
				return ErrTunnelDown
			}
			if sameChan {
				return nil
			}
			// A reconnect replaced the channel, so wait on the new one.
			continue
		case <-ctx.Done():
			if t.State() == StateConnected {
				return nil
			}
			return fmt.Errorf("%w: %v", ErrNotReady, ctx.Err())
		}
	}
}

// markReady closes the readiness channel if it is still open.
func (t *Tunnel) markReady() {
	t.mu.Lock()
	defer t.mu.Unlock()
	select {
	case <-t.ready:
	default:
		close(t.ready)
	}
}

// markNotReady replaces a closed readiness channel with a fresh open one so
// that new callers block again until the next handshake.
func (t *Tunnel) markNotReady() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.running {
		return
	}
	select {
	case <-t.ready:
		t.ready = make(chan struct{})
	default:
	}
}

// ---------------------------------------------------------------------------
// Dialing
// ---------------------------------------------------------------------------

// DialTCP opens a TCP connection to addr through the AmneziaWG tunnel.
//
// The returned connection originates from the tunnel-local address inside the
// gVisor userspace stack. Its packets can only leave the machine as AmneziaWG
// encrypted UDP. If the tunnel is not ready the call fails; it never falls back
// to the default Windows network path.
func (t *Tunnel) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	t.mu.RLock()
	tnet := t.tnet
	running := t.running
	t.mu.RUnlock()
	if !running || tnet == nil {
		return nil, ErrTunnelDown
	}
	if err := t.WaitReady(ctx); err != nil {
		return nil, err
	}
	c, err := tnet.DialContextTCPAddrPort(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("could not reach %s through the tunnel: %w", addr, err)
	}
	return c, nil
}

// LookupHost resolves a hostname using only the DNS servers named in the
// AmneziaWG configuration, queried from inside the tunnel.
//
// This is the SOCKS5 remote-DNS (socks5h) behaviour: the Windows resolver is
// never consulted for SOCKS destinations, so a hostname request cannot leak the
// destination to the local network or the ISP.
// Answers are cached and concurrent lookups for the same name are collapsed
// into one query; see internal/dns for why that matters here.
func (t *Tunnel) LookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	t.mu.RLock()
	running := t.running
	cfg := t.cfg
	t.mu.RUnlock()
	if !running {
		return nil, ErrTunnelDown
	}
	if cfg == nil || len(cfg.DNS) == 0 {
		return nil, ErrNoDNS
	}
	return t.resolver.Lookup(ctx, host)
}

// DNSStats reports in-tunnel resolver cache effectiveness.
func (t *Tunnel) DNSStats() dns.Stats { return t.resolver.Stats() }

// lookupUncached performs one in-tunnel resolution, with progressive retry
// timeouts. The upstream netstack resolver waits five seconds per server before
// moving on, so a lost DNS datagram would otherwise stall a page resource for
// five seconds; a shorter first attempt turns that into roughly two.
func (t *Tunnel) lookupUncached(ctx context.Context, host string) ([]netip.Addr, error) {
	t.mu.RLock()
	tnet := t.tnet
	running := t.running
	t.mu.RUnlock()
	if !running || tnet == nil {
		return nil, ErrTunnelDown
	}
	if err := t.WaitReady(ctx); err != nil {
		return nil, err
	}

	var lastErr error
	var notFound bool
	for attempt := 1; attempt <= len(dnsAttemptTimeouts); attempt++ {
		if err := ctx.Err(); err != nil {
			break
		}
		attemptCtx, cancel := context.WithTimeout(ctx, dnsAttemptTimeouts[attempt-1])
		names, err := tnet.LookupContextHost(attemptCtx, host)
		cancel()

		if err == nil {
			out := make([]netip.Addr, 0, len(names))
			for _, n := range names {
				if a, perr := netip.ParseAddr(n); perr == nil {
					out = append(out, a.Unmap())
				}
			}
			if len(out) > 0 {
				return out, nil
			}
			return nil, fmt.Errorf("in-tunnel DNS returned no usable address for %s", host)
		}

		lastErr = err
		// A not-found answer is worth one confirmation before it is believed.
		//
		// The resolver asks for A and AAAA at the same time and reports the
		// first error either lane produced. A server that answers AAAA for a
		// name that only has an A record does so authoritatively and empty,
		// which this resolver reports as "no such host". If the A response is
		// then lost, and a single UDP datagram over a tunnel can be, that
		// not-found is the only thing left and the name looks like it does not
		// exist at all. Believing it on the first attempt turns one dropped
		// packet into a permanent SOCKS5 host unreachable.
		//
		// Confirming costs close to nothing, because a name that really does
		// not exist is answered immediately rather than waiting out a timeout.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			if notFound {
				break
			}
			notFound = true
		}
		if attempt < len(dnsAttemptTimeouts) {
			t.log.Debugf("in-tunnel DNS attempt %d/%d failed for %s: %v",
				attempt, len(dnsAttemptTimeouts), host, err)
		}
	}
	return nil, fmt.Errorf("in-tunnel DNS resolution failed for %s: %w", host, lastErr)
}

// ListenUDP opens an unconnected UDP socket inside the tunnel.
//
// It is what makes SOCKS5 UDP ASSOCIATE possible: datagrams written to the
// returned connection leave the machine only as AmneziaWG encrypted UDP, the
// same as TCP traffic. ipv6 selects the address family, because a gVisor UDP
// endpoint is bound to one family and can only send within it.
func (t *Tunnel) ListenUDP(ctx context.Context, ipv6 bool) (net.PacketConn, error) {
	t.mu.RLock()
	tnet := t.tnet
	running := t.running
	cfg := t.cfg
	t.mu.RUnlock()
	if !running || tnet == nil {
		return nil, ErrTunnelDown
	}
	local, ok := cfg.AddressOfFamily(ipv6)
	if !ok {
		return nil, fmt.Errorf("%w: tunnel has no %s address", ErrNoRoute, familyName(ipv6))
	}
	if err := t.WaitReady(ctx); err != nil {
		return nil, err
	}

	// Bind to the tunnel address rather than the wildcard. A gVisor endpoint
	// bound to 0.0.0.0 fails source address selection and every send comes back
	// as "no route to host".
	c, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(local, 0))
	if err != nil {
		return nil, fmt.Errorf("could not open an in-tunnel %s UDP socket: %w", familyName(ipv6), err)
	}
	return c, nil
}

func familyName(ipv6 bool) string {
	if ipv6 {
		return "IPv6"
	}
	return "IPv4"
}

// HasDNS reports whether the configuration provides in-tunnel DNS servers.
func (t *Tunnel) HasDNS() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.cfg != nil && len(t.cfg.DNS) > 0
}

// ---------------------------------------------------------------------------
// Supervision, reconnect
// ---------------------------------------------------------------------------

// Reconnect forces the tunnel to rebind its UDP socket and start a fresh
// handshake. It is safe to call from a service control handler.
func (t *Tunnel) Reconnect() {
	select {
	case t.kick <- struct{}{}:
	default:
	}
}

// supervise keeps the tunnel healthy: it watches the newest handshake, kicks a
// new handshake with exponential backoff when there is none, and reacts to
// external reconnect requests from sleep/resume and network-change events.
func (t *Tunnel) supervise(ctx context.Context) {
	ticker := time.NewTicker(superviseInterval)
	defer ticker.Stop()

	backoff := minBackoff
	nextKick := time.Now().Add(backoff)
	wasConnected := false

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.kick:
			t.performReconnect()
			backoff = minBackoff
			nextKick = time.Now().Add(backoff)
			wasConnected = false
			continue
		case <-ticker.C:
		}

		st, err := t.readStats()
		if err != nil {
			// The device may be shutting down; look again on the next tick.
			continue
		}

		healthy := !st.LastHandshake.IsZero() && time.Since(st.LastHandshake) < handshakeStaleAfter
		if healthy {
			if !wasConnected {
				t.log.Infof("AmneziaWG handshake completed (endpoint=%s)", st.Endpoint)
				wasConnected = true
			}
			t.setState(StateConnected)
			t.clearError()
			t.markReady()
			backoff = minBackoff
			nextKick = time.Now().Add(handshakeStaleAfter / 2)
			continue
		}

		// There is no handshake, or the newest one has gone stale.
		t.markNotReady()
		if wasConnected {
			t.log.Warnf("AmneziaWG handshake is stale (last: %s), reconnecting",
				formatHandshake(st.LastHandshake))
			t.setState(StateReconnecting)
			t.reconnects.Add(1)
			wasConnected = false
			backoff = minBackoff
			nextKick = time.Now()
		} else if t.State() != StateReconnecting {
			t.setState(StateConnecting)
		}

		if time.Now().Before(nextKick) {
			continue
		}
		t.log.Debugf("triggering an AmneziaWG handshake (backoff: %s)", backoff)
		t.kickHandshake()
		nextKick = time.Now().Add(backoff)
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// kickHandshake stages a keepalive on every peer, which makes the upstream
// implementation start a handshake when no valid keypair exists.
func (t *Tunnel) kickHandshake() {
	t.mu.RLock()
	dev := t.dev
	keys := t.peerKeys
	t.mu.RUnlock()
	if dev == nil {
		return
	}
	for _, k := range keys {
		if p := dev.LookupPeer(k); p != nil {
			p.SendKeepalive()
		}
	}
}

// performReconnect rebinds the UDP socket and, for hostname endpoints, resolves
// the endpoint again through the upstream writer before reapplying it.
func (t *Tunnel) performReconnect() {
	t.mu.RLock()
	dev := t.dev
	cfg := t.cfg
	running := t.running
	t.mu.RUnlock()
	if !running || dev == nil {
		return
	}

	t.reconnects.Add(1)
	t.markNotReady()
	t.setState(StateReconnecting)
	t.log.Infof("reconnect requested: reopening the UDP socket")

	if err := dev.BindUpdate(); err != nil {
		t.log.Errorf("could not reopen the UDP socket: %v", err)
		t.setError(fmt.Sprintf("could not reopen the UDP socket: %v", err))
	}

	if cfg != nil && endpointNeedsResolution(cfg) {
		ctx, cancel := context.WithTimeout(context.Background(), uapiTimeout)
		uapi, err := toUAPI(ctx, cfg)
		cancel()
		if err != nil {
			t.log.Errorf("could not re-resolve the endpoint: %v", err)
			t.setError(fmt.Sprintf("could not re-resolve the endpoint: %v", err))
		} else if err := dev.IpcSet(uapi); err != nil {
			t.log.Errorf("could not apply the new endpoint: %v", err)
			t.setError(fmt.Sprintf("could not apply the new endpoint: %v", err))
		} else {
			t.log.Infof("endpoint re-resolved")
		}
	}

	t.kickHandshake()
}

// endpointNeedsResolution reports whether any peer endpoint is a hostname
// rather than a literal IP address.
func endpointNeedsResolution(cfg *config.Tunnel) bool {
	for i := range cfg.Config.Peers {
		host := cfg.Config.Peers[i].Endpoint.Host
		host = strings.Trim(host, "[]")
		if _, err := netip.ParseAddr(host); err != nil {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Hot reload
// ---------------------------------------------------------------------------

// Reload applies a new configuration.
//
// A healthy tunnel is never replaced by a broken configuration: the new
// configuration is fully validated against a throwaway device first, and if the
// live apply still fails the previous configuration is restored.
func (t *Tunnel) Reload(ctx context.Context, next *config.Tunnel) (changed bool, err error) {
	if next == nil {
		return false, errors.New("the new configuration is empty")
	}
	if err := DryRun(ctx, t.log, next); err != nil {
		return false, fmt.Errorf("the new configuration is invalid, keeping the running tunnel: %w", err)
	}

	t.mu.RLock()
	prev := t.cfg
	running := t.running
	dev := t.dev
	t.mu.RUnlock()

	if !running {
		t.mu.Lock()
		t.cfg = next
		t.mu.Unlock()
		return true, nil
	}

	if stackEqual(prev, next) {
		// The rollback text is rendered first. IpcSet applies its lines in
		// order, so an interrupted call can leave the device in a mixed state;
		// if the change cannot be undone, it is never started.
		prevUAPI, err := toUAPI(ctx, prev)
		if err != nil {
			return false, fmt.Errorf(
				"the current configuration could not be rendered for rollback, nothing was changed: %w", err)
		}
		nextUAPI, err := toUAPI(ctx, next)
		if err != nil {
			return false, fmt.Errorf("the new configuration could not be rendered, keeping the running tunnel: %w", err)
		}
		if err := dev.IpcSet(nextUAPI); err != nil {
			if restoreErr := dev.IpcSet(prevUAPI); restoreErr != nil {
				t.setState(StateFailed)
				t.setError(fmt.Sprintf("rollback failed: %v", restoreErr))
				return false, fmt.Errorf("the new configuration could not be applied and the previous one could not be restored: %w", restoreErr)
			}
			return false, fmt.Errorf("the new configuration could not be applied, the previous one was restored: %w", err)
		}
		t.mu.Lock()
		t.cfg = next
		keys, kerr := peerKeys(next)
		if kerr == nil {
			t.peerKeys = keys
		}
		t.mu.Unlock()
		t.markNotReady()
		t.setState(StateConnecting)
		t.kickHandshake()
		t.log.Infof("configuration reloaded without rebuilding the tunnel")
		return true, nil
	}

	// Address, DNS or MTU changed: the userspace stack has to be rebuilt.
	t.log.Infof("address, DNS or MTU changed, rebuilding the tunnel")
	t.Stop()
	t.mu.Lock()
	t.cfg = next
	t.mu.Unlock()
	if err := t.Start(ctx); err != nil {
		t.log.Errorf("the tunnel could not be started with the new configuration: %v", err)
		t.mu.Lock()
		t.cfg = prev
		t.mu.Unlock()
		if restoreErr := t.Start(ctx); restoreErr != nil {
			return false, fmt.Errorf("the new configuration failed to start (%v) and the previous one did not start either: %w", err, restoreErr)
		}
		return false, fmt.Errorf("the new configuration failed to start, the previous one was restored: %w", err)
	}
	return true, nil
}

// stackEqual reports whether two configurations produce an identical userspace
// network stack, meaning a reload can be applied over UAPI alone.
func stackEqual(a, b *config.Tunnel) bool {
	if a == nil || b == nil {
		return false
	}
	if a.MTU != b.MTU || len(a.Addresses) != len(b.Addresses) || len(a.DNS) != len(b.DNS) {
		return false
	}
	for i := range a.Addresses {
		if a.Addresses[i] != b.Addresses[i] {
			return false
		}
	}
	for i := range a.DNS {
		if a.DNS[i] != b.DNS[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func formatPrefixes(ps []netip.Prefix) string {
	parts := make([]string, 0, len(ps))
	for _, p := range ps {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ",")
}

func formatHandshake(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Format("2006-01-02 15:04:05")
}

func describeParams(cfg *config.Tunnel) string {
	if len(cfg.AWGParams) == 0 {
		return "none (plain WireGuard)"
	}
	return strings.Join(cfg.AWGParams, ", ") + " | " + cfg.Generation
}
