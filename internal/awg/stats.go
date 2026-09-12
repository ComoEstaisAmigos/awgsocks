package awg

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// PeerStats is the live state of one AmneziaWG peer.
//
// It deliberately carries no key material other than the peer public key, which
// is not a secret. private_key, preshared_key and header_protection_key are
// dropped while parsing so they cannot reach a log, the IPC pipe or the CLI.
type PeerStats struct {
	PublicKey           string    `json:"public_key"`
	Endpoint            string    `json:"endpoint"`
	LastHandshake       time.Time `json:"last_handshake"`
	TxBytes             uint64    `json:"tx_bytes"`
	RxBytes             uint64    `json:"rx_bytes"`
	PersistentKeepalive string    `json:"persistent_keepalive,omitempty"`
	AllowedIPs          []string  `json:"allowed_ips,omitempty"`
}

// Stats is a snapshot of the AmneziaWG device state.
type Stats struct {
	ListenPort int               `json:"listen_port"`
	AWGParams  map[string]string `json:"awg_params"`
	Peers      []PeerStats       `json:"peers"`

	// Aggregated first-peer values, for convenient status display.
	Endpoint      string    `json:"endpoint"`
	LastHandshake time.Time `json:"last_handshake"`
	TxBytes       uint64    `json:"tx_bytes"`
	RxBytes       uint64    `json:"rx_bytes"`
}

// secretUAPIKeys are never copied out of the device.
var secretUAPIKeys = map[string]struct{}{
	"private_key":           {},
	"preshared_key":         {},
	"header_protection_key": {},
}

// awgUAPIKeys are the AmneziaWG-specific device keys reported in status output.
var awgUAPIKeys = []string{
	"jc", "jmin", "jmax",
	"s1", "s2", "s3", "s4",
	"h1", "h2", "h3", "h4",
	"i1", "i2", "i3", "i4", "i5",
	"content_padding_addition",
	"rekey_after_time", "rekey_timeout", "reject_after_time",
	"keepalive_timeout", "max_handshake_attempts",
	"random_trailers", "disable_cookies",
}

// Stats returns a snapshot of the live device state, or an error when the
// tunnel is not running.
func (t *Tunnel) Stats() (Stats, error) { return t.readStats() }

func (t *Tunnel) readStats() (Stats, error) {
	t.mu.RLock()
	dev := t.dev
	running := t.running
	t.mu.RUnlock()
	if !running || dev == nil {
		return Stats{}, ErrTunnelDown
	}
	raw, err := dev.IpcGet()
	if err != nil {
		return Stats{}, err
	}
	return parseUAPIGet(raw)
}

// parseUAPIGet converts the upstream UAPI "get" document into Stats, dropping
// every secret-bearing line.
func parseUAPIGet(raw string) (Stats, error) {
	s := Stats{AWGParams: map[string]string{}}
	awgWanted := map[string]struct{}{}
	for _, k := range awgUAPIKeys {
		awgWanted[k] = struct{}{}
	}

	var cur *PeerStats
	var handshakeSec, handshakeNsec int64

	flush := func() {
		if cur == nil {
			return
		}
		if handshakeSec > 0 || handshakeNsec > 0 {
			cur.LastHandshake = time.Unix(handshakeSec, handshakeNsec)
		}
		s.Peers = append(s.Peers, *cur)
		cur = nil
		handshakeSec, handshakeNsec = 0, 0
	}

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if _, secret := secretUAPIKeys[key]; secret {
			continue
		}
		switch key {
		case "errno":
			if value != "0" {
				return Stats{}, errors.New("UAPI error: errno=" + value)
			}
		case "listen_port":
			s.ListenPort, _ = strconv.Atoi(value)
		case "public_key":
			flush()
			cur = &PeerStats{PublicKey: value}
		case "endpoint":
			if cur != nil {
				cur.Endpoint = value
			}
		case "last_handshake_time_sec":
			handshakeSec, _ = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			handshakeNsec, _ = strconv.ParseInt(value, 10, 64)
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes, _ = strconv.ParseUint(value, 10, 64)
			}
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes, _ = strconv.ParseUint(value, 10, 64)
			}
		case "persistent_keepalive_interval":
			if cur != nil {
				cur.PersistentKeepalive = value
			}
		case "allowed_ip":
			if cur != nil {
				cur.AllowedIPs = append(cur.AllowedIPs, value)
			}
		default:
			if _, want := awgWanted[key]; want {
				s.AWGParams[key] = value
			}
		}
	}
	flush()

	if len(s.Peers) > 0 {
		p := s.Peers[0]
		s.Endpoint = p.Endpoint
		s.LastHandshake = p.LastHandshake
		s.TxBytes = p.TxBytes
		s.RxBytes = p.RxBytes
	}
	return s, nil
}
