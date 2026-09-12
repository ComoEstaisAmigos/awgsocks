// Package ipc implements AWGSocks' local management channel.
//
// Management is exposed only over a Windows named pipe whose ACL grants access
// to LocalSystem and the local Administrators group. There is deliberately no
// TCP management interface: an unauthenticated management port next to an
// unauthenticated proxy port would be an obvious way to take over the tunnel.
package ipc

import "time"

// PipeName is the named pipe AWGSocks listens on.
const PipeName = `\\.\pipe\AWGSocks`

// The pipe ACL is built at runtime by winsys.PipeSecurityDescriptor: it grants
// access to LocalSystem, the local Administrators group and the account the
// process actually runs as, and to nobody else.

// Commands accepted over the pipe.
const (
	CmdStatus    = "status"
	CmdReload    = "reload"
	CmdReconnect = "reconnect"
	CmdStart     = "start"
	CmdStop      = "stop"
	CmdPing      = "ping"
)

// Request is one management command.
type Request struct {
	Command string `json:"command"`
}

// Response is the reply to a Request.
type Response struct {
	OK      bool    `json:"ok"`
	Error   string  `json:"error,omitempty"`
	Message string  `json:"message,omitempty"`
	Status  *Status `json:"status,omitempty"`
}

// TunnelStatus describes the AmneziaWG tunnel.
type TunnelStatus struct {
	State         string            `json:"state"`
	Endpoint      string            `json:"endpoint,omitempty"`
	LastHandshake time.Time         `json:"last_handshake,omitempty"`
	TxBytes       uint64            `json:"tx_bytes"`
	RxBytes       uint64            `json:"rx_bytes"`
	Reconnects    int64             `json:"reconnects"`
	LastError     string            `json:"last_error,omitempty"`
	StartedAt     time.Time         `json:"started_at,omitempty"`
	AWGParams     map[string]string `json:"awg_params,omitempty"`
	Generation    string            `json:"generation,omitempty"`
	Addresses     []string          `json:"addresses,omitempty"`
	DNS           []string          `json:"dns,omitempty"`
	MTU           int               `json:"mtu,omitempty"`
	AllowedIPs    []string          `json:"allowed_ips,omitempty"`
	DNSCache      DNSCacheStatus    `json:"dns_cache"`
}

// DNSCacheStatus reports in-tunnel resolver cache effectiveness. A low hit
// ratio while browsing feels slow is the signature of name resolution, not
// throughput, being the bottleneck.
type DNSCacheStatus struct {
	Hits      uint64 `json:"hits"`
	Misses    uint64 `json:"misses"`
	Coalesced uint64 `json:"coalesced"`
	Entries   int    `json:"entries"`
}

// SocksStatus describes the local SOCKS5 front end.
type SocksStatus struct {
	Listen    string `json:"listen"`
	Listening bool   `json:"listening"`
	Active    int64  `json:"active_connections"`
	Total     int64  `json:"total_connections"`
	Rejected  int64  `json:"rejected_connections"`
	Failed    int64  `json:"failed_connections"`
	BytesUp   uint64 `json:"bytes_client_to_remote"`
	BytesDown uint64 `json:"bytes_remote_to_client"`

	UDPEnabled       bool   `json:"udp_enabled"`
	UDPAssociations  int64  `json:"udp_associations"`
	UDPDatagramsUp   uint64 `json:"udp_datagrams_sent"`
	UDPDatagramsDown uint64 `json:"udp_datagrams_received"`
	UDPDropped       uint64 `json:"udp_datagrams_dropped"`
	UDPBytesUp       uint64 `json:"udp_bytes_sent"`
	UDPBytesDown     uint64 `json:"udp_bytes_received"`
}

// VersionStatus reports the pinned upstream identities.
type VersionStatus struct {
	AWGSocks         string `json:"awgsocks"`
	AmneziaWGGo      string `json:"amneziawg_go"`
	AmneziaWGCommit  string `json:"amneziawg_go_commit"`
	AWGParser        string `json:"amneziawg_windows"`
	AWGParserCommit  string `json:"amneziawg_windows_commit"`
	Wintun           string `json:"wintun"`
	GoVersion        string `json:"go_version"`
	SystemRouteState string `json:"system_route_state"`
	UDPBind          string `json:"udp_bind"`
}

// Status is the full status report returned by CmdStatus.
type Status struct {
	Service    string        `json:"service"`
	ConfigPath string        `json:"config_path"`
	Tunnel     TunnelStatus  `json:"tunnel"`
	Socks5     SocksStatus   `json:"socks5"`
	Versions   VersionStatus `json:"versions"`
	Warnings   []string      `json:"warnings,omitempty"`
	Uptime     string        `json:"uptime,omitempty"`
}

// Handler serves management commands. It is implemented by the service.
type Handler interface {
	Status() *Status
	// Reload re-reads the configuration and returns an account of what it
	// applied and what needs a restart, which is relayed to the caller as
	// Response.Message.
	Reload() (string, error)
	Reconnect() error
	StartTunnel() error
	StopTunnel() error
}
