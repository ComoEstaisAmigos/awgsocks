package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ComoEstaisAmigos/awgsocks/internal/ipc"
)

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

// printStatus renders the status report. No key material can appear here: the
// status pipeline drops private_key, preshared_key and header_protection_key
// while parsing the device state.
func printStatus(st *ipc.Status) {
	fmt.Println("== AWGSocks ==")
	fmt.Printf("Service state     : %s\n", st.Service)
	if st.Uptime != "" {
		fmt.Printf("Uptime            : %s\n", st.Uptime)
	}
	fmt.Printf("Configuration     : %s\n", st.ConfigPath)

	fmt.Println()
	fmt.Println("== SOCKS5 ==")
	fmt.Printf("Listen address    : %s\n", st.Socks5.Listen)
	fmt.Printf("Listening         : %s\n", yesNo(st.Socks5.Listening))
	fmt.Printf("Active sessions   : %d\n", st.Socks5.Active)
	fmt.Printf("Total sessions    : %d\n", st.Socks5.Total)
	fmt.Printf("Rejected          : %d (non-loopback or over the limit)\n", st.Socks5.Rejected)
	fmt.Printf("Failed requests   : %d\n", st.Socks5.Failed)
	fmt.Printf("Relayed           : %s sent / %s received\n",
		humanBytes(st.Socks5.BytesUp), humanBytes(st.Socks5.BytesDown))
	fmt.Printf("UDP ASSOCIATE     : %s\n", formatUDP(st.Socks5))

	fmt.Println()
	fmt.Println("== AmneziaWG tunnel ==")
	fmt.Printf("State             : %s\n", orDash(st.Tunnel.State))
	if st.Tunnel.PausedBy != "" {
		fmt.Printf("Paused            : this configuration is connected on the Windows adapter %s,\n", st.Tunnel.PausedBy)
		fmt.Printf("                    resumes when that adapter disconnects\n")
	}
	fmt.Printf("Endpoint          : %s\n", orDash(st.Tunnel.Endpoint))
	fmt.Printf("Last handshake    : %s\n", formatTime(st.Tunnel.LastHandshake))
	fmt.Printf("Sent              : %s\n", humanBytes(st.Tunnel.TxBytes))
	fmt.Printf("Received          : %s\n", humanBytes(st.Tunnel.RxBytes))
	fmt.Printf("Reconnects        : %d\n", st.Tunnel.Reconnects)
	fmt.Printf("Last error        : %s\n", orDash(st.Tunnel.LastError))
	fmt.Printf("Tunnel addresses  : %s\n", orDash(strings.Join(st.Tunnel.Addresses, ", ")))
	fmt.Printf("In-tunnel DNS     : %s\n", orDash(strings.Join(st.Tunnel.DNS, ", ")))
	fmt.Printf("MTU               : %d\n", st.Tunnel.MTU)
	fmt.Printf("AllowedIPs        : %s\n", orDash(strings.Join(st.Tunnel.AllowedIPs, ", ")))
	fmt.Printf("DNS cache         : %s\n", formatDNSCache(st.Tunnel.DNSCache))
	fmt.Printf("AWG generation    : %s\n", orDash(st.Tunnel.Generation))
	if len(st.Tunnel.AWGParams) > 0 {
		keys := make([]string, 0, len(st.Tunnel.AWGParams))
		for k := range st.Tunnel.AWGParams {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%s", strings.ToUpper(k), st.Tunnel.AWGParams[k]))
		}
		fmt.Printf("Active AWG params : %s\n", strings.Join(parts, " "))
	}

	fmt.Println()
	fmt.Println("== Versions ==")
	fmt.Printf("AWGSocks          : %s\n", st.Versions.AWGSocks)
	fmt.Printf("AmneziaWG         : %s (commit %s)\n", st.Versions.AmneziaWGGo, shortCommit(st.Versions.AmneziaWGCommit))
	fmt.Printf("AWG conf parser   : %s (commit %s)\n", st.Versions.AWGParser, shortCommit(st.Versions.AWGParserCommit))
	fmt.Printf("Wintun            : %s\n", st.Versions.Wintun)
	fmt.Printf("Go                : %s\n", st.Versions.GoVersion)
	fmt.Printf("UDP bind          : %s\n", orDash(st.Versions.UDPBind))
	fmt.Printf("Windows routes    : %s\n", st.Versions.SystemRouteState)

	if len(st.Warnings) > 0 {
		fmt.Println()
		fmt.Println("== Warnings ==")
		for _, w := range st.Warnings {
			fmt.Printf("- %s\n", w)
		}
	}
}

// formatUDP renders the UDP relay counters. A client that cannot send UDP
// through the proxy usually sends it directly instead, so whether this is on
// matters for what actually stays inside the tunnel.
func formatUDP(s ipc.SocksStatus) string {
	if !s.UDPEnabled {
		return "disabled (UDP cannot pass through the proxy)"
	}
	if s.UDPAssociations == 0 && s.UDPDatagramsUp == 0 && s.UDPDatagramsDown == 0 {
		return "enabled, not used yet"
	}
	out := fmt.Sprintf("enabled, %d active associations, %d sent / %d received datagrams (%s / %s)",
		s.UDPAssociations, s.UDPDatagramsUp, s.UDPDatagramsDown,
		humanBytes(s.UDPBytesUp), humanBytes(s.UDPBytesDown))
	if s.UDPDropped > 0 {
		out += fmt.Sprintf(", %d dropped", s.UDPDropped)
	}
	return out
}

// formatDNSCache renders the in-tunnel resolver counters with a hit ratio,
// which is what tells you whether slow browsing is a name resolution problem.
func formatDNSCache(c ipc.DNSCacheStatus) string {
	total := c.Hits + c.Misses + c.Coalesced
	if total == 0 {
		return "no lookups yet"
	}
	saved := c.Hits + c.Coalesced
	return fmt.Sprintf("%d entries, %d hits, %d coalesced, %d tunnel queries (%.0f%% saved)",
		c.Entries, c.Hits, c.Coalesced, c.Misses, float64(saved)*100/float64(total))
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return fmt.Sprintf("%s (%s ago)", t.Local().Format("2006-01-02 15:04:05"),
		time.Since(t).Round(time.Second))
}

func shortCommit(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
