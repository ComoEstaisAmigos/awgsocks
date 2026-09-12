package awg

import (
	"fmt"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

// BindMode selects which upstream UDP bind implementation carries the
// AmneziaWG endpoint traffic. Both implementations live in the upstream
// amneziawg-go conn package; AWGSocks writes neither of them.
type BindMode string

// Available bind modes.
const (
	// BindStd uses conn.NewStdNetBind: standard Go UDP sockets, the same code
	// path amneziawg-go uses on every non-Windows platform. This is the
	// AWGSocks default.
	BindStd BindMode = "std"

	// BindRIO uses conn.NewDefaultBind, which on Windows is the Registered I/O
	// ring-buffer bind (conn.NewWinRingBind). This is what the official
	// AmneziaWG Windows client uses. It reaches a higher packet rate but
	// manages registered memory buffers by hand.
	BindRIO BindMode = "rio"
)

// ParseBindMode validates a bind mode name from configuration.
func ParseBindMode(s string) (BindMode, error) {
	switch BindMode(strings.ToLower(strings.TrimSpace(s))) {
	case "", BindStd:
		return BindStd, nil
	case BindRIO:
		return BindRIO, nil
	default:
		return "", fmt.Errorf("invalid udp_bind value %q (std|rio)", s)
	}
}

// newBind creates the upstream bind for the selected mode.
//
// Why std is the default on Windows:
//
// The Registered I/O bind tears down in this order (upstream
// conn/bind_windows.go, afWinRingBind.CloseAndZero): it closes the completion
// queues, calls RIODeregisterBuffer, releases the ring memory with
// VirtualFree(MEM_RELEASE), and only then closes the socket that owns the RIO
// request queue still referencing those registrations.
//
// AWGSocks rebinds its UDP socket on every network change, sleep/resume and
// reconnect, so it runs that teardown far more often than a desktop VPN client
// does. During development one AmneziaWG test process died with
// STATUS_HEAP_CORRUPTION (0xC0000374); the RIO bind is the only component in
// the process that touches the Windows process heap. The fault could not be
// reproduced afterwards, so this is a precaution rather than a proven defect.
//
// The standard bind has no registered memory to manage, is the same upstream
// code used on every other platform, and changes nothing about the AmneziaWG
// protocol, the obfuscation or the endpoint path.
//
// What it costs, measured rather than assumed: on the loopback benchmark in
// internal/e2e the Registered I/O bind did not move throughput outside run to
// run variance, but it did cut process CPU by roughly a tenth at the same rate.
// So the trade is CPU efficiency, not peak speed. See docs/TESTING.md.
//
// Set "udp_bind": "rio" in config.json to use the Windows Registered I/O bind
// instead.
func newBind(mode BindMode) conn.Bind {
	if mode == BindRIO {
		return conn.NewDefaultBind()
	}
	return conn.NewStdNetBind()
}

// bindDescription renders the active bind for status output.
func bindDescription(mode BindMode) string {
	if mode == BindRIO {
		return "rio (Windows Registered I/O, conn.NewWinRingBind)"
	}
	return "std (conn.NewStdNetBind)"
}
