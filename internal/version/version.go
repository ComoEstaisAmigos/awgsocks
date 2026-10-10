// Package version exposes build and upstream dependency identity for AWGSocks.
package version

import "fmt"

// Version is the AWGSocks release version. It can be overridden at build time
// with -ldflags "-X github.com/ComoEstaisAmigos/awgsocks/internal/version.Version=..."
var Version = "1.0.0"

// Commit is the AWGSocks source revision, injected at build time when available.
var Commit = "unknown"

// BuildDate is injected at build time when available. scripts\build.bat stamps
// the commit date rather than the time of the build, so rebuilding a commit
// reproduces the binary.
var BuildDate = "unknown"

// Pinned upstream identities. These are the exact upstream artifacts AWGSocks
// is built against; see docs/UPSTREAM.md for how they were selected.
const (
	// AmneziaWGGoModule is the userspace AmneziaWG implementation that performs
	// all cryptography and all AmneziaWG obfuscation (Jc/Jmin/Jmax, S1-S4,
	// H1-H4, I1-I5, HeaderProtectionKey, ...). AWGSocks does not reimplement any
	// of it.
	AmneziaWGGoModule  = "github.com/amnezia-vpn/amneziawg-go/v3"
	AmneziaWGGoVersion = "v3.1.20260828"
	AmneziaWGGoCommit  = "b5928efb6ca19f0153958460c3d141f04abc5c2e"

	// AmneziaWGWindowsModule provides the official awg-quick .conf parser and
	// the official .conf -> UAPI writer used by the AmneziaWG Windows client.
	AmneziaWGWindowsModule  = "github.com/amnezia-vpn/amneziawg-windows/v3"
	AmneziaWGWindowsVersion = "v3.1.20260814"
	AmneziaWGWindowsCommit  = "e90531d15802cb976773f3b63443bc281f738ca3"

	// WintunStatus documents that AWGSocks deliberately does not use Wintun.
	// See docs/ARCHITECTURE.md section 3.15 and 3.16, "Where Wintun is used,
	// and why it is not needed".
	WintunStatus = "not used (userspace gVisor netstack; no Windows adapter is created)"

	// ServiceName is the Windows service name.
	ServiceName = "AWGSocks"

	// ServiceDisplayName is shown in services.msc.
	ServiceDisplayName = "AWGSocks AmneziaWG SOCKS5 Proxy"
)

// String renders the multi-line version banner shown by `awgsocks version`.
func String() string {
	return fmt.Sprintf(
		"AWGSocks %s (commit %s, built %s)\n"+
			"AmneziaWG   %s %s (commit %s)\n"+
			"AWG parser  %s %s (commit %s)\n"+
			"Wintun      %s\n",
		Version, Commit, BuildDate,
		AmneziaWGGoModule, AmneziaWGGoVersion, AmneziaWGGoCommit,
		AmneziaWGWindowsModule, AmneziaWGWindowsVersion, AmneziaWGWindowsCommit,
		WintunStatus,
	)
}

// Short renders a single-line identity string for logs.
func Short() string {
	return fmt.Sprintf("AWGSocks %s / AmneziaWG %s", Version, AmneziaWGGoVersion)
}
