// Package config parses and validates the AmneziaWG tunnel configuration and
// the AWGSocks application configuration.
//
// The tunnel configuration pipeline is deliberately the same one the official
// AmneziaWG Windows client uses:
//
//	client.conf
//	  -> conf.FromWgQuickWithUnknownEncoding   (official upstream parser)
//	  -> conf.Config                           (official upstream representation)
//	  -> conf.ToUAPI                           (official upstream UAPI writer)
//	  -> device.IpcSet                         (amneziawg-go userspace device)
//
// AWGSocks adds a strict pre-validation pass in front of the upstream parser so
// that errors name the offending AmneziaWG parameter, and so that a parameter
// the pinned upstream cannot honour is rejected instead of silently ignored.
package config

import "strings"

// paramKind classifies how an AmneziaWG parameter value is validated.
type paramKind int

const (
	kindOther paramKind = iota
	kindUint16
	kindRangeU32 // documented as range<uint32>
	kindRangeU16 // documented as range<uint16>, accepted as uint32 by upstream
	kindBool
	kindKeyBase64
	kindObfChain // I1-I5 CPS description, validated by the upstream device
)

// supportedParam describes one configuration key that AWGSocks accepts.
type supportedParam struct {
	kind paramKind
	// awg marks AmneziaWG-specific parameters (as opposed to plain wg-quick
	// keys). Used only to produce better error messages.
	awg bool
}

// interfaceParams is the set of [Interface] keys the pinned upstream stack can
// actually honour. It is derived from:
//
//   - amneziawg-windows conf/parser.go  (which keys the official parser accepts)
//   - amneziawg-go device/uapi.go       (which keys the device actually applies)
//
// A key outside this map is rejected; see errUnsupportedParam.
var interfaceParams = map[string]supportedParam{
	// Standard WireGuard / wg-quick interface keys.
	"privatekey": {kind: kindKeyBase64},
	"listenport": {kind: kindUint16},
	"mtu":        {kind: kindOther},
	"address":    {kind: kindOther},
	"dns":        {kind: kindOther},
	"table":      {kind: kindOther},

	// AmneziaWG junk packets (Jc/Jmin/Jmax).
	"jc":   {kind: kindUint16, awg: true},
	"jmin": {kind: kindUint16, awg: true},
	"jmax": {kind: kindUint16, awg: true},

	// AmneziaWG random prefixes for init/response/cookie/transport packets.
	"s1": {kind: kindUint16, awg: true},
	"s2": {kind: kindUint16, awg: true},
	"s3": {kind: kindUint16, awg: true},
	"s4": {kind: kindUint16, awg: true},

	// AmneziaWG custom message type identifiers, range<uint32>.
	"h1": {kind: kindRangeU32, awg: true},
	"h2": {kind: kindRangeU32, awg: true},
	"h3": {kind: kindRangeU32, awg: true},
	"h4": {kind: kindRangeU32, awg: true},

	// AmneziaWG 3.x special handshake packets.
	"i1": {kind: kindObfChain, awg: true},
	"i2": {kind: kindObfChain, awg: true},
	"i3": {kind: kindObfChain, awg: true},
	"i4": {kind: kindObfChain, awg: true},
	"i5": {kind: kindObfChain, awg: true},

	// AmneziaWG 3.x header protection and payload padding.
	"headerprotectionkey":    {kind: kindKeyBase64, awg: true},
	"contentpaddingaddition": {kind: kindRangeU16, awg: true},

	// AmneziaWG 3.x timing randomisation.
	"rekeyaftertime":       {kind: kindRangeU16, awg: true},
	"rekeytimeout":         {kind: kindRangeU16, awg: true},
	"rejectaftertime":      {kind: kindRangeU16, awg: true},
	"keepalivetimeout":     {kind: kindRangeU16, awg: true},
	"maxhandshakeattempts": {kind: kindRangeU16, awg: true},

	// AmneziaWG 3.x toggles.
	"randomtrailers": {kind: kindBool, awg: true},
	"disablecookies": {kind: kindBool, awg: true},
}

// peerParams is the set of [Peer] keys AWGSocks accepts.
var peerParams = map[string]supportedParam{
	"publickey":           {kind: kindKeyBase64},
	"presharedkey":        {kind: kindKeyBase64},
	"allowedips":          {kind: kindOther},
	"persistentkeepalive": {kind: kindOther},
	"endpoint":            {kind: kindOther},
}

// scriptHookKeys are wg-quick keys that execute shell commands. AWGSocks runs
// as a Windows service under LocalSystem; executing arbitrary commands from a
// configuration file would be a privilege-escalation vector, so these are
// rejected rather than ignored.
var scriptHookKeys = map[string]struct{}{
	"preup":    {},
	"postup":   {},
	"predown":  {},
	"postdown": {},
}

// emptyValueAllowed lists keys whose value may legitimately be empty, meaning
// "explicitly unset". Mirrors amneziawg-windows conf/parser.go.
var emptyValueAllowed = map[string]struct{}{
	"i1": {}, "i2": {}, "i3": {}, "i4": {}, "i5": {},
	"headerprotectionkey": {}, "contentpaddingaddition": {},
	"rekeyaftertime": {}, "rekeytimeout": {}, "rejectaftertime": {},
	"keepalivetimeout": {}, "maxhandshakeattempts": {},
	"randomtrailers": {}, "disablecookies": {},
}

// awgGeneration reports which AmneziaWG feature generation a configuration
// exercises, for display in `awgsocks status` and `awgsocks check`.
func awgGeneration(keys map[string]bool) string {
	has := func(names ...string) bool {
		for _, n := range names {
			if keys[n] {
				return true
			}
		}
		return false
	}
	switch {
	case has("i1", "i2", "i3", "i4", "i5", "headerprotectionkey", "contentpaddingaddition",
		"rekeyaftertime", "rekeytimeout", "rejectaftertime", "keepalivetimeout",
		"maxhandshakeattempts", "randomtrailers", "disablecookies"):
		return "AmneziaWG 2.0/3.x (I1-I5, header protection, timing parameters)"
	case has("s3", "s4"):
		return "AmneziaWG 1.5 (Jc/Jmin/Jmax, S1-S4, H1-H4)"
	case has("jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"):
		return "AmneziaWG legacy/1.0 (Jc/Jmin/Jmax, S1-S2, H1-H4)"
	default:
		return "plain WireGuard (no AmneziaWG parameters)"
	}
}

// normalizeKey lowercases a configuration key the same way the upstream parser
// does before matching.
func normalizeKey(k string) string {
	return strings.ToLower(strings.TrimSpace(k))
}
