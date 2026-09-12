package config

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// DefaultMTU matches the AmneziaWG Windows client default.
//
// It is derived the same way WireGuard derives its own default: a 1500 byte
// path, minus a 40 byte IPv6 header, minus an 8 byte UDP header, minus the 32
// bytes of WireGuard transport overhead (16 byte header plus 16 byte
// authentication tag). Using the IPv6 header size makes it safe for either
// endpoint family.
const DefaultMTU = 1420

// MinSafeMTU is the floor for an automatically derived MTU. It is the minimum
// MTU IPv6 requires, so the tunnel stays usable no matter how much per-packet
// obfuscation the configuration asks for.
const MinSafeMTU = 1280

// SafeMTU returns the largest tunnel MTU whose AmneziaWG packets still fit a
// standard 1500 byte path.
//
// AmneziaWG adds obfuscation bytes to every data packet that plain WireGuard
// does not have, and WireGuard's classic 1420 default does not account for
// them. With S4 = 43 the resulting UDP datagram is 1523 bytes, which a 1500
// byte path cannot carry: the datagram is fragmented or dropped outright.
//
// The effect is one sided and easy to misread. Downloads keep working, because
// the large packets in that direction are produced by the server. Uploads and
// anything else that sends a full size packet, such as a modern TLS
// ClientHello carrying a post-quantum key share, silently never arrive. The
// symptom is a browser stuck on "performing a TLS handshake" while simple
// requests succeed.
//
// s4 is the transport packet prefix and contentPaddingMax is the upper bound of
// ContentPaddingAddition; both are added to every data packet.
func SafeMTU(s4, contentPaddingMax int) int {
	mtu := DefaultMTU - s4 - contentPaddingMax
	if mtu < MinSafeMTU {
		return MinSafeMTU
	}
	return mtu
}

// headerCipherNonceSize mirrors device.HeaderCipherNonceSize in amneziawg-go.
// When HeaderProtectionKey is set, S1-S4 must be at least this large.
const headerCipherNonceSize = 12

// upstreamVersionNote names the pinned upstream in validation errors.
const upstreamVersionNote = "amneziawg-go v3.1.20260828"

// Tunnel is a validated AmneziaWG tunnel configuration plus the metadata
// AWGSocks needs on top of it.
type Tunnel struct {
	// Config is the official upstream representation, produced by the official
	// upstream parser. It is the only thing handed to the upstream UAPI writer.
	Config *conf.Config

	// Path is the absolute path the configuration was read from.
	Path string

	// Addresses are the tunnel-local addresses assigned to the userspace
	// network stack (from [Interface] Address).
	Addresses []netip.Addr

	// AddressPrefixes keeps the original CIDR form for display.
	AddressPrefixes []netip.Prefix

	// DNS are the resolvers reachable through the tunnel (from [Interface] DNS).
	DNS []netip.Addr

	// DNSSearch holds non-IP DNS entries (search domains). AWGSocks does not
	// implement search-domain expansion; the field exists so that its presence
	// can be reported rather than silently dropped.
	DNSSearch []string

	// MTU for the userspace network stack.
	MTU int

	// MTUExplicit reports whether the MTU came from the configuration file
	// rather than from SafeMTU.
	MTUExplicit bool

	// Generation is a human-readable description of which AmneziaWG feature
	// generation this configuration exercises.
	Generation string

	// AWGParams lists the AmneziaWG-specific keys present, in canonical
	// spelling, for status output.
	AWGParams []string

	// Warnings are non-fatal observations produced during validation.
	Warnings []string

	// s4 is the transport packet prefix length, kept for the parts of the
	// runtime that need to know the per-packet framing.
	s4 int
}

// PerPacketPrefix reports the S4 prefix length applied to every transport
// packet. Zero means plain WireGuard framing.
func (t *Tunnel) PerPacketPrefix() int { return t.s4 }

// AddressOfFamily returns the first tunnel address of the given family.
//
// A gVisor endpoint can only send within the family it is bound to, and binding
// to the wildcard address breaks source address selection, so sockets are bound
// to a concrete tunnel address.
func (t *Tunnel) AddressOfFamily(ipv6 bool) (netip.Addr, bool) {
	for _, a := range t.Addresses {
		if a.Is6() == ipv6 {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// HasFamily reports whether the tunnel carries an address of the given family.
func (t *Tunnel) HasFamily(ipv6 bool) bool {
	_, ok := t.AddressOfFamily(ipv6)
	return ok
}

// Endpoint returns the configured peer endpoint in host:port form.
func (t *Tunnel) Endpoint() string {
	if len(t.Config.Peers) == 0 {
		return ""
	}
	return t.Config.Peers[0].Endpoint.String()
}

// PublicKeyHex returns the first peer public key in the hex form used by UAPI.
func (t *Tunnel) PublicKeyHex() string {
	if len(t.Config.Peers) == 0 {
		return ""
	}
	return t.Config.Peers[0].PublicKey.HexString()
}

// LoadTunnel reads, decodes, validates and parses an AmneziaWG .conf file.
func LoadTunnel(path string) (*Tunnel, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("could not read the configuration file: %w", err)
	}
	return ParseTunnel(raw, abs)
}

// ParseTunnel validates and parses raw AmneziaWG configuration bytes.
// The path argument is used for the tunnel name and for error messages only.
func ParseTunnel(raw []byte, path string) (*Tunnel, error) {
	text := decodeText(raw)

	scan, err := scanConfig(text)
	if err != nil {
		return nil, err
	}
	warnings, err := validateScan(scan)
	if err != nil {
		return nil, err
	}

	name := tunnelNameFromPath(path)
	cfg, err := conf.FromWgQuickWithUnknownEncoding(text, name)
	if err != nil {
		return nil, fmt.Errorf("could not parse the AmneziaWG configuration: %w", err)
	}

	t := &Tunnel{
		Config:     cfg,
		Path:       path,
		MTU:        int(cfg.Interface.MTU),
		Generation: awgGeneration(scan.interfaceKeys),
		AWGParams:  scan.awgParamList(),
		Warnings:   warnings,
	}
	if t.MTU == 0 {
		t.MTU = DefaultMTU
	}

	// AmneziaWG adds bytes to every data packet that plain WireGuard does not
	// have, and the 1420 default does not account for them, so the MTU is
	// derived here unless the configuration states one explicitly.
	s4, cpaMax := scan.perPacketOverhead()
	t.s4 = s4
	safe := SafeMTU(s4, cpaMax)
	t.MTUExplicit = scan.interfaceKeys["mtu"]

	switch {
	case !t.MTUExplicit && safe != t.MTU:
		t.MTU = safe
		if s4 > 0 || cpaMax > 0 {
			t.Warnings = append(t.Warnings, fmt.Sprintf(
				"MTU lowered to %d automatically: AmneziaWG adds S4=%d plus up to %d bytes of "+
					"ContentPaddingAddition to every packet, so at 1420 the result does not fit a "+
					"1500 byte path and large outbound packets are lost", safe, s4, cpaMax))
		}
	case t.MTUExplicit && t.MTU > safe:
		t.Warnings = append(t.Warnings, fmt.Sprintf(
			"MTU = %d is too high for a 1500 byte path once AmneziaWG overhead is added. "+
				"Large outbound packets may be lost, which stalls TLS handshakes and breaks uploads. "+
				"Recommended value: %d", t.MTU, safe))
	}

	if err := t.finalize(); err != nil {
		return nil, err
	}
	return t, nil
}

// finalize converts the upstream representation into the netip forms the
// userspace network stack needs, and applies the remaining semantic checks.
func (t *Tunnel) finalize() error {
	cfg := t.Config

	if len(cfg.Interface.Addresses) == 0 {
		return errors.New("[Interface] Address is missing: the userspace network stack needs a tunnel address")
	}
	for _, a := range cfg.Interface.Addresses {
		addr, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			return fmt.Errorf("invalid Address value: %s", a.String())
		}
		addr = addr.Unmap()
		prefix := netip.PrefixFrom(addr, int(a.Cidr))
		if !prefix.IsValid() {
			return fmt.Errorf("invalid Address prefix: %s", a.String())
		}
		t.Addresses = append(t.Addresses, addr)
		t.AddressPrefixes = append(t.AddressPrefixes, prefix)
	}

	for _, d := range cfg.Interface.DNS {
		addr, ok := netip.AddrFromSlice(d)
		if !ok {
			return fmt.Errorf("invalid DNS address: %s", d.String())
		}
		t.DNS = append(t.DNS, addr.Unmap())
	}
	t.DNSSearch = cfg.Interface.DNSSearch
	if len(t.DNSSearch) > 0 {
		t.Warnings = append(t.Warnings, fmt.Sprintf(
			"DNS search domains (%s) are not applied: AWGSocks only resolves fully qualified names",
			strings.Join(t.DNSSearch, ", ")))
	}
	if len(t.DNS) == 0 {
		t.Warnings = append(t.Warnings,
			"[Interface] DNS is not set: hostname requests over SOCKS5 will be refused and only IP destinations will work")
	}

	if len(cfg.Peers) == 0 {
		return errors.New("there is no [Peer] section: AWGSocks is an AmneziaWG client and needs at least one peer")
	}
	if len(cfg.Peers) > 1 {
		t.Warnings = append(t.Warnings, fmt.Sprintf(
			"%d peers are defined: egress is selected by AllowedIPs matching", len(cfg.Peers)))
	}
	for i := range cfg.Peers {
		p := &cfg.Peers[i]
		if p.PublicKey.IsZero() {
			return fmt.Errorf("peer #%d has no PublicKey", i+1)
		}
		if p.Endpoint.IsEmpty() {
			return fmt.Errorf("peer #%d has no Endpoint: the client must know which server to reach", i+1)
		}
		if p.Endpoint.Port == 0 {
			return fmt.Errorf("peer #%d has an invalid Endpoint port: %s", i+1, p.Endpoint.String())
		}
		if len(p.AllowedIPs) == 0 {
			return fmt.Errorf("peer #%d has no AllowedIPs: no traffic could ever be routed to it", i+1)
		}
	}

	if t.MTU < 576 || t.MTU > 65535 {
		return fmt.Errorf("invalid MTU: %d", t.MTU)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Raw scan and validation
// ---------------------------------------------------------------------------

type kv struct {
	key   string
	value string
	line  int
}

type configScan struct {
	iface         []kv
	peers         [][]kv
	interfaceKeys map[string]bool
}

// awgParamList returns the AmneziaWG-specific keys present, in canonical order.
func (s *configScan) awgParamList() []string {
	order := []string{
		"jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
		"h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
		"headerprotectionkey", "contentpaddingaddition",
		"rekeyaftertime", "rekeytimeout", "rejectaftertime",
		"keepalivetimeout", "maxhandshakeattempts",
		"randomtrailers", "disablecookies",
	}
	display := map[string]string{
		"headerprotectionkey": "HeaderProtectionKey", "contentpaddingaddition": "ContentPaddingAddition",
		"rekeyaftertime": "RekeyAfterTime", "rekeytimeout": "RekeyTimeout",
		"rejectaftertime": "RejectAfterTime", "keepalivetimeout": "KeepaliveTimeout",
		"maxhandshakeattempts": "MaxHandshakeAttempts",
		"randomtrailers":       "RandomTrailers", "disablecookies": "DisableCookies",
	}
	var out []string
	for _, k := range order {
		if !s.interfaceKeys[k] {
			continue
		}
		if d, ok := display[k]; ok {
			out = append(out, d)
		} else {
			out = append(out, strings.ToUpper(k))
		}
	}
	return out
}

// perPacketOverhead returns the AmneziaWG bytes added to every transport
// packet: the S4 prefix and the upper bound of ContentPaddingAddition.
//
// The junk packets (Jc/Jmin/Jmax) and the S1-S3 prefixes are not included,
// because they apply to handshake and cookie packets, which are far smaller
// than the MTU and therefore never the packet that overflows the path.
func (s *configScan) perPacketOverhead() (s4, contentPaddingMax int) {
	for _, e := range s.iface {
		switch e.key {
		case "s4":
			if v, err := strconv.Atoi(e.value); err == nil && v > 0 {
				s4 = v
			}
		case "contentpaddingaddition":
			if _, hi, err := ParseUintRange(e.value, 32); err == nil {
				contentPaddingMax = int(hi)
			}
		}
	}
	return s4, contentPaddingMax
}

var sectionRe = regexp.MustCompile(`^\[(.+)\]$`)

// scanConfig performs a structural pass over the configuration text without
// interpreting values, so that validateScan can report precise errors.
func scanConfig(text string) (*configScan, error) {
	s := &configScan{interfaceKeys: map[string]bool{}}
	section := ""
	var current []kv

	flushPeer := func() {
		if section == "peer" {
			s.peers = append(s.peers, current)
		}
		current = nil
	}

	for i, line := range strings.Split(text, "\n") {
		lineNo := i + 1
		if p := strings.IndexByte(line, '#'); p >= 0 {
			line = line[:p]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if m := sectionRe.FindStringSubmatch(line); m != nil {
			name := strings.ToLower(strings.TrimSpace(m[1]))
			switch name {
			case "interface":
				flushPeer()
				section = "interface"
			case "peer":
				flushPeer()
				section = "peer"
			default:
				return nil, fmt.Errorf("line %d: unknown section [%s] (only [Interface] and [Peer] are supported)", lineNo, m[1])
			}
			continue
		}
		if section == "" {
			return nil, fmt.Errorf("line %d: %q must appear inside a section ([Interface] or [Peer])", lineNo, line)
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: %q has no equals separator", lineNo, line)
		}
		entry := kv{key: normalizeKey(key), value: strings.TrimSpace(value), line: lineNo}
		if section == "interface" {
			s.iface = append(s.iface, entry)
			s.interfaceKeys[entry.key] = true
		} else {
			current = append(current, entry)
		}
	}
	flushPeer()

	if len(s.iface) == 0 {
		return nil, errors.New("there is no [Interface] section")
	}
	return s, nil
}

// validateScan applies the strict AWGSocks parameter policy. It returns
// warnings for non-fatal observations and an error for anything the pinned
// upstream implementation cannot honour.
func validateScan(s *configScan) ([]string, error) {
	var warnings []string
	seen := map[string]int{}

	for _, e := range s.iface {
		if _, isHook := scriptHookKeys[e.key]; isHook {
			return nil, fmt.Errorf(
				"line %d: %q is not supported: AWGSocks runs as a LocalSystem service and does not "+
					"execute commands from a configuration file. Remove this key",
				e.line, e.key)
		}
		p, ok := interfaceParams[e.key]
		if !ok {
			return nil, fmt.Errorf(
				"line %d: unsupported AWG parameter %q. The pinned upstream (%s) does not implement this key, "+
					"and ignoring it silently would be worse than failing", e.line, e.key, upstreamVersionNote)
		}
		if seen[e.key] > 0 {
			return nil, fmt.Errorf("line %d: %q is defined more than once in [Interface] (first at line %d)",
				e.line, e.key, seen[e.key])
		}
		seen[e.key] = e.line

		if e.value == "" {
			if _, allowed := emptyValueAllowed[e.key]; !allowed {
				return nil, fmt.Errorf("line %d: %q has no value", e.line, e.key)
			}
			continue
		}
		w, err := validateValue(e, p)
		if err != nil {
			return nil, err
		}
		warnings = append(warnings, w...)
	}

	w, err := validateInterfaceSemantics(s)
	if err != nil {
		return nil, err
	}
	warnings = append(warnings, w...)

	for pi, peer := range s.peers {
		pseen := map[string]bool{}
		for _, e := range peer {
			p, ok := peerParams[e.key]
			if !ok {
				return nil, fmt.Errorf("line %d: unsupported parameter %q in the [Peer] section", e.line, e.key)
			}
			if pseen[e.key] {
				return nil, fmt.Errorf("line %d: %[3]q is defined more than once in peer #%[2]d", e.line, pi+1, e.key)
			}
			pseen[e.key] = true
			if e.value == "" {
				return nil, fmt.Errorf("line %d: %q has no value", e.line, e.key)
			}
			if _, err := validateValue(e, p); err != nil {
				return nil, err
			}
		}
	}
	return warnings, nil
}

func validateValue(e kv, p supportedParam) ([]string, error) {
	var warnings []string
	switch p.kind {
	case kindUint16:
		v, err := strconv.ParseUint(e.value, 10, 64)
		if err != nil || v > math.MaxUint16 {
			return nil, fmt.Errorf("line %d: invalid %s value %q: it must be an integer between 0 and 65535",
				e.line, strings.ToUpper(e.key), e.value)
		}
	case kindRangeU32:
		if _, _, err := ParseUintRange(e.value, 32); err != nil {
			return nil, fmt.Errorf("line %d: invalid %s range %q: %v (format: a or a-b, 0 to 4294967295)",
				e.line, strings.ToUpper(e.key), e.value, err)
		}
	case kindRangeU16:
		lo, hi, err := ParseUintRange(e.value, 32)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid %s range %q: %v (format: a or a-b)",
				e.line, e.key, e.value, err)
		}
		// The official documentation types these as range<uint16> while the
		// pinned upstream accepts uint32, so anything above the limit is a warning.
		if hi > math.MaxUint16 || lo > math.MaxUint16 {
			warnings = append(warnings, fmt.Sprintf(
				"line %d: %s value %q is above 65535; the official documentation types this parameter as "+
					"range<uint16> while the pinned upstream accepts range<uint32>", e.line, e.key, e.value))
		}
	case kindBool:
		if _, err := ParseAWGBool(e.value); err != nil {
			return nil, fmt.Errorf("line %d: invalid %s value %q: it must be on/off, true/false or 1/0",
				e.line, e.key, e.value)
		}
	case kindKeyBase64:
		if err := validateBase64Key(e.value); err != nil {
			return nil, fmt.Errorf("line %d: invalid %s: %v", e.line, e.key, err)
		}
	case kindObfChain:
		// I1-I5 chain descriptions can only be validated by the upstream device,
		// which the dry run performed by `awgsocks check` does.
	case kindOther:
		switch e.key {
		case "address":
			if err := validateCIDRList(e.value); err != nil {
				return nil, fmt.Errorf("line %d: invalid Address: %v", e.line, err)
			}
		case "allowedips":
			if err := validateCIDRList(e.value); err != nil {
				return nil, fmt.Errorf("line %d: invalid AllowedIPs: %v", e.line, err)
			}
		case "dns":
			if err := validateDNSList(e.value); err != nil {
				return nil, fmt.Errorf("line %d: invalid DNS: %v", e.line, err)
			}
		case "endpoint":
			if err := validateEndpoint(e.value); err != nil {
				return nil, fmt.Errorf("line %d: invalid Endpoint %q: %v", e.line, e.value, err)
			}
		case "persistentkeepalive":
			if e.value != "off" && e.value != "(off)" {
				v, err := strconv.ParseUint(e.value, 10, 64)
				if err != nil || v > 65535 {
					return nil, fmt.Errorf("line %d: invalid PersistentKeepalive %q: 0 to 65535 seconds, or off",
						e.line, e.value)
				}
			}
		case "mtu":
			v, err := strconv.Atoi(e.value)
			if err != nil || v < 576 || v > 65535 {
				return nil, fmt.Errorf("line %d: invalid MTU %q: 576 to 65535", e.line, e.value)
			}
		case "table":
			if strings.ToLower(e.value) != "off" {
				return nil, fmt.Errorf(
					"line %d: Table = %q is not supported. AWGSocks installs no Windows route, and a "+
						"configuration asking for system wide routing must not be ignored silently. "+
						"Remove this line or write Table = off", e.line, e.value)
			}
		}
	}
	return warnings, nil
}

// validateInterfaceSemantics checks relationships between AmneziaWG parameters
// that only make sense once the whole [Interface] section is known.
func validateInterfaceSemantics(s *configScan) ([]string, error) {
	var warnings []string
	get := func(key string) (string, bool) {
		for _, e := range s.iface {
			if e.key == key {
				return e.value, e.value != ""
			}
		}
		return "", false
	}
	num := func(key string) (uint64, bool) {
		v, ok := get(key)
		if !ok {
			return 0, false
		}
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}

	// Junk generation upstream computes min + rand(max-min). When Jmin exceeds
	// Jmax that subtraction underflows a uint32 and asks for an enormous
	// allocation, so the combination is rejected outright here.
	jc, hasJc := num("jc")
	jmin, hasJmin := num("jmin")
	jmax, hasJmax := num("jmax")
	if hasJc && jc > 0 {
		if !hasJmin || !hasJmax {
			return nil, errors.New("Jmin and Jmax must be set whenever Jc is greater than zero")
		}
		if jmin > jmax {
			return nil, fmt.Errorf("Jmin (%d) must not be greater than Jmax (%d)", jmin, jmax)
		}
		if jmax == 0 {
			return nil, errors.New("Jmax must not be zero while Jc is greater than zero")
		}
	}
	if (hasJmin || hasJmax) && (!hasJc || jc == 0) {
		warnings = append(warnings, "Jmin and Jmax are set but Jc is zero, so no junk packets will be sent")
	}

	// H1-H4 ranges must not overlap. The upstream device rejects that too
	// (device/uapi.go mergeWithDevice: headers must not overlap).
	type hdr struct {
		name   string
		lo, hi uint64
	}
	var headers []hdr
	for _, name := range []string{"h1", "h2", "h3", "h4"} {
		v, ok := get(name)
		if !ok {
			continue
		}
		lo, hi, err := ParseUintRange(v, 32)
		if err != nil {
			continue // validateValue has already reported this
		}
		headers = append(headers, hdr{strings.ToUpper(name), lo, hi})
	}
	for i := 0; i < len(headers); i++ {
		for j := i + 1; j < len(headers); j++ {
			a, b := headers[i], headers[j]
			if a.lo <= b.hi && b.lo <= a.hi {
				return nil, fmt.Errorf(
					"%s (%d-%d) and %s (%d-%d) overlap: AmneziaWG message type ranges must be disjoint",
					a.name, a.lo, a.hi, b.name, b.lo, b.hi)
			}
		}
	}
	if len(headers) > 0 && len(headers) < 4 {
		var missing []string
		for _, name := range []string{"H1", "H2", "H3", "H4"} {
			found := false
			for _, h := range headers {
				if h.name == name {
					found = true
				}
			}
			if !found {
				missing = append(missing, name)
			}
		}
		warnings = append(warnings, fmt.Sprintf(
			"%s not set: those message types stay at the standard WireGuard values (1 to 4)",
			strings.Join(missing, ", ")))
	}

	// With HeaderProtectionKey in use, S1-S4 must be at least the nonce size.
	// Upstream mergeWithDevice applies the same rule.
	if _, ok := get("headerprotectionkey"); ok {
		for _, name := range []string{"s1", "s2", "s3", "s4"} {
			v, has := num(name)
			if !has || v < headerCipherNonceSize {
				cur, present := get(name)
				if !present {
					cur = "unset"
				}
				return nil, fmt.Errorf(
					"%[1]s must be at least %[2]d when HeaderProtectionKey is set (current value: %[3]s)",
					strings.ToUpper(name), headerCipherNonceSize, cur)
			}
		}
	}
	return warnings, nil
}

// ---------------------------------------------------------------------------
// Value helpers
// ---------------------------------------------------------------------------

// ParseUintRange parses the AmneziaWG range syntax documented at
// https://docs.amnezia.org/documentation/amnezia-wg/ : either a single fixed
// value "a" or an inclusive range "a-b". bits is 16 or 32.
//
// This mirrors device.UintRange.FromString in amneziawg-go exactly, including
// the rule that the upper bound must not be smaller than the lower bound.
func ParseUintRange(s string, bits int) (lo, hi uint64, err error) {
	parts := strings.Split(strings.TrimSpace(s), "-")
	if len(parts) < 1 || len(parts) > 2 {
		return 0, 0, errors.New("malformed range")
	}
	lo, err = strconv.ParseUint(strings.TrimSpace(parts[0]), 10, bits)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid lower bound: %s", parts[0])
	}
	hi = lo
	if len(parts) == 2 {
		hi, err = strconv.ParseUint(strings.TrimSpace(parts[1]), 10, bits)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid upper bound: %s", parts[1])
		}
	}
	if hi < lo {
		return 0, 0, fmt.Errorf("the upper bound (%d) is below the lower bound (%d)", hi, lo)
	}
	return lo, hi, nil
}

// ParseAWGBool parses the on/off form used by awg-quick configuration files.
func ParseAWGBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "on", "1", "true", "t", "yes":
		return true, nil
	case "off", "0", "false", "f", "no":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value %q", s)
	}
}

func validateBase64Key(s string) error {
	decoded, err := decodeStdBase64(s)
	if err != nil {
		return fmt.Errorf("could not decode base64: %v", err)
	}
	if len(decoded) != 32 {
		return fmt.Errorf("a key must decode to exactly 32 bytes, got %d", len(decoded))
	}
	return nil
}

func validateCIDRList(s string) error {
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return errors.New("empty element (two commas in a row)")
		}
		if strings.Contains(part, "/") {
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return fmt.Errorf("invalid CIDR %q: %v", part, err)
			}
			if p.Addr().Is4() && p.Bits() > 32 {
				return fmt.Errorf("invalid prefix length for IPv4: %q", part)
			}
			continue
		}
		if _, err := netip.ParseAddr(part); err != nil {
			return fmt.Errorf("invalid IP address %q: %v", part, err)
		}
	}
	return nil
}

func validateDNSList(s string) error {
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return errors.New("empty element (two commas in a row)")
		}
		if _, err := netip.ParseAddr(part); err != nil {
			// Upstream treats non-IP entries as search domains.
			if strings.ContainsAny(part, " \t") {
				return fmt.Errorf("invalid DNS entry %q", part)
			}
		}
	}
	return nil
}

func validateEndpoint(s string) error {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return errors.New("the port is missing")
	}
	host, portStr := s[:i], s[i+1:]
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("invalid port %q", portStr)
	}
	if host == "" {
		return errors.New("the host is empty")
	}
	if strings.HasPrefix(host, "[") {
		if !strings.HasSuffix(host, "]") {
			return errors.New("the IPv6 address has no closing bracket")
		}
		inner := host[1 : len(host)-1]
		if idx := strings.LastIndexByte(inner, '%'); idx > 0 {
			inner = inner[:idx]
		}
		if _, err := netip.ParseAddr(inner); err != nil {
			return fmt.Errorf("invalid IPv6 address %q", inner)
		}
		return nil
	}
	if strings.Contains(host, ":") {
		return errors.New("an IPv6 address must be bracketed, for example [fd00::1]:51820")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	// A hostname: only a coarse shape check here, resolution happens at connect time.
	if len(host) > 253 || strings.ContainsAny(host, " \t/\\") {
		return fmt.Errorf("invalid host %q", host)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Text decoding and naming
// ---------------------------------------------------------------------------

// decodeText converts a configuration file to UTF-8. The AmneziaWG Windows
// client writes UTF-16 files with a BOM; Amnezia mobile and server-generated
// files are UTF-8. Both are accepted.
func decodeText(raw []byte) string {
	switch {
	case bytes.HasPrefix(raw, []byte{0xFF, 0xFE}):
		return decodeUTF16(raw[2:], false)
	case bytes.HasPrefix(raw, []byte{0xFE, 0xFF}):
		return decodeUTF16(raw[2:], true)
	case bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}):
		raw = raw[3:]
	}
	if utf8.Valid(raw) && !bytes.Contains(raw, []byte{0x00}) {
		return string(raw)
	}
	// With no BOM, content carrying NUL bytes is probably UTF-16LE, so try it.
	if len(raw)%2 == 0 {
		return decodeUTF16(raw, false)
	}
	return string(raw)
}

func decodeUTF16(b []byte, bigEndian bool) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		if bigEndian {
			u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		} else {
			u[i] = uint16(b[2*i+1])<<8 | uint16(b[2*i])
		}
	}
	return string(utf16.Decode(u))
}

var unsafeNameChars = regexp.MustCompile(`[^a-zA-Z0-9_=+.-]`)

// tunnelNameFromPath derives an upstream-valid tunnel name from the config file
// name. The upstream parser rejects names outside ^[a-zA-Z0-9_=+.-]{1,32}$.
func tunnelNameFromPath(path string) string {
	base := filepath.Base(path)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	base = unsafeNameChars.ReplaceAllString(base, "_")
	if len(base) > 32 {
		base = base[:32]
	}
	if base == "" || !conf.TunnelNameIsValid(base) {
		return "awgsocks"
	}
	return base
}
