package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// Test key material. These are randomly generated 32-byte values used only by
// the test suite; they are not connected to any real deployment.
const (
	testPrivateKey  = "YK6ykvX+Ql0uI0NcocLtcl53xfgvWCs1xnfjLkKFEFc="
	testPublicKey   = "ODQSPx7PXqCrsYPrVSD8qzBo/GPPS7QzGr2w1FM0j0I="
	testPresharedKy = "0FMxkxJzb9ChYNbL8pktnkTYiGbTKvpzsKaZZXNY5lY="
	testHeaderKey   = "sKjILpwPIu+oZQE9DohGjaWEsiqG92wQ7hXp21dVrlA="
)

// userConfig is the exact configuration class named in the AWGSocks
// requirements: AmneziaWG 1.5 with Jc/Jmin/Jmax, S1-S4 and H1-H4 ranges.
const userConfig = `[Interface]
PrivateKey = ` + testPrivateKey + `
Address = 10.66.66.2/32,fd42:42:42::2/128
DNS = 1.1.1.1,1.0.0.1

Jc = 10
Jmin = 50
Jmax = 1000

S1 = 150
S2 = 135
S3 = 107
S4 = 43

H1 = 301745575-401745574
H2 = 876826554-976826553
H3 = 1337755454-1437755454
H4 = 1776593183-1876593183

[Peer]
PublicKey = ` + testPublicKey + `
PresharedKey = ` + testPresharedKy + `
Endpoint = 203.0.113.10:54522
AllowedIPs = 0.0.0.0/0,::/0
`

func parse(t *testing.T, text string) (*Tunnel, error) {
	t.Helper()
	return ParseTunnel([]byte(text), filepath.Join(t.TempDir(), "client.conf"))
}

func mustParse(t *testing.T, text string) *Tunnel {
	t.Helper()
	tun, err := parse(t, text)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	return tun
}

func TestUserConfigurationClassIsAccepted(t *testing.T) {
	tun := mustParse(t, userConfig)

	if len(tun.Addresses) != 2 {
		t.Fatalf("expected 2 tunnel addresses, got %d", len(tun.Addresses))
	}
	if tun.Addresses[0].String() != "10.66.66.2" || tun.Addresses[1].String() != "fd42:42:42::2" {
		t.Fatalf("the IPv4 and IPv6 tunnel addresses are wrong: %v", tun.Addresses)
	}
	if tun.AddressPrefixes[0].String() != "10.66.66.2/32" || tun.AddressPrefixes[1].String() != "fd42:42:42::2/128" {
		t.Fatalf("the prefix information was not preserved: %v", tun.AddressPrefixes)
	}
	if len(tun.DNS) != 2 {
		t.Fatalf("expected 2 DNS servers, got %d", len(tun.DNS))
	}
	// The MTU is derived from the AmneziaWG overhead; the plain WireGuard
	// default of 1420 is too high for this configuration.
	if tun.MTU != SafeMTU(43, 0) {
		t.Fatalf("expected a derived MTU of %d, got %d", SafeMTU(43, 0), tun.MTU)
	}
	if got, want := tun.Endpoint(), "203.0.113.10:54522"; got != want {
		t.Fatalf("expected endpoint %q, got %q", want, got)
	}
	if !strings.Contains(tun.Generation, "1.5") {
		t.Fatalf("expected the AmneziaWG 1.5 generation, got %s", tun.Generation)
	}

	// AllowedIPs 0.0.0.0/0 and ::/0 must be accepted, but never as Windows routes.
	peer := tun.Config.Peers[0]
	if len(peer.AllowedIPs) != 2 {
		t.Fatalf("expected 2 AllowedIPs entries, got %d", len(peer.AllowedIPs))
	}
	if peer.AllowedIPs[0].String() != "0.0.0.0/0" || peer.AllowedIPs[1].String() != "::/0" {
		t.Fatalf("AllowedIPs was not preserved: %v", peer.AllowedIPs)
	}
	if peer.PresharedKey.IsZero() {
		t.Fatal("PresharedKey was not preserved")
	}
}

func TestUserConfigurationProducesExpectedUAPI(t *testing.T) {
	tun := mustParse(t, userConfig)
	uapi, err := tun.Config.ToUAPI()
	if err != nil {
		t.Fatalf("could not generate the UAPI document: %v", err)
	}

	// Check that the AmneziaWG parameters reach the UAPI under the exact
	// upstream key names with their values intact.
	want := []string{
		"jc=10", "jmin=50", "jmax=1000",
		"s1=150", "s2=135", "s3=107", "s4=43",
		"h1=301745575-401745574",
		"h2=876826554-976826553",
		"h3=1337755454-1437755454",
		"h4=1776593183-1876593183",
		"endpoint=203.0.113.10:54522",
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
		"replace_peers=true",
	}
	for _, w := range want {
		if !strings.Contains(uapi, w+"\n") {
			t.Errorf("the UAPI output is missing %q", w)
		}
	}

	// The H1-H4 ranges must not be collapsed to a single value.
	if strings.Contains(uapi, "h1=301745575\n") {
		t.Error("the H1 range was collapsed to a single value")
	}
}

func TestHeaderRangeSyntax(t *testing.T) {
	cases := []struct {
		in      string
		lo, hi  uint64
		wantErr bool
	}{
		{"301745575-401745574", 301745575, 401745574, false},
		{"5", 5, 5, false},
		{"0-4294967295", 0, 4294967295, false},
		{"10-5", 0, 0, true},
		{"4294967296", 0, 0, true},
		{"abc", 0, 0, true},
		{"1-2-3", 0, 0, true},
		{"", 0, 0, true},
	}
	for _, c := range cases {
		lo, hi, err := ParseUintRange(c.in, 32)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: expected an error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error: %v", c.in, err)
			continue
		}
		if lo != c.lo || hi != c.hi {
			t.Errorf("%q: expected %d-%d, got %d-%d", c.in, c.lo, c.hi, lo, hi)
		}
	}
}

func TestUnsupportedParameterIsRejected(t *testing.T) {
	cfg := strings.Replace(userConfig, "Jc = 10", "Jc = 10\nS5 = 99", 1)
	_, err := parse(t, cfg)
	if err == nil {
		t.Fatal("an unsupported parameter was accepted")
	}
	if !strings.Contains(err.Error(), "unsupported AWG parameter") {
		t.Fatalf("expected a clear incompatibility error, got %v", err)
	}
}

func TestScriptHooksAreRejected(t *testing.T) {
	for _, key := range []string{"PreUp", "PostUp", "PreDown", "PostDown"} {
		cfg := strings.Replace(userConfig, "DNS = 1.1.1.1,1.0.0.1",
			"DNS = 1.1.1.1,1.0.0.1\n"+key+" = calc.exe", 1)
		if _, err := parse(t, cfg); err == nil {
			t.Fatalf("%s was accepted but should have been rejected", key)
		}
	}
}

func TestTableDirectiveOnlyAllowsOff(t *testing.T) {
	off := strings.Replace(userConfig, "DNS = 1.1.1.1,1.0.0.1", "DNS = 1.1.1.1,1.0.0.1\nTable = off", 1)
	if _, err := parse(t, off); err != nil {
		t.Fatalf("Table = off should have been accepted: %v", err)
	}
	auto := strings.Replace(userConfig, "DNS = 1.1.1.1,1.0.0.1", "DNS = 1.1.1.1,1.0.0.1\nTable = auto", 1)
	if _, err := parse(t, auto); err == nil {
		t.Fatal("Table = auto should have been rejected")
	}
}

func TestOverlappingHeaderRangesRejected(t *testing.T) {
	cfg := strings.Replace(userConfig,
		"H2 = 876826554-976826553",
		"H2 = 301745500-401745600", 1)
	_, err := parse(t, cfg)
	if err == nil {
		t.Fatal("overlapping H ranges were accepted")
	}
	if !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("expected an overlap error, got %v", err)
	}
}

func TestJunkBoundsValidated(t *testing.T) {
	// Jmin greater than Jmax underflows a uint32 upstream and asks for an
	// enormous allocation, so it must be rejected outright.
	cfg := strings.Replace(userConfig, "Jmin = 50\nJmax = 1000", "Jmin = 1000\nJmax = 50", 1)
	if _, err := parse(t, cfg); err == nil {
		t.Fatal("Jmin greater than Jmax was accepted")
	}

	cfg = strings.Replace(userConfig, "Jmin = 50\nJmax = 1000", "", 1)
	if _, err := parse(t, cfg); err == nil {
		t.Fatal("missing Jmin and Jmax were accepted while Jc is greater than zero")
	}
}

func TestHeaderProtectionRequiresLargeEnoughPaddings(t *testing.T) {
	cfg := strings.Replace(userConfig, "S4 = 43", "S4 = 4\nHeaderProtectionKey = "+testHeaderKey, 1)
	_, err := parse(t, cfg)
	if err == nil {
		t.Fatal("a small S4 was accepted together with HeaderProtectionKey")
	}
	if !strings.Contains(err.Error(), "HeaderProtectionKey") {
		t.Fatalf("expected a clear error, got %v", err)
	}
}

func TestAWG3ParametersAccepted(t *testing.T) {
	cfg := strings.Replace(userConfig, "H4 = 1776593183-1876593183",
		"H4 = 1776593183-1876593183\n"+
			"HeaderProtectionKey = "+testHeaderKey+"\n"+
			"ContentPaddingAddition = 0-100\n"+
			"RekeyAfterTime = 100-140\n"+
			"RekeyTimeout = 4-6\n"+
			"RejectAfterTime = 150-200\n"+
			"KeepaliveTimeout = 8-12\n"+
			"MaxHandshakeAttempts = 10-20\n"+
			"RandomTrailers = on\n"+
			"DisableCookies = off", 1)
	tun, err := parse(t, cfg)
	if err != nil {
		t.Fatalf("the AmneziaWG 3.x parameters were rejected: %v", err)
	}
	if !strings.Contains(tun.Generation, "3.x") {
		t.Fatalf("expected the 3.x generation, got %s", tun.Generation)
	}
	uapi, err := tun.Config.ToUAPI()
	if err != nil {
		t.Fatalf("could not generate the UAPI document: %v", err)
	}
	for _, want := range []string{
		"content_padding_addition=0-100",
		"rekey_after_time=100-140",
		"rekey_timeout=4-6",
		"reject_after_time=150-200",
		"keepalive_timeout=8-12",
		"max_handshake_attempts=10-20",
		"random_trailers=1",
		"disable_cookies=0",
		"header_protection_key=",
	} {
		if !strings.Contains(uapi, want) {
			t.Errorf("the UAPI output is missing %q", want)
		}
	}
}

func TestInvalidValuesProduceUsefulErrors(t *testing.T) {
	cases := []struct {
		name    string
		replace [2]string
		wantSub string
	}{
		{"broken H1", [2]string{"H1 = 301745575-401745574", "H1 = 401745574-301745575"}, "H1"},
		{"broken endpoint", [2]string{"Endpoint = 203.0.113.10:54522", "Endpoint = 203.0.113.10"}, "Endpoint"},
		{"broken private key", [2]string{"PrivateKey = " + testPrivateKey, "PrivateKey = notbase64!!"}, "privatekey"},
		{"broken IPv6", [2]string{"Address = 10.66.66.2/32,fd42:42:42::2/128", "Address = 10.66.66.2/32,fd42::zz::2/128"}, "Address"},
		{"broken S1", [2]string{"S1 = 150", "S1 = 70000"}, "S1"},
		{"broken CIDR", [2]string{"AllowedIPs = 0.0.0.0/0,::/0", "AllowedIPs = 0.0.0.0/33"}, "AllowedIPs"},
	}
	for _, c := range cases {
		cfg := strings.Replace(userConfig, c.replace[0], c.replace[1], 1)
		_, err := parse(t, cfg)
		if err == nil {
			t.Errorf("%s: expected an error", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.wantSub) {
			t.Errorf("%s: the error should mention %q, got %v", c.name, c.wantSub, err)
		}
	}
}

func TestMissingPeerFieldsRejected(t *testing.T) {
	noEndpoint := strings.Replace(userConfig, "Endpoint = 203.0.113.10:54522\n", "", 1)
	if _, err := parse(t, noEndpoint); err == nil {
		t.Fatal("a configuration without Endpoint was accepted")
	}
	noAllowed := strings.Replace(userConfig, "AllowedIPs = 0.0.0.0/0,::/0\n", "", 1)
	if _, err := parse(t, noAllowed); err == nil {
		t.Fatal("a configuration without AllowedIPs was accepted")
	}
}

func TestUTF16ConfigIsDecoded(t *testing.T) {
	var raw []byte
	raw = append(raw, 0xFF, 0xFE)
	for _, r := range userConfig {
		raw = append(raw, byte(r), byte(r>>8))
	}
	tun, err := ParseTunnel(raw, filepath.Join(t.TempDir(), "client.conf"))
	if err != nil {
		t.Fatalf("could not read the UTF-16 configuration: %v", err)
	}
	if tun.Endpoint() != "203.0.113.10:54522" {
		t.Fatalf("UTF-16 decoding is broken: %s", tun.Endpoint())
	}
}

func TestNoDNSProducesWarningNotError(t *testing.T) {
	cfg := strings.Replace(userConfig, "DNS = 1.1.1.1,1.0.0.1\n", "", 1)
	tun, err := parse(t, cfg)
	if err != nil {
		t.Fatalf("a missing DNS line must not be an error: %v", err)
	}
	found := false
	for _, w := range tun.Warnings {
		if strings.Contains(w, "DNS") {
			found = true
		}
	}
	if !found {
		t.Fatal("no warning was produced for the missing DNS line")
	}
}

func TestParseAWGBool(t *testing.T) {
	for _, s := range []string{"on", "1", "true", "yes"} {
		if v, err := ParseAWGBool(s); err != nil || !v {
			t.Errorf("%q should be true", s)
		}
	}
	for _, s := range []string{"off", "0", "false", "no"} {
		if v, err := ParseAWGBool(s); err != nil || v {
			t.Errorf("%q should be false", s)
		}
	}
	if _, err := ParseAWGBool("maybe"); err == nil {
		t.Error("an invalid value was accepted")
	}
}

// TestSafeMTUAccountsForAmneziaOverhead covers the bug that made outbound
// full-size packets vanish: WireGuard's 1420 default does not leave room for
// the AmneziaWG per-packet prefix, so a 1500 byte path cannot carry the result.
func TestSafeMTUAccountsForAmneziaOverhead(t *testing.T) {
	cases := []struct {
		s4, cpa, want int
	}{
		{0, 0, 1420},    // plain WireGuard: the classic default is kept
		{43, 0, 1377},   // the target configuration
		{150, 0, 1270},  // falls back to the MinSafeMTU floor
		{43, 100, 1277}, // ContentPaddingAddition counts too
	}
	for _, c := range cases {
		got := SafeMTU(c.s4, c.cpa)
		want := c.want
		if want < MinSafeMTU {
			want = MinSafeMTU
		}
		if got != want {
			t.Errorf("SafeMTU(%d,%d) = %d, expected %d", c.s4, c.cpa, got, want)
		}
	}

	// The packet built from the derived MTU must fit a 1500 byte path.
	const s4 = 43
	mtu := SafeMTU(s4, 0)
	wire := mtu + s4 + 32 + 8 + 20 // AWG overhead + UDP + IPv4
	if wire > 1500 {
		t.Fatalf("with the derived MTU the packet is %d bytes, which does not fit a 1500 byte path", wire)
	}
}

func TestUserConfigurationGetsSafeMTU(t *testing.T) {
	tun := mustParse(t, userConfig)
	if tun.MTUExplicit {
		t.Fatal("the example configuration has no MTU line, so it must be derived")
	}
	if tun.MTU != SafeMTU(43, 0) {
		t.Fatalf("expected MTU %d, got %d", SafeMTU(43, 0), tun.MTU)
	}
	found := false
	for _, w := range tun.Warnings {
		if strings.Contains(w, "MTU lowered to") {
			found = true
		}
	}
	if !found {
		t.Errorf("no warning was produced for the lowered MTU: %v", tun.Warnings)
	}
}

func TestExplicitMTUIsHonouredButWarned(t *testing.T) {
	cfg := strings.Replace(userConfig, "DNS = 1.1.1.1,1.0.0.1",
		"DNS = 1.1.1.1,1.0.0.1\nMTU = 1420", 1)
	tun := mustParse(t, cfg)
	if !tun.MTUExplicit {
		t.Fatal("an explicit MTU was not flagged as explicit")
	}
	if tun.MTU != 1420 {
		t.Fatalf("an explicit MTU must not be changed, got %d", tun.MTU)
	}
	found := false
	for _, w := range tun.Warnings {
		if strings.Contains(w, "too high") {
			found = true
		}
	}
	if !found {
		t.Errorf("no warning was produced for the high MTU: %v", tun.Warnings)
	}

	// A safe value must not warn.
	safe := strings.Replace(userConfig, "DNS = 1.1.1.1,1.0.0.1",
		"DNS = 1.1.1.1,1.0.0.1\nMTU = 1377", 1)
	tun2 := mustParse(t, safe)
	for _, w := range tun2.Warnings {
		if strings.Contains(w, "too high") {
			t.Errorf("a safe MTU must not produce a warning: %s", w)
		}
	}
}
