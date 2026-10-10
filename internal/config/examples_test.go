package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestShippedExampleConfigJSONLoads guards the example application
// configuration: it must stay valid JSON with the exact field names the loader
// accepts, because LoadApp rejects unknown fields.
func TestShippedExampleConfigJSONLoads(t *testing.T) {
	src := filepath.Join("..", "..", "config", "config.example.json")
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("could not read the example config.json: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(dst, raw, 0o600); err != nil {
		t.Fatalf("could not copy it: %v", err)
	}

	app, err := LoadApp(dst)
	if err != nil {
		t.Fatalf("could not load the example config.json: %v", err)
	}
	if app.Socks5Listen != DefaultSocksListen {
		t.Errorf("unexpected socks5_listen in the example file: %s", app.Socks5Listen)
	}
	if app.UDPBind != DefaultUDPBind {
		t.Errorf("unexpected udp_bind in the example file: %s", app.UDPBind)
	}
	if !strings.HasSuffix(strings.ToLower(app.ConfigPath), "client.conf") {
		t.Errorf("unexpected config path in the example file: %s", app.ConfigPath)
	}
}

// TestShippedExampleConfParses guards the example AmneziaWG configuration.
// The keys are redacted placeholders, so parsing must fail on the key material
// and on nothing else: any other error would mean the example documents a
// parameter AWGSocks does not actually accept.
func TestShippedExampleConfParses(t *testing.T) {
	src := filepath.Join("..", "..", "config", "example.conf")
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("could not read the example .conf: %v", err)
	}

	// Replace the placeholder keys with valid test keys.
	text := string(raw)
	text = strings.Replace(text, "kDgLGlIv7Vxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=", testPrivateKey, 1)
	text = strings.Replace(text, "cu7q95KZxxxxPdJrA7aDEY3JOJIuDIC/vjSxmHG4=", testPublicKey, 1)
	text = strings.Replace(text, "cu7q95KZxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=", testPublicKey, 1)
	text = strings.Replace(text, "z+0pxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=", testPresharedKy, 1)

	tun, err := ParseTunnel([]byte(text), filepath.Join(t.TempDir(), "client.conf"))
	if err != nil {
		t.Fatalf("could not parse the example .conf: %v", err)
	}
	if !strings.Contains(tun.Generation, "1.5") {
		t.Errorf("the example file should be AmneziaWG 1.5 class, got %s", tun.Generation)
	}
	if len(tun.Addresses) != 2 {
		t.Errorf("the example file should carry an IPv4 and an IPv6 tunnel address, got %d", len(tun.Addresses))
	}
}
