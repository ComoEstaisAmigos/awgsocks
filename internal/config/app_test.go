package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoopbackOnlyListenIsEnforced(t *testing.T) {
	ok := []string{"127.0.0.1:10808", "127.0.0.2:1080", "[::1]:10808"}
	for _, a := range ok {
		if err := ValidateLoopbackListen(a); err != nil {
			t.Errorf("%s should have been accepted: %v", a, err)
		}
	}
	bad := []string{
		"0.0.0.0:10808",
		"[::]:10808",
		"192.168.1.20:10808",
		"10.0.0.5:10808",
		"8.8.8.8:10808",
		"127.0.0.1:0",
		"localhost:10808",
		"",
	}
	for _, a := range bad {
		if err := ValidateLoopbackListen(a); err == nil {
			t.Errorf("%q should have been rejected", a)
		}
	}
}

func TestLoadAppMissingFileUsesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	app, err := LoadApp(path)
	if err != nil {
		t.Fatalf("a missing file must not be an error: %v", err)
	}
	if app.Socks5Listen != DefaultSocksListen {
		t.Fatalf("expected the default listen address, got %s", app.Socks5Listen)
	}
	if !app.AutoStart {
		t.Fatal("auto_start should default to on")
	}
}

func TestLoadAppRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(path, []byte(`{"config":"C:\\x.conf","mystery_field":1}`), 0o600)
	if _, err := LoadApp(path); err == nil {
		t.Fatal("an unknown field was accepted")
	}
}

func TestLoadAppRejectsPublicListen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(path, []byte(`{"config":"C:\\x.conf","socks5_listen":"0.0.0.0:10808"}`), 0o600)
	_, err := LoadApp(path)
	if err == nil {
		t.Fatal("a 0.0.0.0 listen address was accepted")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected a clear loopback error: %v", err)
	}
}

func TestAppSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	app := DefaultApp()
	app.ConfigPath = filepath.Join(dir, "client.conf")
	app.LogLevel = "debug"
	app.MaxConnections = 256
	if err := app.Normalize(); err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if err := app.Save(path); err != nil {
		t.Fatalf("could not save: %v", err)
	}

	loaded, err := LoadApp(path)
	if err != nil {
		t.Fatalf("could not load: %v", err)
	}
	if loaded.LogLevel != "debug" || loaded.MaxConnections != 256 {
		t.Fatalf("the values were not preserved: %+v", loaded)
	}
	if loaded.ConfigPath != app.ConfigPath {
		t.Fatalf("the config path was not preserved: %s", loaded.ConfigPath)
	}
}

func TestAppConfigNeverStoresKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	app := DefaultApp()
	app.ConfigPath = filepath.Join(dir, "client.conf")
	if err := app.Save(path); err != nil {
		t.Fatalf("could not save: %v", err)
	}
	raw, _ := os.ReadFile(path)
	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{"privatekey", "private_key", "presharedkey", "preshared_key"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("config.json must contain no key material, found %q", forbidden)
		}
	}
}

func TestUDPBindValidation(t *testing.T) {
	app := DefaultApp()
	if app.UDPBind != DefaultUDPBind {
		t.Fatalf("udp_bind should default to %q, got %q", DefaultUDPBind, app.UDPBind)
	}
	for _, v := range []string{"std", "rio", "STD", "RIO", ""} {
		a := DefaultApp()
		a.UDPBind = v
		if err := a.Normalize(); err != nil {
			t.Errorf("udp_bind %q should have been accepted: %v", v, err)
		}
	}
	for _, v := range []string{"iocp", "wintun", "auto"} {
		a := DefaultApp()
		a.UDPBind = v
		if err := a.Normalize(); err == nil {
			t.Errorf("udp_bind %q should have been rejected", v)
		}
	}
}

// TestLoadAppAcceptsBOM covers the common Windows case: Notepad and Windows
// PowerShell write UTF-8 files with a byte order mark, and encoding/json
// refuses to parse one.
func TestLoadAppAcceptsBOM(t *testing.T) {
	// Forward slashes avoid backslash escaping in JSON; Normalize turns the
	// path into an absolute Windows one anyway.
	body := `{"config":"C:/ProgramData/AWGSocks/client.conf","socks5_listen":"127.0.0.1:10808","udp_bind":"rio"}`

	cases := map[string][]byte{
		"utf8-bom": append([]byte{0xEF, 0xBB, 0xBF}, body...),
		"utf16-le": utf16LE(body),
		"plain":    []byte(body),
	}
	for name, raw := range cases {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatalf("%s: could not write: %v", name, err)
		}
		app, err := LoadApp(path)
		if err != nil {
			t.Errorf("%s: could not load: %v", name, err)
			continue
		}
		if app.UDPBind != "rio" || app.Socks5Listen != "127.0.0.1:10808" {
			t.Errorf("%s: wrong values: %+v", name, app)
		}
	}
}

func utf16LE(s string) []byte {
	out := []byte{0xFF, 0xFE}
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}
