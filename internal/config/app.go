package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// Default locations and values for the application configuration.
const (
	DefaultRootDir      = `C:\ProgramData\AWGSocks`
	DefaultAppFileName  = "config.json"
	DefaultConfFileName = "client.conf"
	DefaultSocksListen  = "127.0.0.1:10808"
	DefaultLogLevel     = "info"
	DefaultUDPBind      = "std"
)

// App is the AWGSocks application configuration, stored as config.json next to
// the tunnel configuration. It deliberately holds no key material: the
// AmneziaWG .conf remains the single source of truth for tunnel parameters.
type App struct {
	// ConfigPath is the absolute path of the AmneziaWG .conf file.
	ConfigPath string `json:"config"`

	// Socks5Listen is the SOCKS5 listen address. It must be a loopback address.
	Socks5Listen string `json:"socks5_listen"`

	// AutoStart controls whether the tunnel is brought up when the service
	// starts. When false the tunnel stays down until `awgsocks reconnect`.
	AutoStart bool `json:"auto_start"`

	// LogLevel is one of debug, info, warn, error.
	LogLevel string `json:"log_level"`

	// MaxConnections caps simultaneous SOCKS5 sessions. Zero means the default.
	MaxConnections int `json:"max_connections,omitempty"`

	// LogMaxSizeMB is the log rotation threshold in megabytes. Zero uses 8.
	LogMaxSizeMB int `json:"log_max_size_mb,omitempty"`

	// LogMaxFiles is how many rotated log files to keep. Zero uses 5.
	LogMaxFiles int `json:"log_max_files,omitempty"`

	// UDPAssociate enables SOCKS5 UDP ASSOCIATE, which lets clients send UDP
	// through the tunnel. Defaults to true.
	//
	// It is a pointer so that an absent field keeps the default while an
	// explicit false is honoured.
	UDPAssociate *bool `json:"udp_associate,omitempty"`

	// UDPBind selects which upstream amneziawg-go UDP bind carries the
	// AmneziaWG endpoint traffic: "std" (default) or "rio". See
	// internal/awg/bind.go for the trade-off.
	UDPBind string `json:"udp_bind,omitempty"`

	// path records where this configuration was loaded from.
	path string
}

// RootDir returns the AWGSocks data directory, honouring the AWGSOCKS_ROOT
// environment variable for tests and portable installs.
func RootDir() string {
	if v := strings.TrimSpace(os.Getenv("AWGSOCKS_ROOT")); v != "" {
		return v
	}
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "AWGSocks")
	}
	return DefaultRootDir
}

// AppConfigPath returns the default config.json location.
func AppConfigPath() string { return filepath.Join(RootDir(), DefaultAppFileName) }

// TunnelConfigPath returns the default client.conf location.
func TunnelConfigPath() string { return filepath.Join(RootDir(), DefaultConfFileName) }

// LogDir returns the log directory.
func LogDir() string { return filepath.Join(RootDir(), "logs") }

// DefaultApp returns an App populated with the documented defaults.
func DefaultApp() *App {
	return &App{
		ConfigPath:   TunnelConfigPath(),
		Socks5Listen: DefaultSocksListen,
		AutoStart:    true,
		LogLevel:     DefaultLogLevel,
		UDPBind:      DefaultUDPBind,
		UDPAssociate: boolPtr(true),
	}
}

// LoadApp reads config.json. A missing file is not an error: the documented
// defaults are returned so that a fresh installation works without one.
func LoadApp(path string) (*App, error) {
	if path == "" {
		path = AppConfigPath()
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	raw, err := os.ReadFile(abs)
	if errors.Is(err, os.ErrNotExist) {
		app := DefaultApp()
		app.path = abs
		if err := app.Normalize(); err != nil {
			return nil, err
		}
		return app, nil
	}
	if err != nil {
		return nil, fmt.Errorf("could not read the application configuration: %w", err)
	}

	app := DefaultApp()
	// Notepad and Windows PowerShell write a BOM at the start of UTF-8 files
	// and encoding/json refuses one. The same decoder as the .conf reader is
	// used here, so a file saved as UTF-16 is also accepted.
	dec := json.NewDecoder(strings.NewReader(decodeText(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(app); err != nil {
		return nil, fmt.Errorf("could not parse %s: %w", abs, err)
	}
	app.path = abs
	if err := app.Normalize(); err != nil {
		return nil, err
	}
	return app, nil
}

// Normalize validates the application configuration and fills in defaults.
func (a *App) Normalize() error {
	if strings.TrimSpace(a.ConfigPath) == "" {
		a.ConfigPath = TunnelConfigPath()
	}
	abs, err := filepath.Abs(a.ConfigPath)
	if err != nil {
		return fmt.Errorf("invalid config path %q: %w", a.ConfigPath, err)
	}
	a.ConfigPath = abs

	if strings.TrimSpace(a.Socks5Listen) == "" {
		a.Socks5Listen = DefaultSocksListen
	}
	if err := ValidateLoopbackListen(a.Socks5Listen); err != nil {
		return err
	}

	if strings.TrimSpace(a.LogLevel) == "" {
		a.LogLevel = DefaultLogLevel
	}
	switch strings.ToLower(a.LogLevel) {
	case "debug", "info", "warn", "warning", "error":
	default:
		return fmt.Errorf("invalid log_level %q (debug|info|warn|error)", a.LogLevel)
	}

	if a.UDPAssociate == nil {
		a.UDPAssociate = boolPtr(true)
	}

	switch strings.ToLower(strings.TrimSpace(a.UDPBind)) {
	case "":
		a.UDPBind = DefaultUDPBind
	case "std", "rio":
		a.UDPBind = strings.ToLower(strings.TrimSpace(a.UDPBind))
	default:
		return fmt.Errorf("invalid udp_bind %q (std|rio)", a.UDPBind)
	}

	if a.MaxConnections < 0 {
		return fmt.Errorf("max_connections must not be negative: %d", a.MaxConnections)
	}
	if a.LogMaxSizeMB < 0 || a.LogMaxFiles < 0 {
		return errors.New("log_max_size_mb and log_max_files must not be negative")
	}
	return nil
}

// Path reports where this configuration was loaded from or will be saved to.
func (a *App) Path() string {
	if a.path == "" {
		return AppConfigPath()
	}
	return a.path
}

// Save writes the configuration as indented JSON, creating parent directories.
func (a *App) Save(path string) error {
	if path == "" {
		path = a.Path()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("could not create the directory: %w", err)
	}
	raw, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return fmt.Errorf("could not write the file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("could not rename the temporary file: %w", err)
	}
	a.path = path
	return nil
}

// ValidateLoopbackListen enforces the hard requirement that the SOCKS5 proxy is
// reachable only from the local machine. Binding 0.0.0.0, ::, a LAN address or
// a public address would expose an unauthenticated VPN egress to the network,
// so it is rejected rather than warned about.
func ValidateLoopbackListen(addr string) error {
	host, port, err := splitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid socks5_listen %q: %v", addr, err)
	}
	if port == 0 {
		return fmt.Errorf("invalid socks5_listen %q: the port must not be zero", addr)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("invalid socks5_listen %q: the host must be an IP address, for example 127.0.0.1:10808", addr)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf(
			"socks5_listen must be a loopback address, %q was rejected. "+
				"The proxy is unauthenticated, so binding 0.0.0.0, :: or a LAN address would expose it", addr)
	}
	return nil
}

// UDPEnabled reports whether SOCKS5 UDP ASSOCIATE should be offered.
func (a *App) UDPEnabled() bool {
	return a.UDPAssociate == nil || *a.UDPAssociate
}

func boolPtr(v bool) *bool { return &v }

func splitHostPort(addr string) (string, uint16, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return "", 0, err
	}
	return ap.Addr().String(), ap.Port(), nil
}
