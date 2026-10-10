package service

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/ComoEstaisAmigos/awgsocks/internal/config"
	"github.com/ComoEstaisAmigos/awgsocks/internal/version"
	"github.com/ComoEstaisAmigos/awgsocks/internal/winsys"
)

// serviceDescription is shown in services.msc.
const serviceDescription = "Exposes an AmneziaWG userspace tunnel as a local SOCKS5 proxy only. " +
	"It does not change Windows routing, the default gateway, system DNS or system proxy settings."

// stateWaitTimeout bounds how long control commands wait for a state change.
const stateWaitTimeout = 30 * time.Second

// InstallOptions configures service installation.
type InstallOptions struct {
	// ConfigPath is the AmneziaWG .conf supplied by the operator.
	ConfigPath string
	// InPlace keeps the configuration where it is instead of copying it into
	// the AWGSocks data directory.
	InPlace bool
	// Socks5Listen overrides the default listen address.
	Socks5Listen string
	// LogLevel overrides the default log level.
	LogLevel string
	// AutoStartTunnel controls the auto_start setting written to config.json.
	AutoStartTunnel bool
	// StartService starts the service once installation succeeds.
	StartService bool
	Scripts      []string
}

var programFilesDir = func() (string, error) {
	return windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
}

func programDir() (string, error) {
	pf, err := programFilesDir()
	if err != nil {
		return "", fmt.Errorf("could not locate Program Files: %w", err)
	}
	return filepath.Join(pf, version.ServiceName), nil
}

var requiredPrivileges = []string{"SeChangeNotifyPrivilege"}

func multiSZ(items []string) []uint16 {
	var out []uint16
	for _, s := range items {
		out = append(out, utf16.Encode([]rune(s))...)
		out = append(out, 0)
	}
	return append(out, 0)
}

func restrictPrivileges(s *mgr.Service) error {
	buf := multiSZ(requiredPrivileges)
	info := struct{ privileges *uint16 }{&buf[0]}
	if err := windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
		(*byte)(unsafe.Pointer(&info))); err != nil {
		return fmt.Errorf("could not restrict the service privileges: %w", err)
	}
	return nil
}

// serviceConfig is how the service is registered.
//
// It starts with the other automatic services rather than as a delayed one.
// Delayed start holds a service back until roughly two minutes after boot, and
// for a proxy that is two minutes of every program started at logon, a torrent
// client or a browser configured to use it, being refused. The delay used to
// hide a real defect instead of serving a purpose: a tunnel that could not come
// up for want of a network was never tried again, so waiting for the network
// was the only thing keeping it alive. Manager now retries that start, and
// wakes the retry when an address appears, so the service can open its port at
// once and bring the tunnel up as soon as the network allows.
func serviceConfig() mgr.Config {
	return mgr.Config{
		DisplayName:      version.ServiceDisplayName,
		Description:      serviceDescription,
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: false,
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		ErrorControl:     mgr.ErrorNormal,
		ServiceStartName: winsys.ServiceAccount(version.ServiceName),
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
		// The tunnel is entirely userspace, so nothing beyond networking is
		// required; the Tcpip service is enough for sockets.
		Dependencies: []string{"Tcpip"},
	}
}

// RepairPermissions puts the ACLs under the data directory back the way an
// install leaves them, without touching the service registration, the
// configuration or the tunnel.
//
// It exists because Windows actively invites people to break them. Explorer
// cannot open C:\ProgramData\AWGSocks and offers to "grant permanent access",
// and accepting adds the interactive user to the directory with Full control.
// Full control on a directory carries FILE_DELETE_CHILD, so client.conf and
// config.json can then be replaced whatever their own ACLs say, and the private
// key read along the way. Recovering from one wrong click
// should not mean reinstalling.
func RepairPermissions() error {
	if err := winsys.RequireElevation("repairing the data directory permissions"); err != nil {
		return err
	}
	return repairPermissions(os.Stdout, realACLs())
}

// aclOps is the set of ACL calls repairPermissions makes, injected so that a
// test can assert which path receives which treatment. Getting that routing
// wrong is the failure that matters: handing client.conf the readable DACL
// would publish a private key, and handing config.json the strict one would
// put back the friction this all exists to remove.
type aclOps struct {
	dataDir    func(string) error
	logDir     func(string) error
	secret     func(string) error
	readable   func(string) error
	programDir func(string) error
	program    func(string) error
	protect    func(string) error
}

func realACLs() aclOps {
	sid := winsys.ServiceSID(version.ServiceName)
	return aclOps{
		dataDir:    func(p string) error { return winsys.EnsureDataDir(p, sid) },
		logDir:     func(p string) error { return winsys.EnsureLogDir(p, sid) },
		secret:     func(p string) error { return winsys.ProtectSecret(p, sid) },
		readable:   func(p string) error { return winsys.ProtectUserReadable(p, sid) },
		programDir: func(p string) error { return winsys.EnsureProgramDir(p, sid) },
		program:    func(p string) error { return winsys.ProtectProgram(p, sid) },
		protect:    winsys.Protect,
	}
}

func repairPermissions(w io.Writer, acl aclOps) error {
	root := config.RootDir()
	if _, err := os.Stat(root); err != nil {
		return fmt.Errorf("%s does not exist, so there is nothing to repair: %w", root, err)
	}

	// Directories first: closing the parent is what removes the escalation
	// path, and every file below is then secured on its own terms.
	if err := acl.dataDir(root); err != nil {
		return err
	}
	fmt.Fprintf(w, "  %-52s SYSTEM and Administrators, read for the service\n", root)
	if _, err := os.Stat(config.LogDir()); err == nil {
		if err := acl.logDir(config.LogDir()); err != nil {
			return err
		}
		fmt.Fprintf(w, "  %-52s SYSTEM and Administrators, modify for the service\n", config.LogDir())
	}

	// The tunnel configuration is read from config.json rather than assumed,
	// because an --in-place install leaves it outside the data directory.
	if app, err := config.LoadApp(""); err == nil && app.ConfigPath != "" {
		if _, serr := os.Stat(app.ConfigPath); serr == nil {
			if err := acl.secret(app.ConfigPath); err != nil {
				return err
			}
			fmt.Fprintf(w, "  %-52s SYSTEM and Administrators, read for the service (holds the private key)\n", app.ConfigPath)
		}
	}

	legacy := filepath.Join(root, "awgsocks.exe")
	if _, err := os.Stat(legacy); err == nil {
		if err := acl.protect(legacy); err != nil {
			return err
		}
		fmt.Fprintf(w, "  %-52s SYSTEM and Administrators only (left by an older version)\n", legacy)
	}

	appPath := config.AppConfigPath()
	if _, err := os.Stat(appPath); err == nil {
		if err := acl.readable(appPath); err != nil {
			return err
		}
		fmt.Fprintf(w, "  %-52s readable by any local user, writable by admins\n", appPath)
	}

	if dir, err := programDir(); err == nil {
		if entries, rerr := os.ReadDir(dir); rerr == nil {
			if err := acl.programDir(dir); err != nil {
				return err
			}
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				if err := acl.program(filepath.Join(dir, e.Name())); err != nil {
					return err
				}
			}
			fmt.Fprintf(w, "  %-52s readable and runnable by any user, writable by admins\n", dir)
		}
	}

	fmt.Fprintln(w, "\nPermissions repaired. Nothing else was changed.")
	return nil
}

// Install creates the data directories, stores the configuration, applies
// restrictive ACLs and registers the Windows service.
func Install(opts InstallOptions) error {
	if err := winsys.RequireElevation("installing the service"); err != nil {
		return err
	}
	if strings.TrimSpace(opts.ConfigPath) == "" {
		return errors.New("--config must name the AmneziaWG configuration file")
	}

	srcPath, err := filepath.Abs(opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("invalid configuration path: %w", err)
	}
	// Verify the configuration is valid before touching anything.
	tunCfg, err := config.LoadTunnel(srcPath)
	if err != nil {
		return fmt.Errorf("the configuration is invalid, nothing was installed: %w", err)
	}

	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("could not connect to the service control manager: %w", err)
	}
	defer scm.Disconnect()
	if s, err := scm.OpenService(version.ServiceName); err == nil {
		s.Close()
		return fmt.Errorf("the %s service is already installed: run `awgsocks uninstall` first", version.ServiceName)
	}

	progDir, err := programDir()
	if err != nil {
		return err
	}
	sid := winsys.ServiceSID(version.ServiceName)
	root := config.RootDir()
	if err := winsys.EnsureDataDir(root, sid); err != nil {
		return err
	}
	if err := winsys.EnsureLogDir(config.LogDir(), sid); err != nil {
		return err
	}

	destPath := srcPath
	if !opts.InPlace {
		destPath = config.TunnelConfigPath()
		if !strings.EqualFold(srcPath, destPath) {
			if err := copyFile(srcPath, destPath); err != nil {
				return fmt.Errorf("could not copy the configuration: %w", err)
			}
			fmt.Printf("Configuration copied: %s -> %s\n", srcPath, destPath)
		}
	}
	if err := winsys.ProtectSecret(destPath, sid); err != nil {
		return err
	}

	appPath := config.AppConfigPath()
	app, kept, err := installApp(appPath, destPath, opts)
	if err != nil {
		return err
	}
	if err := app.Save(appPath); err != nil {
		return err
	}
	// config.json holds no key material, and being unable to read your own
	// proxy settings without elevation is friction with nothing behind it. It
	// is therefore readable by any local user and writable only by SYSTEM and
	// Administrators. The directory around it stays closed either way, so this
	// opens no path to replacing the service binary.
	if err := winsys.ProtectUserReadable(appPath, sid); err != nil {
		return err
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not determine the executable path: %w", err)
	}
	exePath, _ = filepath.Abs(exePath)

	// A service must not be launched from a directory that a standard user can
	// write to: anyone able to replace the file would get code execution as
	// the service account. The binary and the scripts are therefore copied into
	// Program Files, which any user may read and run but only Administrators
	// may change, and the service is registered against that copy.
	servicePath, err := installProgram(exePath, progDir, opts.Scripts, sid)
	if err != nil {
		return err
	}
	removeLegacyBinary(root)

	s, err := scm.CreateService(version.ServiceName, servicePath, serviceConfig(), "service")
	if err != nil {
		return fmt.Errorf("could not create the service: %w", err)
	}
	defer s.Close()
	if err := restrictPrivileges(s); err != nil {
		s.Delete()
		return fmt.Errorf("%w, so the service was not installed", err)
	}

	// Let the SCM restart the service after an unexpected exit.
	recovery := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}
	if err := s.SetRecoveryActions(recovery, 86400); err != nil {
		fmt.Printf("Warning: could not set the recovery actions: %v\n", err)
	}

	fmt.Printf("The %s service has been installed.\n", version.ServiceName)
	fmt.Printf("  Service binary : %s\n", servicePath)
	fmt.Printf("  Scripts        : %s\n", progDir)
	fmt.Printf("  Service account: %s, privileges limited to %s\n",
		winsys.ServiceAccount(version.ServiceName), strings.Join(requiredPrivileges, ", "))
	fmt.Printf("  Configuration  : %s\n", destPath)
	if kept {
		fmt.Printf("  Settings       : kept from the existing %s\n", appPath)
	} else {
		fmt.Printf("  Settings       : %s written with the defaults\n", appPath)
	}
	fmt.Printf("  App settings   : %s\n", appPath)
	fmt.Printf("  Logs           : %s\n", config.LogDir())
	fmt.Printf("  SOCKS5         : %s\n", app.Socks5Listen)
	fmt.Printf("  Permissions    : %s\n", winsys.DescribePermissions())
	fmt.Printf("  AmneziaWG      : %s (%s)\n", version.AmneziaWGGoVersion, tunCfg.Generation)
	fmt.Printf("  Wintun         : %s\n", version.WintunStatus)

	if !opts.StartService {
		// The service is installed but not started. Without saying so plainly,
		// the only thing the user sees is the browser reporting that the proxy
		// refuses connections, with no clue why.
		fmt.Println()
		fmt.Println("The service is NOT RUNNING YET, so nothing is listening on the SOCKS5 port.")
		fmt.Printf("To start it:    awgsocks start   (or pass --start when installing)\n")
		return nil
	}

	if err := s.Start(); err != nil {
		return fmt.Errorf("could not start the service: %w", err)
	}
	if err := waitForState(s, svc.Running); err != nil {
		return err
	}
	fmt.Printf("\nService started. SOCKS5 is ready on %s\n", app.Socks5Listen)
	return nil
}

// Uninstall stops and removes the service. Unless purge is set, the operator
// AmneziaWG configuration is kept: deleting it is never implicit.
func Uninstall(purge, keepSettings bool) error {
	if purge && keepSettings {
		return errors.New("--purge deletes the settings that --keep-settings is asked to keep, so the two cannot be combined")
	}
	if err := winsys.RequireElevation("removing the service"); err != nil {
		return err
	}

	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("could not connect to the service control manager: %w", err)
	}
	defer scm.Disconnect()

	s, err := scm.OpenService(version.ServiceName)
	if err != nil {
		fmt.Printf("The %s service is not installed.\n", version.ServiceName)
	} else {
		defer s.Close()
		if status, err := s.Query(); err == nil && status.State != svc.Stopped {
			if _, err := s.Control(svc.Stop); err != nil {
				fmt.Printf("Warning: could not stop the service: %v\n", err)
			} else if err := waitForState(s, svc.Stopped); err != nil {
				fmt.Printf("Warning: %v\n", err)
			}
		}
		if err := s.Delete(); err != nil {
			return fmt.Errorf("could not delete the service: %w", err)
		}
		fmt.Printf("The %s service has been removed.\n", version.ServiceName)
	}

	root := config.RootDir()
	confPath := config.TunnelConfigPath()

	removeInstalledData(os.Stdout, keepSettings)
	removeLegacyBinary(root)
	if dir, err := programDir(); err == nil {
		if _, serr := os.Stat(dir); serr == nil {
			fmt.Printf("The program and its scripts were kept: %s\n", dir)
		}
	}

	// AWGSocks never creates a Wintun adapter, so there is none to clean up.
	// This is stated explicitly so that it can be audited.
	fmt.Println("Wintun adapter: never created, nothing to clean up.")
	fmt.Println("Windows routing table: never modified, no route to undo.")

	if purge {
		if err := os.RemoveAll(root); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("could not delete %s: %w", root, err)
		}
		fmt.Printf("The whole data directory was deleted: %s\n", root)
		return nil
	}

	if _, err := os.Stat(confPath); err == nil {
		fmt.Printf("The AmneziaWG configuration was kept: %s\n", confPath)
		fmt.Println("To delete it too: awgsocks uninstall --purge")
	} else {
		// Remove the directory only if it is now empty.
		os.Remove(root)
	}
	return nil
}

func installApp(appPath, destPath string, opts InstallOptions) (app *config.App, kept bool, err error) {
	app = config.DefaultApp()
	if _, serr := os.Stat(appPath); serr == nil {
		if existing, lerr := config.LoadApp(appPath); lerr == nil {
			app, kept = existing, true
		} else {
			fmt.Printf("Warning: the existing settings could not be read, so the defaults are used: %v\n", lerr)
		}
	}
	app.ConfigPath = destPath
	if !opts.AutoStartTunnel {
		app.AutoStart = false
	}
	if opts.Socks5Listen != "" {
		app.Socks5Listen = opts.Socks5Listen
	}
	if opts.LogLevel != "" {
		app.LogLevel = opts.LogLevel
	}
	if err := app.Normalize(); err != nil {
		return nil, false, err
	}
	return app, kept, nil
}

func removeInstalledData(w io.Writer, keepSettings bool) {
	if keepSettings {
		fmt.Fprintf(w, "Settings and logs kept for the next install: %s, %s\n", config.AppConfigPath(), config.LogDir())
		return
	}
	if err := os.RemoveAll(config.LogDir()); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(w, "Warning: could not delete the log directory: %v\n", err)
	} else {
		fmt.Fprintf(w, "Logs deleted: %s\n", config.LogDir())
	}
	if err := os.Remove(config.AppConfigPath()); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(w, "Warning: could not delete config.json: %v\n", err)
	}
}

func installProgram(exePath, dir string, scripts []string, sid string) (string, error) {
	if err := winsys.EnsureProgramDir(dir, sid); err != nil {
		return "", err
	}
	servicePath := filepath.Join(dir, "awgsocks.exe")
	type copyJob struct{ src, dst string }
	jobs := []copyJob{{exePath, servicePath}}
	for _, name := range scripts {
		src := filepath.Join(filepath.Dir(exePath), name)
		if _, err := os.Stat(src); err == nil {
			jobs = append(jobs, copyJob{src, filepath.Join(dir, name)})
		}
	}
	for _, j := range jobs {
		if !strings.EqualFold(filepath.Clean(j.src), filepath.Clean(j.dst)) {
			if err := copyWhenReleased(j.src, j.dst); err != nil {
				return "", fmt.Errorf("could not copy %s into %s: %w", filepath.Base(j.src), dir, err)
			}
			fmt.Printf("Copied: %s -> %s\n", j.src, j.dst)
		}
		if err := winsys.ProtectProgram(j.dst, sid); err != nil {
			return "", err
		}
	}
	return servicePath, nil
}

func copyWhenReleased(src, dst string) error {
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		if err = copyFile(src, dst); err == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return err
}

func removeLegacyBinary(root string) {
	legacy := filepath.Join(root, "awgsocks.exe")
	if _, err := os.Stat(legacy); err != nil {
		return
	}
	if err := os.Remove(legacy); err != nil {
		fmt.Printf("Warning: could not delete %s, left by an older version: %v\n", legacy, err)
		return
	}
	fmt.Printf("Deleted the service binary an older version kept in %s\n", root)
}

// StartService starts the installed service.
func StartService() error {
	return withService("starting the service", func(s *mgr.Service) error {
		status, err := s.Query()
		if err == nil && status.State == svc.Running {
			fmt.Println("The service is already running.")
			return nil
		}
		if err := s.Start(); err != nil {
			return fmt.Errorf("could not start the service: %w", err)
		}
		if err := waitForState(s, svc.Running); err != nil {
			return err
		}
		fmt.Println("Service started.")
		return nil
	})
}

// StopService stops the installed service.
func StopService() error {
	return withService("stopping the service", func(s *mgr.Service) error {
		status, err := s.Query()
		if err == nil && status.State == svc.Stopped {
			fmt.Println("The service is already stopped.")
			return nil
		}
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("could not stop the service: %w", err)
		}
		if err := waitForState(s, svc.Stopped); err != nil {
			return err
		}
		fmt.Println("Service stopped.")
		return nil
	})
}

// RestartService stops and starts the installed service.
func RestartService() error {
	if err := StopService(); err != nil {
		return err
	}
	return StartService()
}

// QueryState returns the SCM state of the service as a word for CLI output,
// such as "running", "stopped" or "not installed".
//
// It opens the service control manager with connect-only rights and the
// service with query-status rights, so that reading the state does not require
// Administrator privileges. mgr.Connect would ask for full control and fail for
// a standard user.
func QueryState() (string, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", fmt.Errorf("could not connect to the service control manager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)

	name, err := windows.UTF16PtrFromString(version.ServiceName)
	if err != nil {
		return "", err
	}
	handle, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return "not installed", nil
	}
	defer windows.CloseServiceHandle(handle)

	s := &mgr.Service{Name: version.ServiceName, Handle: handle}
	status, err := s.Query()
	if err != nil {
		return "", fmt.Errorf("could not read the service state: %w", err)
	}
	return stateName(status.State), nil
}

func withService(action string, fn func(*mgr.Service) error) error {
	if err := winsys.RequireElevation(action); err != nil {
		return err
	}
	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("could not connect to the service control manager: %w", err)
	}
	defer scm.Disconnect()

	s, err := scm.OpenService(version.ServiceName)
	if err != nil {
		return fmt.Errorf("the %s service was not found: run `awgsocks install` first", version.ServiceName)
	}
	defer s.Close()
	return fn(s)
}

func waitForState(s *mgr.Service, want svc.State) error {
	deadline := time.Now().Add(stateWaitTimeout)
	for time.Now().Before(deadline) {
		status, err := s.Query()
		if err != nil {
			return fmt.Errorf("could not read the service state: %w", err)
		}
		if status.State == want {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("the service did not reach the %s state within %s", stateName(want), stateWaitTimeout)
}

func stateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continuing"
	case svc.PausePending:
		return "pausing"
	case svc.Paused:
		return "paused"
	default:
		return "unknown"
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
