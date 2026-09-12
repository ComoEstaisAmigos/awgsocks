// Package winsys holds the Windows-specific helpers AWGSocks needs: privilege
// checks, filesystem ACLs and network-change notifications.
//
// The directory is named winsys rather than windows so that it does not shadow
// golang.org/x/sys/windows inside this repository.
package winsys

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// secureSDDL grants full access to LocalSystem (SY) and the local
// Administrators group (BA) only, with inheritance disabled (P) so that a
// permissive ACL on ProgramData cannot widen it. Standard users, including the
// interactive user, get no access at all.
const secureSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// readableSDDL is secureSDDL plus read access for the local Users group, for a
// file that holds no secret and that its owner has a reason to look at.
//
// It is deliberately read only. The directory stays closed, so this grants no
// way to add, replace or delete anything there, and the file itself cannot be
// written. That matters because config.json names the .conf the LocalSystem
// service loads: being able to rewrite it would let a standard user redirect
// what that service runs, which is a privilege boundary even though AWGSocks
// never executes anything out of a configuration file.
//
// Windows grants "bypass traverse checking" to everyone by default, so a file
// carrying this DACL can be opened by its full path even though the directory
// around it refuses to be listed.
const readableSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"

// ErrNotElevated is returned by operations that require Administrator rights.
var ErrNotElevated = errors.New("this operation requires Administrator privileges")

// IsElevated reports whether the current process runs with an elevated token.
func IsElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

// RequireElevation returns ErrNotElevated when the process is not elevated.
func RequireElevation(action string) error {
	if IsElevated() {
		return nil
	}
	return fmt.Errorf("%s: %w", action, ErrNotElevated)
}

// EnsureDir creates a directory if needed and locks its ACL down to
// SYSTEM and Administrators.
func EnsureDir(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("could not create %s: %w", path, err)
	}
	return Protect(path)
}

// Protect replaces the DACL of path with the AWGSocks secure DACL. It is used
// for the data directory, the tunnel configuration and the log directory, so
// that a private key on disk is not world-readable.
func Protect(path string) error {
	return applyDACL(path, secureSDDL)
}

// applyDACL replaces the DACL of path with sddl and disables inheritance, so
// that a permissive ACL higher up cannot widen it.
func applyDACL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("could not build the security descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("could not read the DACL: %w", err)
	}
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
	if err != nil {
		return fmt.Errorf("could not apply the ACL to %s: %w", path, err)
	}
	return nil
}

// ProtectUserReadable locks a file down to SYSTEM and Administrators for
// writing, while letting any local user read it.
//
// Use it only for files with nothing sensitive in them. client.conf holds the
// private key and the log files hold every destination reached at debug level,
// so both keep the stricter Protect.
func ProtectUserReadable(path string) error {
	return applyDACL(path, readableSDDL)
}

// ProtectTree secures a directory and every file directly inside it.
func ProtectTree(dir string) error {
	if err := Protect(dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil // an unreadable directory already has a restrictive ACL
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := Protect(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// DescribePermissions returns a human-readable summary of what AWGSocks locks
// down, for use in documentation output.
func DescribePermissions() string {
	return "full access for SYSTEM and Administrators, inheritance disabled (" + secureSDDL + ")"
}
