package winsys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// wellKnownSIDs are the only two principals AWGSocks' secure DACL may name.
func wellKnownSIDs(t *testing.T) (system, admins string) {
	t.Helper()
	sy, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("could not build the LocalSystem SID: %v", err)
	}
	ba, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatalf("could not build the Administrators SID: %v", err)
	}
	return sy.String(), ba.String()
}

// aclEntry is one allow ACE: who, and what they may do.
type aclEntry struct {
	sid  string
	mask uint32
}

// aclPrincipals lists the SIDs named by the DACL actually in force on path.
func aclPrincipals(t *testing.T, path string) (sids []string, protected bool) {
	t.Helper()
	entries, protected := aclEntries(t, path)
	for _, e := range entries {
		sids = append(sids, e.sid)
	}
	return sids, protected
}

// aclEntries reads back the DACL actually in force, masks included, so a test
// can tell read access from write access rather than only naming principals.
func aclEntries(t *testing.T, path string) (entries []aclEntry, protected bool) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("could not read the security descriptor of %s: %v", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("could not read the DACL of %s: %v", path, err)
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		t.Fatalf("could not read the control bits of %s: %v", path, err)
	}
	protected = ctrl&windows.SE_DACL_PROTECTED != 0

	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatalf("could not read ACE %d of %s: %v", i, path, err)
		}
		entries = append(entries, aclEntry{
			sid:  (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String(),
			mask: uint32(ace.Mask),
		})
	}
	return entries, protected
}

// TestProtectGrantsExactlyTwoPrincipals is a security invariant, not a unit
// test of convenience: the whole reason a LocalSystem service is launched from
// C:\ProgramData\AWGSocks is that nobody but SYSTEM and Administrators can
// write there. An extra allow ACE for a standard user turns that directory
// back into a privilege escalation path, because Full control on a directory
// carries FILE_DELETE_CHILD and lets a file be replaced whatever its own ACL
// says.
func TestProtectGrantsExactlyTwoPrincipals(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "AWGSocks")
	if err := EnsureDir(dir); err != nil {
		t.Fatalf("EnsureDir failed: %v", err)
	}

	system, admins := wellKnownSIDs(t)
	want := map[string]bool{system: true, admins: true}

	got, protected := aclPrincipals(t, dir)
	if !protected {
		t.Error("inheritance is not disabled, a permissive parent ACL would widen this directory")
	}
	if len(got) != len(want) {
		t.Fatalf("the secure DACL names %d principals, expected exactly 2: %v", len(got), got)
	}
	for _, sid := range got {
		if !want[sid] {
			t.Errorf("an unexpected principal is allowed on the protected directory: %s", sid)
		}
	}
}

// TestProtectAppliesToFilesToo covers the file case, which is what keeps
// client.conf, holding the private key, out of reach of the interactive user.
func TestProtectAppliesToFilesToo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.conf")
	if err := os.WriteFile(path, []byte("[Interface]\n"), 0o600); err != nil {
		t.Fatalf("could not create the test file: %v", err)
	}
	if err := Protect(path); err != nil {
		t.Fatalf("Protect failed: %v", err)
	}

	system, admins := wellKnownSIDs(t)
	want := map[string]bool{system: true, admins: true}

	got, protected := aclPrincipals(t, path)
	if !protected {
		t.Error("the file DACL is not protected, so it can inherit a wider ACL")
	}
	for _, sid := range got {
		if !want[sid] {
			t.Errorf("an unexpected principal is allowed on the protected file: %s", sid)
		}
	}
}

// TestDescribePermissionsMatchesWhatIsApplied keeps the string AWGSocks prints
// and documents from drifting away from the DACL it actually sets.
func TestDescribePermissionsMatchesWhatIsApplied(t *testing.T) {
	if got := DescribePermissions(); !strings.Contains(got, secureSDDL) {
		t.Errorf("the documented permissions do not quote the DACL in force:\n got: %s\nwant it to contain: %s", got, secureSDDL)
	}
}

// writeRights are every way a DACL can let somebody change a file or get rid
// of it. The point of ProtectUserReadable is that a standard user holds none
// of them.
const writeRights = windows.FILE_WRITE_DATA |
	windows.FILE_APPEND_DATA |
	windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES |
	windows.DELETE |
	windows.WRITE_DAC |
	windows.WRITE_OWNER

// TestProtectUserReadableLetsUsersReadButNotWrite pins the trade that makes
// config.json readable without elevation.
//
// Reading it is harmless: it holds no key material. Writing it is not, because
// it names the .conf the LocalSystem service loads, so a standard user able to
// rewrite it could redirect what that service brings up. The test therefore
// checks the access mask rather than only the principal list: an ACE for Users
// that quietly carried FILE_WRITE_DATA would pass a name-only check.
func TestProtectUserReadableLetsUsersReadButNotWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("could not create the test file: %v", err)
	}
	if err := ProtectUserReadable(path); err != nil {
		t.Fatalf("ProtectUserReadable failed: %v", err)
	}

	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatalf("could not build the Users SID: %v", err)
	}
	system, admins := wellKnownSIDs(t)

	entries, protected := aclEntries(t, path)
	if !protected {
		t.Error("the DACL is not protected, so it could inherit a wider ACL")
	}

	allowed := map[string]uint32{}
	for _, e := range entries {
		allowed[e.sid] |= e.mask
	}
	for _, want := range []string{system, admins, users.String()} {
		if _, ok := allowed[want]; !ok {
			t.Errorf("%s is not named by the DACL", want)
		}
	}
	if len(allowed) != 3 {
		t.Fatalf("expected exactly SYSTEM, Administrators and Users, got %d principals: %v", len(allowed), entries)
	}

	if got := allowed[users.String()] & writeRights; got != 0 {
		t.Errorf("Users hold write rights on config.json (mask bits %#x), which would let a standard user "+
			"redirect the configuration a LocalSystem service loads", got)
	}
	if allowed[users.String()]&windows.FILE_READ_DATA == 0 {
		t.Error("Users cannot read config.json, which is the whole point of this DACL")
	}
}

// TestStrictProtectGrantsUsersNothing guards the other side of the split: the
// files that do hold secrets must not pick up the readable DACL by mistake.
// client.conf carries the private key and the logs carry every destination
// reached once log_level is debug.
func TestStrictProtectGrantsUsersNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.conf")
	if err := os.WriteFile(path, []byte("[Interface]\n"), 0o600); err != nil {
		t.Fatalf("could not create the test file: %v", err)
	}
	if err := Protect(path); err != nil {
		t.Fatalf("Protect failed: %v", err)
	}

	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatalf("could not build the Users SID: %v", err)
	}
	entries, _ := aclEntries(t, path)
	for _, e := range entries {
		if e.sid == users.String() {
			t.Fatalf("the strict DACL names Users, so a file holding a private key would be readable: %+v", e)
		}
	}
}
