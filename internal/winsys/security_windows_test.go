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
// test of convenience: the whole reason the private key is kept in
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
	got := DescribePermissions()
	for _, want := range []string{"SYSTEM and Administrators", "read for the service account", "logs: modify", "writable by Administrators only"} {
		if !strings.Contains(got, want) {
			t.Errorf("the printed permissions do not mention %q:\n%s", want, got)
		}
	}
}

const fileDeleteChild = 0x40

func principalMasks(t *testing.T, path string) map[string]uint32 {
	t.Helper()
	entries, protected := aclEntries(t, path)
	if !protected {
		t.Errorf("the DACL of %s is not protected, so it could inherit a wider ACL", path)
	}
	masks := map[string]uint32{}
	for _, e := range entries {
		masks[e.sid] |= e.mask
	}
	return masks
}

func expectPrincipals(t *testing.T, what string, masks map[string]uint32, want ...string) {
	t.Helper()
	if len(masks) != len(want) {
		t.Errorf("%s names %d principals, expected %d: %v", what, len(masks), len(want), masks)
	}
	for _, sid := range want {
		if _, ok := masks[sid]; !ok {
			t.Errorf("%s does not name %s", what, sid)
		}
	}
}

func TestServiceAccountCanOnlyReadItsData(t *testing.T) {
	svc := ServiceSID("AWGSocks")
	system, admins := wellKnownSIDs(t)
	dir := filepath.Join(t.TempDir(), "AWGSocks")
	if err := EnsureDataDir(dir, svc); err != nil {
		t.Fatalf("EnsureDataDir failed: %v", err)
	}
	masks := principalMasks(t, dir)
	expectPrincipals(t, "the data directory", masks, system, admins, svc)
	if got := masks[svc] & (writeRights | fileDeleteChild); got != 0 {
		t.Errorf("the service account can change the data directory (mask bits %#x)", got)
	}

	conf := filepath.Join(dir, "client.conf")
	if err := os.WriteFile(conf, []byte("[Interface]\n"), 0o600); err != nil {
		t.Fatalf("could not create the test file: %v", err)
	}
	if err := ProtectSecret(conf, svc); err != nil {
		t.Fatalf("ProtectSecret failed: %v", err)
	}
	masks = principalMasks(t, conf)
	expectPrincipals(t, "client.conf", masks, system, admins, svc)
	if masks[svc]&windows.FILE_READ_DATA == 0 {
		t.Error("the service account cannot read client.conf, so the tunnel could never start")
	}
	if got := masks[svc] & writeRights; got != 0 {
		t.Errorf("the service account can change client.conf (mask bits %#x)", got)
	}
}

func TestServiceAccountCanWriteOnlyItsLogs(t *testing.T) {
	svc := ServiceSID("AWGSocks")
	system, admins := wellKnownSIDs(t)
	dir := filepath.Join(t.TempDir(), "logs")
	if err := EnsureLogDir(dir, svc); err != nil {
		t.Fatalf("EnsureLogDir failed: %v", err)
	}
	masks := principalMasks(t, dir)
	expectPrincipals(t, "the log directory", masks, system, admins, svc)
	if masks[svc]&windows.FILE_WRITE_DATA == 0 || masks[svc]&windows.DELETE == 0 {
		t.Error("the service account cannot create and rotate its log files")
	}
	if got := masks[svc] & (windows.WRITE_DAC | windows.WRITE_OWNER); got != 0 {
		t.Errorf("the service account can change who may read the logs (mask bits %#x)", got)
	}
}

func TestProgramFilesAreRunnableButNotWritable(t *testing.T) {
	svc := ServiceSID("AWGSocks")
	system, admins := wellKnownSIDs(t)
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatalf("could not build the Users SID: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "AWGSocks")
	if err := EnsureProgramDir(dir, svc); err != nil {
		t.Fatalf("EnsureProgramDir failed: %v", err)
	}
	exe := filepath.Join(dir, "awgsocks.exe")
	if err := os.WriteFile(exe, []byte("MZ"), 0o600); err != nil {
		t.Fatalf("could not create the test file: %v", err)
	}
	if err := ProtectProgram(exe, svc); err != nil {
		t.Fatalf("ProtectProgram failed: %v", err)
	}
	for _, path := range []string{dir, exe} {
		masks := principalMasks(t, path)
		expectPrincipals(t, path, masks, system, admins, users.String(), svc)
		for _, who := range []string{users.String(), svc} {
			if got := masks[who] & (writeRights | fileDeleteChild); got != 0 {
				t.Errorf("%s can change %s (mask bits %#x), which would let it replace what the service runs", who, path, got)
			}
			if masks[who]&windows.FILE_EXECUTE == 0 || masks[who]&windows.FILE_READ_DATA == 0 {
				t.Errorf("%s cannot read and run %s", who, path)
			}
		}
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
// it names the .conf the service loads, so a standard user able to
// rewrite it could redirect what that service brings up. The test therefore
// checks the access mask rather than only the principal list: an ACE for Users
// that quietly carried FILE_WRITE_DATA would pass a name-only check.
func TestProtectUserReadableLetsUsersReadButNotWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("could not create the test file: %v", err)
	}
	svc := ServiceSID("AWGSocks")
	if err := ProtectUserReadable(path, svc); err != nil {
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
	for _, want := range []string{system, admins, users.String(), svc} {
		if _, ok := allowed[want]; !ok {
			t.Errorf("%s is not named by the DACL", want)
		}
	}
	if len(allowed) != 4 {
		t.Fatalf("expected exactly SYSTEM, Administrators, Users and the service, got %d principals: %v", len(allowed), entries)
	}
	if got := allowed[svc] & writeRights; got != 0 {
		t.Errorf("the service account can write config.json (mask bits %#x)", got)
	}

	if got := allowed[users.String()] & writeRights; got != 0 {
		t.Errorf("Users hold write rights on config.json (mask bits %#x), which would let a standard user "+
			"redirect the configuration the service loads", got)
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
