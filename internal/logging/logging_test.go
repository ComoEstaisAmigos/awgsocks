package logging

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	sampleBase64Key = "YK6ykvX+Ql0uI0NcocLtcl53xfgvWCs1xnfjLkKFEFc="
	sampleHexKey    = "60aeb292f5fe425d2e23435ca1c2ed725e77c5f82f582b35c677e32e42851057"
)

func TestRedactRemovesKeyMaterial(t *testing.T) {
	cases := []string{
		"private_key=" + sampleHexKey,
		"PrivateKey = " + sampleBase64Key,
		"preshared_key=" + sampleHexKey,
		"PresharedKey = " + sampleBase64Key,
		"header_protection_key=" + sampleHexKey,
		"HeaderProtectionKey = " + sampleBase64Key,
		"a key somewhere in a line: " + sampleBase64Key,
		"hex form: " + sampleHexKey,
	}
	for _, c := range cases {
		got := Redact(c)
		if strings.Contains(got, sampleBase64Key) || strings.Contains(got, sampleHexKey) {
			t.Errorf("a key leaked: %q -> %q", c, got)
		}
		if !strings.Contains(got, "[REDACTED]") {
			t.Errorf("no redaction marker: %q -> %q", c, got)
		}
	}
}

func TestRedactKeepsNormalText(t *testing.T) {
	in := "SOCKS5 connection established: 127.0.0.1:10808 -> 93.184.216.34:443"
	if got := Redact(in); got != in {
		t.Fatalf("plain text was altered: %q", got)
	}
}

func TestRedactUAPIDropsSecrets(t *testing.T) {
	uapi := strings.Join([]string{
		"private_key=" + sampleHexKey,
		"listen_port=51820",
		"jc=10",
		"public_key=" + sampleHexKey,
		"preshared_key=" + sampleHexKey,
		"endpoint=1.2.3.4:51820",
		"",
	}, "\n")

	got := RedactUAPI(uapi)
	if strings.Contains(got, "private_key="+sampleHexKey) {
		t.Error("private_key leaked")
	}
	if strings.Contains(got, "preshared_key="+sampleHexKey) {
		t.Error("preshared_key leaked")
	}
	if !strings.Contains(got, "jc=10") || !strings.Contains(got, "endpoint=1.2.3.4:51820") {
		t.Errorf("non-secret lines were not preserved: %q", got)
	}
}

func TestLoggerRedactsEverythingItWrites(t *testing.T) {
	dir := t.TempDir()
	var console bytes.Buffer
	l, err := New(Options{Dir: dir, Level: LevelDebug, Console: &console})
	if err != nil {
		t.Fatalf("could not create the logger: %v", err)
	}
	l.Debugf("UAPI: private_key=%s", sampleHexKey)
	l.Infof("conf: PrivateKey = %s", sampleBase64Key)
	l.Close()

	raw, err := os.ReadFile(filepath.Join(dir, "awgsocks.log"))
	if err != nil {
		t.Fatalf("could not read the log file: %v", err)
	}
	for _, text := range []string{string(raw), console.String()} {
		if strings.Contains(text, sampleHexKey) || strings.Contains(text, sampleBase64Key) {
			t.Fatal("the logger wrote key material")
		}
	}
}

func TestLevelFiltering(t *testing.T) {
	dir := t.TempDir()
	l, err := New(Options{Dir: dir, Level: LevelWarn})
	if err != nil {
		t.Fatalf("could not create the logger: %v", err)
	}
	l.Debugf("should-not-appear-debug")
	l.Infof("should-not-appear-info")
	l.Warnf("should-appear-warn")
	l.Errorf("should-appear-error")
	l.Close()

	raw, _ := os.ReadFile(filepath.Join(dir, "awgsocks.log"))
	text := string(raw)
	if strings.Contains(text, "should-not-appear") {
		t.Error("the level filter did not work")
	}
	if !strings.Contains(text, "should-appear-warn") || !strings.Contains(text, "should-appear-error") {
		t.Error("the WARN and ERROR lines were not written")
	}
}

func TestRotationKeepsFileCountBounded(t *testing.T) {
	dir := t.TempDir()
	l, err := New(Options{Dir: dir, Level: LevelInfo, MaxSizeBytes: 512, MaxFiles: 2})
	if err != nil {
		t.Fatalf("could not create the logger: %v", err)
	}
	for i := 0; i < 400; i++ {
		l.Infof("filler line %d %s", i, strings.Repeat("x", 64))
	}
	l.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("could not read the directory: %v", err)
	}
	count := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".log") {
			count++
		}
	}
	// The active file plus at most MaxFiles rotated ones.
	if count > 3 {
		t.Fatalf("expected at most 3 log files, found %d", count)
	}
	if count < 2 {
		t.Fatalf("no rotation happened, file count %d", count)
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]Level{
		"debug": LevelDebug, "info": LevelInfo, "": LevelInfo,
		"warn": LevelWarn, "warning": LevelWarn, "ERROR": LevelError,
	} {
		got, err := ParseLevel(in)
		if err != nil || got != want {
			t.Errorf("%q: expected %v, got %v (%v)", in, want, got, err)
		}
	}
	if _, err := ParseLevel("nonsense"); err == nil {
		t.Error("an invalid level was accepted")
	}
}

// rotatedFiles counts the archived logs beside the active one.
func rotatedFiles(t *testing.T, dir string) int {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "awgsocks-*.log"))
	if err != nil {
		t.Fatalf("could not list the log directory: %v", err)
	}
	return len(matches)
}

// TestSetRotationTakesEffectOnTheOpenFile covers what a configuration reload
// needs from the logger: new limits must apply to the file that is already
// open. Reopening it would be the easy implementation and the wrong one, since
// the service would lose the handle it is writing through.
func TestSetRotationTakesEffectOnTheOpenFile(t *testing.T) {
	dir := t.TempDir()
	log, err := New(Options{Dir: dir, Level: LevelInfo, MaxSizeBytes: 8 << 20, MaxFiles: 5})
	if err != nil {
		t.Fatalf("could not create the logger: %v", err)
	}
	defer log.Close()

	for i := 0; i < 50; i++ {
		log.Infof("a line written while the threshold is still 8 MiB, number %d", i)
	}
	if n := rotatedFiles(t, dir); n != 0 {
		t.Fatalf("a few kilobytes rotated an 8 MiB log: %d rotated files", n)
	}

	log.SetRotation(1024, 2)
	if size, files := log.Rotation(); size != 1024 || files != 2 {
		t.Fatalf("SetRotation was not recorded: size=%d files=%d", size, files)
	}

	for i := 0; i < 50; i++ {
		log.Infof("a line written after the threshold dropped to 1 KiB, number %d", i)
	}
	if n := rotatedFiles(t, dir); n == 0 {
		t.Fatal("the new 1 KiB threshold was ignored, nothing rotated")
	}
}

// TestSetRotationIgnoresZero pins the contract that lets a caller change one
// limit without knowing the other: zero means "leave this alone", the same way
// zero means "use the default" in New. Treating it as "no limit" would silently
// turn rotation off for anyone who set only log_max_files.
func TestSetRotationIgnoresZero(t *testing.T) {
	log, err := New(Options{MaxSizeBytes: 4096, MaxFiles: 3})
	if err != nil {
		t.Fatalf("could not create the logger: %v", err)
	}
	defer log.Close()

	log.SetRotation(0, 0)
	if size, files := log.Rotation(); size != 4096 || files != 3 {
		t.Fatalf("zero overwrote a limit: size=%d files=%d", size, files)
	}

	log.SetRotation(8192, 0)
	if size, files := log.Rotation(); size != 8192 || files != 3 {
		t.Fatalf("changing one limit disturbed the other: size=%d files=%d", size, files)
	}
}
