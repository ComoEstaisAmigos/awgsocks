package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestDoubleClickHelpListsOnlyScriptsThatExist covers the case that made this
// conditional worth writing: the executable is published on its own, or copied
// out of its folder, and the helper scripts are not beside it. Naming files that
// are not there would send someone looking for something that does not exist.
func TestDoubleClickHelpListsOnlyScriptsThatExist(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"service-install.bat", "service-status.bat"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("@echo off\n"), 0o644); err != nil {
			t.Fatalf("could not create %s: %v", name, err)
		}
	}

	var buf bytes.Buffer
	doubleClickHelp(&buf, dir)
	out := buf.String()

	for _, want := range []string{"service-install.bat", "service-status.bat"} {
		if !strings.Contains(out, want) {
			t.Errorf("%s exists but was not listed:\n%s", want, out)
		}
	}
	for _, absent := range []string{"service-start.bat", "service-stop.bat", "service-uninstall.bat"} {
		if strings.Contains(out, absent) {
			t.Errorf("%s does not exist but was listed:\n%s", absent, out)
		}
	}
	assertHelpIsRunnable(t, out)
}

// TestDoubleClickHelpWithoutScripts checks the executable on its own still says
// something useful rather than pointing at an empty list.
func TestDoubleClickHelpWithoutScripts(t *testing.T) {
	var buf bytes.Buffer
	doubleClickHelp(&buf, t.TempDir())
	out := buf.String()

	if strings.Contains(out, ".bat") {
		t.Errorf("a script was named although none exist:\n%s", out)
	}
	if strings.Contains(out, "sitting next to this file") {
		t.Errorf("the message still points at scripts that are not there:\n%s", out)
	}
	if !strings.Contains(out, "double clicking it does nothing on its own") {
		t.Errorf("the explanation went missing:\n%s", out)
	}
	assertHelpIsRunnable(t, out)
}

// TestDoubleClickHelpKeepsScriptOrder checks the scripts are listed in the order
// someone needs them, install first, rather than in directory order.
func TestDoubleClickHelpKeepsScriptOrder(t *testing.T) {
	dir := t.TempDir()
	for _, s := range helperScripts {
		if err := os.WriteFile(filepath.Join(dir, s.name), []byte("@echo off\n"), 0o644); err != nil {
			t.Fatalf("could not create %s: %v", s.name, err)
		}
	}

	var buf bytes.Buffer
	doubleClickHelp(&buf, dir)
	out := buf.String()

	prev := -1
	for _, s := range helperScripts {
		at := strings.Index(out, s.name)
		if at < 0 {
			t.Fatalf("%s was not listed:\n%s", s.name, out)
		}
		if at < prev {
			t.Fatalf("%s appears out of order:\n%s", s.name, out)
		}
		prev = at
	}
}

// TestHelperScriptsInHandlesMissingDirectory guards the path where the
// executable's location cannot be determined, which must degrade quietly rather
// than panic on a double click.
func TestHelperScriptsInHandlesMissingDirectory(t *testing.T) {
	if got := helperScriptsIn(""); got != nil {
		t.Errorf("an empty directory should list nothing, got %v", got)
	}
	if got := helperScriptsIn(filepath.Join(t.TempDir(), "nope")); len(got) != 0 {
		t.Errorf("a missing directory should list nothing, got %v", got)
	}
}

// TestReleasePackageShipsEveryHelperScript keeps three lists of the same six
// files from drifting apart: the scripts the double click message can name,
// the scripts in windows\, and the scripts scripts\package.ps1 puts in the zip.
//
// Each way they can disagree ships something broken. A script added to
// windows\ but not to the package never reaches anyone; one the package lists
// but the message does not is never mentioned to the person who needs it; and
// one the message names but the zip lacks sends them looking for a file that is
// not there.
func TestReleasePackageShipsEveryHelperScript(t *testing.T) {
	root := filepath.Join("..", "..")

	var named []string
	for _, s := range helperScripts {
		named = append(named, s.name)
	}

	raw, err := os.ReadFile(filepath.Join(root, "scripts", "package.ps1"))
	if err != nil {
		t.Fatalf("could not read scripts/package.ps1: %v", err)
	}
	block := regexp.MustCompile(`(?s)\$scripts = @\((.*?)\)`).FindSubmatch(raw)
	if block == nil {
		t.Fatal("scripts/package.ps1 no longer declares $scripts = @(...), so this check cannot see what it ships")
	}
	var packaged []string
	for _, m := range regexp.MustCompile(`'([^']+)'`).FindAllSubmatch(block[1], -1) {
		packaged = append(packaged, string(m[1]))
	}
	if strings.Join(packaged, ",") != strings.Join(named, ",") {
		t.Errorf("scripts/package.ps1 ships %v but the executable names %v, in that order", packaged, named)
	}

	found, err := filepath.Glob(filepath.Join(root, "windows", "*.bat"))
	if err != nil {
		t.Fatal(err)
	}
	var inTree []string
	for _, f := range found {
		inTree = append(inTree, filepath.Base(f))
	}
	want := append([]string(nil), named...)
	sort.Strings(inTree)
	sort.Strings(want)
	if strings.Join(inTree, ",") != strings.Join(want, ",") {
		t.Errorf("windows\\ holds %v but the executable names %v", inTree, want)
	}
}

// assertHelpIsRunnable pins the form of the command the message offers.
//
// A bare awgsocks.exe is not a runnable command everywhere: PowerShell never
// searches the current directory, and cmd stops doing so once
// NoDefaultCurrentDirectoryInExePath is set. Someone who followed the old
// message got "not recognized as the name of a cmdlet" and no way forward.
//
// Checking for a substring is not enough here, because ".\awgsocks.exe --help"
// contains "awgsocks.exe --help" and the weaker assertion passed either way.
// So the line is found and its start is examined.
func assertHelpIsRunnable(t *testing.T, out string) {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "--help") {
			continue
		}
		// The prefix is spelled out rather than taken from selfInvocation.
		// Comparing the message against the same constant it was built from
		// asserts nothing: change the constant and both sides move together,
		// which is exactly how the first version of this test passed while the
		// message was wrong.
		if got := strings.TrimSpace(line); !strings.HasPrefix(got, `.\awgsocks.exe `) {
			t.Errorf("the offered command is not runnable from the current directory: %q", got)
		}
		return
	}
	t.Errorf("the command line fallback was not offered:\n%s", out)
}
