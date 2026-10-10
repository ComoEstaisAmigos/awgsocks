package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ComoEstaisAmigos/awgsocks/internal/ipc"
)

func TestDoubleClickHelpNamesNoScripts(t *testing.T) {
	var buf bytes.Buffer
	doubleClickHelp(&buf)
	out := buf.String()

	want := "awgsocks.exe: This is a command line program, so double clicking it does nothing on its own.\n\n" +
		"To drive it by hand, open an Administrator prompt in this folder\nand run:\n\n  .\\awgsocks.exe --help\n\n"
	if out != want {
		t.Errorf("unexpected double click message:\n%s", out)
	}
	if strings.Contains(out, ".bat") {
		t.Errorf("the message names a script, which may be missing or differ from what is beside it:\n%s", out)
	}
	assertHelpIsRunnable(t, out)
}

// TestReleasePackageShipsEveryHelperScript keeps three lists of the same six
// files from drifting apart: the scripts install copies to Program Files,
// the scripts in windows\, and the scripts scripts\package.ps1 puts in the zip.
//
// Each way they can disagree ships something broken. A script added to
// windows\ but not to the package never reaches anyone; one the package lists
// but install does not copy never reaches Program Files; and one install
// copies but the zip lacks is silently missing from every installation it
// makes.
func TestReleasePackageShipsEveryHelperScript(t *testing.T) {
	root := filepath.Join("..", "..")

	named := helperScripts

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
		t.Errorf("scripts/package.ps1 ships %v but install copies %v, in that order", packaged, named)
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
		t.Errorf("windows\\ holds %v but install copies %v", inTree, want)
	}
}

// TestServiceScriptsReadThePauseFieldTheServiceSends ties the scripts to the
// JSON they parse. service-start.bat and service-install.bat read
// tunnel.paused_by out of `awgsocks status --json` to tell a paused tunnel from
// a working one, and a renamed field would not break them loudly: they would
// quietly go back to announcing that the proxy is accepting connections while
// it refuses every request.
func TestServiceScriptsReadThePauseFieldTheServiceSends(t *testing.T) {
	jsonName := func(typ reflect.Type, field string) string {
		f, ok := typ.FieldByName(field)
		if !ok {
			t.Fatalf("%s has no field %s", typ, field)
		}
		return strings.Split(f.Tag.Get("json"), ",")[0]
	}
	want := "$s." + jsonName(reflect.TypeOf(ipc.Status{}), "Tunnel") + "." +
		jsonName(reflect.TypeOf(ipc.TunnelStatus{}), "PausedBy")

	for _, script := range []string{"service-start.bat", "service-install.bat"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "windows", script))
		if err != nil {
			t.Fatalf("could not read %s: %v", script, err)
		}
		if !strings.Contains(string(raw), want) {
			t.Errorf("%s does not read %s, the field the service sends for a paused tunnel", script, want)
		}
	}
}

func TestControlScriptsHandOverToTheInstalledCopy(t *testing.T) {
	read := func(script string) string {
		raw, err := os.ReadFile(filepath.Join("..", "..", "windows", script))
		if err != nil {
			t.Fatalf("could not read %s: %v", script, err)
		}
		return string(raw)
	}
	for _, script := range []string{"service-start.bat", "service-stop.bat", "service-status.bat", "service-config.bat", "service-uninstall.bat"} {
		body := read(script)
		for _, want := range []string{`Services\AWGSocks" /v ImagePath`, "call :SERVICE_DIR", "AWGSOCKS_FORWARDED", ":FORWARD", `call "%SVCDIR%%~nx0"`} {
			if !strings.Contains(body, want) {
				t.Errorf("%s does not hand over to the installed copy: %q is missing", script, want)
			}
		}
		if strings.Index(body, "goto :FORWARD") > strings.Index(body, "net session") {
			t.Errorf("%s asks for elevation before handing over, so the installed copy would not be the one elevated", script)
		}
		if !strings.Contains(body, `if not exist "%AWGSOCKS%" if defined SVCDIR set "AWGSOCKS=%SVCDIR%awgsocks.exe"`) {
			t.Errorf("%s does not fall back to the installed awgsocks.exe", script)
		}
		installed := "sc query AWGSocks"
		if script == "service-config.bat" {
			installed = `if not exist "%CONFIG%"`
		}
		if i := strings.Index(body, installed); i < 0 || i > strings.Index(body, "was not found next to this script") {
			t.Errorf("%s reports a missing awgsocks.exe before checking whether the service is installed", script)
		}
		if strings.Contains(body, "%ProgramFiles%\\AWGSocks\\%~nx0") {
			t.Errorf("%s finds the installed copy through an environment variable a user can set", script)
		}
	}
	install := read("service-install.bat")
	if i := strings.Index(install, "call :CONFIRM_REPLACE"); i < 0 || i > strings.Index(install, "call :PICK_CONF") || !strings.Contains(install, "Type y to continue") {
		t.Error("service-install.bat does not ask before replacing an installed service, or asks only after the .conf was picked")
	}
	if !strings.Contains(install, "uninstall --keep-settings") {
		t.Error("service-install.bat removes the installed service without keeping its settings")
	}
	if strings.Contains(install, "uninstall --keep-settings >nul") || !strings.Contains(install, "if defined REMOVE_FAILED goto :FAIL") {
		t.Error("service-install.bat hides whether removing the installed service worked, so a failure surfaces as a confusing install error")
	}
	if strings.Contains(install, "--socks %SOCKS%") {
		t.Error("service-install.bat overrides the kept socks5_listen on every install")
	}
	if strings.Contains(install, ":FORWARD") {
		t.Error("service-install.bat hands over to the installed copy, so it could never install a newer version")
	}
}

func TestServiceScriptsStayConsistent(t *testing.T) {
	for _, script := range helperScripts {
		raw, err := os.ReadFile(filepath.Join("..", "..", "windows", script))
		if err != nil {
			t.Fatalf("could not read %s: %v", script, err)
		}
		body := string(raw)
		if strings.Contains(body, "\t") {
			t.Errorf("%s indents with tabs", script)
		}
		if strings.Count(body, "10808") > strings.Count(body, `set "SOCKS=127.0.0.1:10808"`) {
			t.Errorf("%s hardcodes the proxy port instead of reading socks5_listen from config.json", script)
		}
		if strings.Contains(body, "10808") && !strings.Contains(body, "call :READ_SOCKS") {
			t.Errorf("%s defines a default proxy address but never reads the configured one", script)
		}
		if !strings.Contains(body, "Start-Process -FilePath $env:SELF -Verb RunAs") {
			t.Errorf("%s does not elevate through $env:SELF, so a path holding an apostrophe breaks elevation", script)
		}
		if strings.Contains(body, " docs/") {
			t.Errorf("%s points at a repository path the release zip does not contain", script)
		}
		for i, line := range strings.Split(body, "\n") {
			l := strings.ToLower(strings.TrimSpace(line))
			if l == "rem" || strings.HasPrefix(l, "rem ") || strings.HasPrefix(l, "::") {
				t.Errorf("%s:%d is a comment line; the scripts carry none", script, i+1)
			}
		}
		for _, phrase := range []string{"so there is nothing to start", "so there is nothing to stop", "left no data behind", "settings file does not exist"} {
			if strings.Contains(body, phrase) {
				t.Errorf("%s says %q instead of the one not installed message", script, phrase)
			}
		}
		if script != "service-install.bat" && !strings.Contains(body, "echo The AWGSocks service is not installed.\r\n    goto :END") {
			t.Errorf("%s does not say the service is not installed the way the other scripts do", script)
		}
	}
}

// TestUsageEndsWithABlankLine keeps the prompt that follows `awgsocks --help`
// from sitting directly under the last line of the notes.
func TestUsageEndsWithABlankLine(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		buf.ReadFrom(r)
		done <- buf.String()
	}()
	usage(w)
	w.Close()
	out := <-done
	if !strings.HasSuffix(out, ".\n\n") || strings.HasSuffix(out, "\n\n\n") {
		t.Fatalf("the usage text should end with exactly one blank line, it ends with %q", out[len(out)-40:])
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
