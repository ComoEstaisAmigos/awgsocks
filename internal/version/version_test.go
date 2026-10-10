package version

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestBuildScriptStampsThisVersion keeps the two places the release version is
// written from drifting apart.
//
// scripts/build.bat passes its own VERSION to the linker with -X, which
// overrides the value here, so a release built from the script reports
// whatever the script says. Bumping one and forgetting the other produces a
// binary that names the wrong version, and nothing else would notice.
func TestBuildScriptStampsThisVersion(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "build.bat"))
	if err != nil {
		t.Fatalf("could not read scripts/build.bat: %v", err)
	}
	m := regexp.MustCompile(`(?m)^set VERSION=(\S+?)\r?$`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("scripts/build.bat no longer sets VERSION, so this check cannot see what it stamps")
	}
	if got := string(m[1]); got != Version {
		t.Fatalf("scripts/build.bat stamps version %q but internal/version says %q", got, Version)
	}
}

// TestReleaseToolchainIsDocumented keeps the Go version releases are packaged
// with, pinned in scripts/package.ps1 so the zip is reproducible, equal to the
// one UPSTREAM.md tells people to use when they check a release.
func TestReleaseToolchainIsDocumented(t *testing.T) {
	root := filepath.Join("..", "..")
	raw, err := os.ReadFile(filepath.Join(root, "scripts", "package.ps1"))
	if err != nil {
		t.Fatalf("could not read scripts/package.ps1: %v", err)
	}
	m := regexp.MustCompile(`(?m)^\$goToolchain = '(go\d+\.\d+(?:\.\d+)?)'`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("scripts/package.ps1 no longer pins $goToolchain, so releases are not reproducible")
	}
	doc, err := os.ReadFile(filepath.Join(root, "docs", "UPSTREAM.md"))
	if err != nil {
		t.Fatalf("could not read docs/UPSTREAM.md: %v", err)
	}
	if want := "releases are packaged with " + string(m[1]); !strings.Contains(string(doc), want) {
		t.Errorf("scripts/package.ps1 pins %s but docs/UPSTREAM.md does not say %q", m[1], want)
	}
}

// TestDocsNameThePinnedUpstream keeps the documentation from quoting an
// upstream AmneziaWG version the binary is not built against.
//
// The README and UPSTREAM.md each carry a version table, and sample output in
// other documents quotes versions and short commits. None of them is generated,
// so bumping the constants here leaves every one of them silently stale.
func TestDocsNameThePinnedUpstream(t *testing.T) {
	root := filepath.Join("..", "..")
	docs, err := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	docs = append(docs, filepath.Join(root, "README.md"))

	versions := map[string]bool{AmneziaWGGoVersion: true, AmneziaWGWindowsVersion: true}
	commits := []string{AmneziaWGGoCommit, AmneziaWGWindowsCommit}
	versionRe := regexp.MustCompile(`\bv\d+\.\d+\.\d{8}\b`)
	fullCommitRe := regexp.MustCompile(`\b[0-9a-f]{40}\b`)
	shortCommitRe := regexp.MustCompile(`\(commit ([0-9a-f]{7,39})\)`)

	isPinnedPrefix := func(s string) bool {
		for _, c := range commits {
			if strings.HasPrefix(c, s) {
				return true
			}
		}
		return false
	}

	for _, doc := range docs {
		raw, err := os.ReadFile(doc)
		if err != nil {
			t.Fatalf("could not read %s: %v", doc, err)
		}
		text := string(raw)
		name := filepath.Base(doc)
		for _, v := range versionRe.FindAllString(text, -1) {
			if !versions[v] {
				t.Errorf("%s names upstream version %s, which is not pinned in internal/version", name, v)
			}
		}
		for _, c := range fullCommitRe.FindAllString(text, -1) {
			if !isPinnedPrefix(c) {
				t.Errorf("%s names commit %s, which is not pinned in internal/version", name, c)
			}
		}
		for _, m := range shortCommitRe.FindAllStringSubmatch(text, -1) {
			if !isPinnedPrefix(m[1]) {
				t.Errorf("%s quotes short commit %s, which is not a pinned commit", name, m[1])
			}
		}
		if name == "README.md" || name == "UPSTREAM.md" {
			for _, want := range []string{AmneziaWGGoVersion, AmneziaWGWindowsVersion, AmneziaWGGoCommit, AmneziaWGWindowsCommit} {
				if !strings.Contains(text, want) {
					t.Errorf("%s has a version table but does not name %s", name, want)
				}
			}
		}
	}
}
