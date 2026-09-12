package version

import (
	"os"
	"path/filepath"
	"regexp"
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
