package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ComoEstaisAmigos/awgsocks/internal/ipc"
)

// captureStatus renders a status report the way `awgsocks status` prints it.
func captureStatus(t *testing.T, st *ipc.Status) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = stdout }()

	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	printStatus(st)
	w.Close()
	return <-done
}

// TestStatusSaysWhyTheTunnelIsPaused matters because a paused tunnel otherwise
// looks exactly like a stopped one, and the reason is on another program's
// adapter, not anywhere in AWGSocks' own settings.
func TestStatusSaysWhyTheTunnelIsPaused(t *testing.T) {
	st := &ipc.Status{Service: "running"}
	st.Tunnel.State = "stopped"
	st.Tunnel.PausedBy = `"AmneziaVPN" (10.66.66.2)`

	out := captureStatus(t, st)
	want := "State             : stopped\n" +
		"Paused            : this configuration is connected on the Windows adapter \"AmneziaVPN\" (10.66.66.2),\n" +
		"                    resumes when that adapter disconnects\n"
	if !strings.Contains(out, want) {
		t.Fatalf("the pause is not explained under the state line:\n%s", out)
	}

	st.Tunnel.PausedBy = ""
	if out := captureStatus(t, st); strings.Contains(out, "Paused") {
		t.Fatalf("a tunnel that is not paused is reported as paused:\n%s", out)
	}
}

func TestStatusWarnsWhenProgramsResolveNamesThemselves(t *testing.T) {
	const hint = "no program sent a hostname"

	st := &ipc.Status{Service: "running"}
	st.Socks5.Total = resolvesItselfAfter + 10
	if out := captureStatus(t, st); !strings.Contains(out, hint) {
		t.Fatalf("programs that only send IP addresses were not pointed out:\n%s", out)
	}

	st.Socks5.Hostnames = 1
	if out := captureStatus(t, st); strings.Contains(out, hint) {
		t.Fatalf("the hint was shown although a hostname arrived:\n%s", out)
	}

	st.Socks5.Hostnames = 0
	st.Socks5.Total = resolvesItselfAfter - 1
	if out := captureStatus(t, st); strings.Contains(out, hint) {
		t.Fatalf("the hint was shown after too few sessions to judge:\n%s", out)
	}
}

func TestDNSCacheNamesWhereQueriesGo(t *testing.T) {
	c := ipc.DNSCacheStatus{Entries: 3, Hits: 2, Misses: 3}
	if got := formatDNSCache(c, false); !strings.Contains(got, "3 tunnel queries") {
		t.Fatalf("in-tunnel queries are mislabelled: %s", got)
	}
	if got := formatDNSCache(c, true); !strings.Contains(got, "3 local queries") {
		t.Fatalf("queries to a resolver on this PC are labelled as tunnel queries: %s", got)
	}
}

func TestFailedRequestsAreSplitByCause(t *testing.T) {
	if got := formatFailed(ipc.SocksStatus{}); got != "0" {
		t.Fatalf("no failures should read as 0, got %q", got)
	}
	got := formatFailed(ipc.SocksStatus{Failed: 26, Unresolved: 24})
	if want := "26 (24 names not resolved, 2 could not connect)"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
