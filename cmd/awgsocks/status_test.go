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
