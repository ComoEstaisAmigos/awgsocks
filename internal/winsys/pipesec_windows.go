package winsys

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

// basePipeSDDL grants full access to LocalSystem (SY) and the local
// Administrators group (BA), with inheritance disabled (P).
const basePipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"

// PipeSecurityDescriptor returns the SDDL for the AWGSocks management pipe.
//
// The base descriptor covers the normal case, where AWGSocks runs as
// LocalSystem. The account that actually owns the process is added as well, so
// that `awgsocks run` in the foreground works for the user who started it.
// Without this the pipe server can create its first instance but cannot open
// the next one, because a named pipe listener must reopen the pipe by name.
//
// No other principal is granted access: an unprivileged process cannot read
// tunnel status or trigger a reconnect.
func PipeSecurityDescriptor() string {
	sid, err := currentProcessSID()
	if err != nil || sid == "" {
		return basePipeSDDL
	}
	// LocalSystem is already covered by SY, so there is nothing to add.
	if sid == "S-1-5-18" {
		return basePipeSDDL
	}
	return basePipeSDDL + fmt.Sprintf("(A;;GA;;;%s)", sid)
}

// currentProcessSID returns the SID string of the account this process runs as.
func currentProcessSID() (string, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return "", err
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	s := user.User.Sid.String()
	if strings.TrimSpace(s) == "" {
		return "", errors.New("could not read the SID")
	}
	return s, nil
}
