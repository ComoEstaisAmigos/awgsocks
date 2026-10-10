package socks5

import (
	"context"
	"errors"
	"strings"

	"github.com/ComoEstaisAmigos/awgsocks/internal/awg"
)

// replyForError maps a dial or resolve failure to a SOCKS5 reply code.
//
// The important case is the AmneziaWG tunnel being down or without a live
// handshake: that is reported as "network unreachable", because from the
// client's point of view the only network AWGSocks offers really is
// unreachable. There is no code path that retries such a request over the
// default Windows network.
func replyForError(err error, fallback byte) byte {
	switch {
	case err == nil:
		return repSuccess
	case errors.Is(err, awg.ErrTunnelDown), errors.Is(err, awg.ErrNotReady):
		return repNetworkUnreachable
	case errors.Is(err, awg.ErrNoDNS):
		return repHostUnreachable
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return repHostUnreachable
	}
	// gVisor reports a TCP RST as a textual error, so it is matched here in
	// order to return the standard SOCKS5 "connection refused" code.
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "connection refused"):
		return repConnectionRefused
	case strings.Contains(msg, "network is unreachable"):
		return repNetworkUnreachable
	case strings.Contains(msg, "no route to host"), strings.Contains(msg, "host is unreachable"):
		return repHostUnreachable
	}
	if fallback == 0 {
		return repGeneralFailure
	}
	return fallback
}
