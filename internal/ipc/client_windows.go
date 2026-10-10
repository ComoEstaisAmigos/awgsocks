package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Microsoft/go-winio"
)

// ErrNotRunning means the management pipe does not exist, which normally means
// the AWGSocks service is not running.
var ErrNotRunning = errors.New("the AWGSocks management pipe was not found, the service may not be running")

// dialTimeout bounds how long the CLI waits for the pipe.
const dialTimeout = 5 * time.Second

// Call sends one management command and returns the response.
func Call(ctx context.Context, cmd string) (*Response, error) {
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	c, err := winio.DialPipeContext(dialCtx, PipeName)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, winio.ErrTimeout) {
			return nil, ErrNotRunning
		}
		return nil, fmt.Errorf("%w: %v", ErrNotRunning, err)
	}
	defer c.Close()

	if deadline, ok := ctx.Deadline(); ok {
		c.SetDeadline(deadline)
	} else {
		c.SetDeadline(time.Now().Add(requestTimeout))
	}

	raw, err := json.Marshal(Request{Command: cmd})
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if _, err := c.Write(raw); err != nil {
		return nil, fmt.Errorf("could not send the management request: %w", err)
	}

	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("could not read the management response: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("could not parse the management response: %w", err)
	}
	return &resp, nil
}
