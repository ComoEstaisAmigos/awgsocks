package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Microsoft/go-winio"

	"github.com/ComoEstaisAmigos/awgsocks/internal/logging"
	"github.com/ComoEstaisAmigos/awgsocks/internal/winsys"
)

// requestTimeout bounds how long a single management request may take.
const requestTimeout = 60 * time.Second

// Server serves the AWGSocks management pipe.
type Server struct {
	log     *logging.Logger
	handler Handler

	mu      sync.Mutex
	ln      net.Listener
	closing atomic.Bool
	wg      sync.WaitGroup
}

// NewServer creates an unstarted pipe server.
func NewServer(log *logging.Logger, handler Handler) *Server {
	return &Server{log: log, handler: handler}
}

// Start creates the named pipe and begins serving management requests.
func (s *Server) Start() error {
	sddl := winsys.PipeSecurityDescriptor()
	ln, err := winio.ListenPipe(PipeName, &winio.PipeConfig{
		SecurityDescriptor: sddl,
		MessageMode:        false,
		InputBufferSize:    16 * 1024,
		OutputBufferSize:   256 * 1024,
	})
	if err != nil {
		return fmt.Errorf("could not open the management pipe %s: %w", PipeName, err)
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()

	s.log.Infof("management pipe up: %s (ACL: %s)", PipeName, sddl)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop(ln)
	}()
	return nil
}

// Stop closes the pipe and waits for in-flight requests.
func (s *Server) Stop() {
	if s.closing.Swap(true) {
		return
	}
	s.mu.Lock()
	ln := s.ln
	s.ln = nil
	s.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	s.wg.Wait()
	s.log.Infof("management pipe closed")
}

func (s *Server) acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if s.closing.Load() || errors.Is(err, winio.ErrPipeListenerClosed) {
				return
			}
			s.log.Errorf("management pipe accept error: %v", err)
			return
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer c.Close()
			s.serve(c)
		}(c)
	}
}

func (s *Server) serve(c net.Conn) {
	c.SetDeadline(time.Now().Add(requestTimeout))

	reader := bufio.NewReader(c)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		s.log.Debugf("could not read the management request: %v", err)
		return
	}

	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		writeResponse(c, Response{OK: false, Error: "could not parse the request: " + err.Error()})
		return
	}

	s.log.Debugf("management command received: %s", req.Command)
	writeResponse(c, s.dispatch(req))
}

func (s *Server) dispatch(req Request) Response {
	switch req.Command {
	case CmdPing:
		return Response{OK: true, Message: "pong"}
	case CmdStatus:
		return Response{OK: true, Status: s.handler.Status()}
	case CmdReload:
		msg, err := s.handler.Reload()
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		if msg == "" {
			msg = "configuration reloaded"
		}
		return Response{OK: true, Message: msg}
	case CmdReconnect:
		if err := s.handler.Reconnect(); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Message: "reconnect triggered"}
	case CmdStart:
		if err := s.handler.StartTunnel(); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Message: "tunnel started"}
	case CmdStop:
		if err := s.handler.StopTunnel(); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Message: "tunnel stopped"}
	default:
		return Response{OK: false, Error: fmt.Sprintf("unknown command: %q", req.Command)}
	}
}

func writeResponse(c net.Conn, resp Response) {
	raw, err := json.Marshal(resp)
	if err != nil {
		raw = []byte(`{"ok":false,"error":"could not serialise the response"}`)
	}
	raw = append(raw, '\n')
	c.Write(raw)
}
