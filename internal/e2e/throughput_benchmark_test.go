package e2e

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ComoEstaisAmigos/awgsocks/internal/awg"
)

const (
	benchmarkEchoPort    = 9001
	benchmarkSinkPort    = 9002
	benchmarkPayloadSize = 256 << 10
)

// BenchmarkProductionDataPath measures the complete production path on
// loopback. Each operation sends benchmarkPayloadSize bytes per concurrent
// SOCKS5 CONNECT stream to an echo service behind a second AmneziaWG device
// and reads every byte back. The reported Mbit/s is one-direction application
// payload throughput; the echo return traffic is intentionally excluded so it
// can be compared with conventional download/upload measurements.
//
// The benchmark opens persistent SOCKS5 connections before timing begins. It
// therefore measures sustained data transport rather than handshakes or TCP
// slow start. Run it alone, without other network-heavy work:
//
//	go test ./internal/e2e -run '^$' -bench BenchmarkProductionDataPath -benchtime=10s -benchmem
func BenchmarkProductionDataPath(b *testing.B) {
	for _, streams := range []int{1, 2, 4, 8} {
		b.Run(fmt.Sprintf("streams=%d", streams), func(b *testing.B) {
			benchmarkDataPath(b, streams, awg.NetstackUpstream)
		})
	}
}

// BenchmarkExperimentalDataPath runs the identical full-path benchmark with
// only the client TUN handoff changed. The experimental mode is never exposed
// through application configuration and cannot change production behaviour.
func BenchmarkExperimentalDataPath(b *testing.B) {
	for _, mode := range []awg.NetstackMode{
		awg.NetstackBuffered,
		awg.NetstackBatched,
		awg.NetstackBatchedBuffered,
	} {
		b.Run(string(mode), func(b *testing.B) {
			for _, streams := range []int{1, 2, 4, 8} {
				b.Run(fmt.Sprintf("streams=%d", streams), func(b *testing.B) {
					benchmarkDataPath(b, streams, mode)
				})
			}
		})
	}
}

func benchmarkDataPath(b *testing.B, streams int, netstackMode awg.NetstackMode) {
	b.Helper()
	h := startHarnessWithNetstack(b, false, awg.BindStd, netstackMode)
	startBenchmarkEcho(b, h)

	payload := make([]byte, benchmarkPayloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	conns := make([]net.Conn, streams)
	for i := range conns {
		c, _, err := socksDial(h.socks.Addr(), 0x01, ipv4Bytes(serverV4), benchmarkEchoPort)
		if err != nil {
			b.Fatalf("SOCKS5 CONNECT stream %d failed: %v", i, err)
		}
		c.SetDeadline(time.Now().Add(30 * time.Second))
		conns[i] = c
	}
	b.Cleanup(func() {
		for _, c := range conns {
			if c != nil {
				c.Close()
			}
		}
	})

	// Establish the data path before the measurement. This both avoids timing
	// first-packet effects and detects a broken echo service early.
	if err := echoRound(conns[0], payload); err != nil {
		b.Fatalf("benchmark warm-up failed: %v", err)
	}

	b.SetBytes(int64(streams * len(payload)))
	b.ResetTimer()
	processCPUStart := processCPUTime()
	for i := 0; i < b.N; i++ {
		if err := echoAll(conns, payload); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	processCPU := processCPUTime() - processCPUStart
	if processCPU > 0 {
		b.ReportMetric(float64(processCPU.Nanoseconds())/float64(b.N), "cpu-ns/op")
		if elapsed := b.Elapsed(); elapsed > 0 {
			b.ReportMetric(100*float64(processCPU)/float64(elapsed), "cpu-pct")
		}
	}
}

func startBenchmarkEcho(b *testing.B, h *harness) {
	b.Helper()
	ln, err := h.server.tnet.ListenTCPAddrPort(
		netip.AddrPortFrom(netip.MustParseAddr(serverV4), benchmarkEchoPort))
	if err != nil {
		b.Fatalf("could not open in-tunnel benchmark echo listener: %v", err)
	}
	b.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
}

func echoAll(conns []net.Conn, payload []byte) error {
	errCh := make(chan error, len(conns))
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			if err := echoRound(c, payload); err != nil {
				errCh <- err
			}
		}(c)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		return err
	}
	return nil
}

func echoRound(c net.Conn, payload []byte) error {
	writeDone := make(chan error, 1)
	go func() {
		_, err := c.Write(payload)
		writeDone <- err
	}()

	received := make([]byte, len(payload))
	_, readErr := io.ReadFull(c, received)
	writeErr := <-writeDone
	if writeErr != nil {
		return fmt.Errorf("write failed: %w", writeErr)
	}
	if readErr != nil {
		return fmt.Errorf("read failed: %w", readErr)
	}
	if !bytes.Equal(payload, received) {
		return fmt.Errorf("echo payload was corrupted")
	}
	return nil
}

// ---------------------------------------------------------------------------
// One-directional transport
// ---------------------------------------------------------------------------

// BenchmarkProductionUpload measures the same production path in one direction
// only, which is what a typical download or upload looks like.
//
// The echo benchmarks above carry traffic both ways at once and impose a
// barrier per operation: every byte has to come back before the next block is
// sent. That makes them a poor model of a bulk transfer and a poor instrument
// for locating a bottleneck, because the measured rate is bounded by the round
// trip rather than by how fast the path can move bytes. This benchmark writes
// continuously and never waits for a reply.
func BenchmarkProductionUpload(b *testing.B) {
	for _, streams := range []int{1, 2, 4, 8} {
		b.Run(fmt.Sprintf("streams=%d", streams), func(b *testing.B) {
			benchmarkUpload(b, streams, awg.NetstackUpstream)
		})
	}
}

// BenchmarkExperimentalUpload runs the one-directional transport with the
// experimental network stack handoffs.
func BenchmarkExperimentalUpload(b *testing.B) {
	for _, mode := range []awg.NetstackMode{
		awg.NetstackBuffered,
		awg.NetstackBatched,
		awg.NetstackBatchedBuffered,
	} {
		b.Run(string(mode), func(b *testing.B) {
			for _, streams := range []int{1, 4} {
				b.Run(fmt.Sprintf("streams=%d", streams), func(b *testing.B) {
					benchmarkUpload(b, streams, mode)
				})
			}
		})
	}
}

func benchmarkUpload(b *testing.B, streams int, netstackMode awg.NetstackMode) {
	b.Helper()
	benchmarkUploadWithBind(b, streams, awg.BindStd, netstackMode)
}

func benchmarkUploadWithBind(b *testing.B, streams int, bind awg.BindMode, netstackMode awg.NetstackMode) {
	b.Helper()
	h := startHarnessWithNetstack(b, false, bind, netstackMode)
	startBenchmarkSink(b, h)

	payload := make([]byte, benchmarkPayloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	conns := make([]net.Conn, streams)
	for i := range conns {
		c, _, err := socksDial(h.socks.Addr(), 0x01, ipv4Bytes(serverV4), benchmarkSinkPort)
		if err != nil {
			b.Fatalf("SOCKS5 CONNECT stream %d failed: %v", i, err)
		}
		c.SetDeadline(time.Now().Add(10 * time.Minute))
		conns[i] = c
	}

	// Open the congestion window before timing so the measurement reflects
	// sustained transport rather than TCP slow start.
	for _, c := range conns {
		if _, err := c.Write(payload); err != nil {
			b.Fatalf("benchmark warm-up failed: %v", err)
		}
	}

	b.SetBytes(int64(streams * len(payload)))
	b.ResetTimer()
	processCPUStart := processCPUTime()
	for i := 0; i < b.N; i++ {
		if err := writeAll(conns, payload); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	processCPU := processCPUTime() - processCPUStart
	if processCPU > 0 {
		b.ReportMetric(float64(processCPU.Nanoseconds())/float64(b.N), "cpu-ns/op")
		if elapsed := b.Elapsed(); elapsed > 0 {
			b.ReportMetric(100*float64(processCPU)/float64(elapsed), "cpu-pct")
		}
	}

	// Half close each stream and collect the count the far side actually
	// received, so that a silent truncation cannot pass as throughput.
	want := uint64(b.N+1) * uint64(len(payload))
	for i, c := range conns {
		hc, ok := c.(interface{ CloseWrite() error })
		if !ok {
			b.Fatalf("stream %d cannot be half closed", i)
		}
		if err := hc.CloseWrite(); err != nil {
			b.Fatalf("stream %d half close failed: %v", i, err)
		}
	}
	for i, c := range conns {
		var tally [8]byte
		if _, err := io.ReadFull(c, tally[:]); err != nil {
			b.Fatalf("stream %d did not report its byte count: %v", i, err)
		}
		if got := binary.BigEndian.Uint64(tally[:]); got != want {
			b.Fatalf("stream %d delivered %d bytes, sent %d", i, got, want)
		}
		c.Close()
	}
}

// startBenchmarkSink serves a discard endpoint inside the tunnel. It verifies
// the byte pattern as it reads and reports the total it received once the
// client half closes, so loss or corruption fails the benchmark instead of
// inflating it.
func startBenchmarkSink(b *testing.B, h *harness) {
	b.Helper()
	ln, err := h.server.tnet.ListenTCPAddrPort(
		netip.AddrPortFrom(netip.MustParseAddr(serverV4), benchmarkSinkPort))
	if err != nil {
		b.Fatalf("could not open the in-tunnel sink listener: %v", err)
	}
	b.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1<<16)
				var total uint64
				for {
					n, err := c.Read(buf)
					for i := 0; i < n; i++ {
						if buf[i] != byte((total+uint64(i))%256) {
							return // corrupted; the client's tally check will fail
						}
					}
					total += uint64(n)
					if err != nil {
						break
					}
				}
				var tally [8]byte
				binary.BigEndian.PutUint64(tally[:], total)
				_, _ = c.Write(tally[:])
			}(c)
		}
	}()
}

func writeAll(conns []net.Conn, payload []byte) error {
	errCh := make(chan error, len(conns))
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			if _, err := c.Write(payload); err != nil {
				errCh <- err
			}
		}(c)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		return err
	}
	return nil
}

// BenchmarkBindModeUpload compares the two upstream UDP binds on the
// one-directional path.
//
// A CPU profile of the standard bind attributes roughly 57% of all processor
// time to the Windows socket syscall transition and about 2% to AmneziaWG
// encryption and decryption together, so the number of UDP syscalls per packet,
// not the cryptography and not the network stack handoff, is what bounds this
// path. The Registered I/O bind is the upstream answer to that on Windows.
func BenchmarkBindModeUpload(b *testing.B) {
	cases := []struct {
		name         string
		bind         awg.BindMode
		netstackMode awg.NetstackMode
	}{
		{"std", awg.BindStd, awg.NetstackUpstream},
		{"rio", awg.BindRIO, awg.NetstackUpstream},
		{"rio+batched", awg.BindRIO, awg.NetstackBatchedBuffered},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			for _, streams := range []int{1, 4} {
				b.Run(fmt.Sprintf("streams=%d", streams), func(b *testing.B) {
					benchmarkUploadWithBind(b, streams, tc.bind, tc.netstackMode)
				})
			}
		})
	}
}
