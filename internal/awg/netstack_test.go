package awg

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// fakeTUN behaves like the upstream netstack device: one packet per Read call,
// blocking until one is available, filling buf[0][offset:] only.
type fakeTUN struct {
	packets chan []byte
	events  chan tun.Event

	mu        sync.Mutex
	closed    bool
	readCalls int
}

func newFakeTUN(depth int) *fakeTUN {
	return &fakeTUN{
		packets: make(chan []byte, depth),
		events:  make(chan tun.Event, 1),
	}
}

func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	p, ok := <-f.packets
	if !ok {
		return 0, os.ErrClosed
	}
	f.mu.Lock()
	f.readCalls++
	f.mu.Unlock()
	n := copy(bufs[0][offset:], p)
	sizes[0] = n
	return 1, nil
}

func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) { return len(bufs), nil }
func (f *fakeTUN) MTU() (int, error)                            { return 1420, nil }
func (f *fakeTUN) Name() (string, error)                        { return "fake", nil }
func (f *fakeTUN) File() *os.File                               { return nil }
func (f *fakeTUN) Events() <-chan tun.Event                     { return f.events }
func (f *fakeTUN) BatchSize() int                               { return 1 }

func (f *fakeTUN) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.packets)
		close(f.events)
	}
	return nil
}

// deviceBuffers mirrors how the AmneziaWG device presents its read buffers: one
// large pooled buffer per slot, written to at a transport offset.
func deviceBuffers(n int) ([][]byte, []int) {
	bufs := make([][]byte, n)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	return bufs, make([]int, n)
}

func marker(i int) []byte {
	return []byte{byte(i >> 8), byte(i), 0xAA, 0xBB}
}

// TestBatchTunNeverWaitsToFillABatch is the regression test for the failure
// this adapter was written to avoid.
//
// A batching adapter that waits for its batch to fill before returning will
// hold a lone packet indefinitely. The AmneziaWG handshake hides that, because
// handshake messages are built and sent by the peer directly and never pass
// through the TUN read path, so the tunnel still reports itself connected while
// the first data packet of every connection is stuck in the adapter.
func TestBatchTunNeverWaitsToFillABatch(t *testing.T) {
	fake := newFakeTUN(4)
	bt := newBatchTun(fake, netstackBatchSize, netstackBatchSize)
	defer bt.Close()

	fake.packets <- marker(1)

	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		bufs, sizes := deviceBuffers(netstackBatchSize)
		n, err := bt.Read(bufs, sizes, 16)
		done <- result{n, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("read failed: %v", r.err)
		}
		if r.n != 1 {
			t.Fatalf("expected the single queued packet, got %d", r.n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read is waiting for the batch to fill: a lone packet was never delivered")
	}
}

// TestBatchTunPreservesOrderAndLosesNothing pushes far more packets than the
// queue depth so the free list has to recycle, then checks every packet arrives
// exactly once and in order, at the requested offset.
func TestBatchTunPreservesOrderAndLosesNothing(t *testing.T) {
	const total = 5000
	const offset = 19

	fake := newFakeTUN(8)
	bt := newBatchTun(fake, netstackBatchSize, netstackBatchSize)

	go func() {
		for i := 0; i < total; i++ {
			fake.packets <- marker(i)
		}
	}()

	bufs, sizes := deviceBuffers(netstackBatchSize)
	got := 0
	maxBatch := 0
	deadline := time.Now().Add(30 * time.Second)

	for got < total {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d packets arrived before the deadline", got, total)
		}
		n, err := bt.Read(bufs, sizes, offset)
		if err != nil {
			t.Fatalf("read failed after %d packets: %v", got, err)
		}
		if n < 1 {
			t.Fatalf("Read returned %d packets and no error", n)
		}
		if n > maxBatch {
			maxBatch = n
		}
		for i := 0; i < n; i++ {
			if sizes[i] != 4 {
				t.Fatalf("packet %d has size %d, want 4", got, sizes[i])
			}
			want := marker(got)
			if string(bufs[i][offset:offset+4]) != string(want) {
				t.Fatalf("packet %d arrived out of order or corrupted: %v", got, bufs[i][offset:offset+4])
			}
			got++
		}
	}

	if maxBatch < 2 {
		t.Fatalf("batching never happened: the largest batch was %d", maxBatch)
	}
	t.Logf("delivered %d packets in order, largest batch %d, upstream read calls %d", got, maxBatch, fake.readCalls)

	if err := bt.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
}

// TestBatchTunReportsClosure checks that a reader blocked in Read is released
// when the wrapped device goes away, and reports a closure rather than a
// silent zero-packet read.
func TestBatchTunReportsClosure(t *testing.T) {
	fake := newFakeTUN(1)
	bt := newBatchTun(fake, netstackBatchSize, netstackBatchSize)

	done := make(chan error, 1)
	go func() {
		bufs, sizes := deviceBuffers(netstackBatchSize)
		_, err := bt.Read(bufs, sizes, 16)
		done <- err
	}()

	// Let the reader park inside Read before closing underneath it.
	time.Sleep(50 * time.Millisecond)
	if err := bt.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a read on a closed device returned no error")
		}
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("expected os.ErrClosed, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read never returned after the device was closed: shutdown deadlock")
	}
}

// TestBatchTunAppliesBackpressure proves the queue is bounded. With the
// consumer stalled, the reader must stop draining the wrapped device once its
// fixed buffer set is exhausted, rather than growing without limit.
func TestBatchTunAppliesBackpressure(t *testing.T) {
	const depth = 8

	fake := newFakeTUN(1024)
	bt := newBatchTun(fake, 1, depth)
	defer bt.Close()

	for i := 0; i < 512; i++ {
		fake.packets <- marker(i)
	}

	// Give the reader ample time to drain as much as it is willing to hold.
	time.Sleep(300 * time.Millisecond)

	fake.mu.Lock()
	calls := fake.readCalls
	fake.mu.Unlock()

	// The adapter may hold depth packets in the queue plus one in hand.
	if calls > depth+1 {
		t.Fatalf("the adapter read %d packets ahead with a queue depth of %d: backpressure is gone", calls, depth)
	}
	if calls == 0 {
		t.Fatal("the adapter read nothing at all")
	}
	t.Logf("read ahead %d packets with queue depth %d", calls, depth)
}

// TestBatchTunUpstreamModeIsUntouched guarantees the production path is the
// upstream object itself, with no wrapper in between.
func TestBatchTunUpstreamModeIsUntouched(t *testing.T) {
	fake := newFakeTUN(1)
	defer fake.Close()

	if got := wrapNetstackTUN(fake, NetstackUpstream); got != tun.Device(fake) {
		t.Fatal("NetstackUpstream wrapped the device instead of passing it through")
	}
	if got := wrapNetstackTUN(fake, NetstackMode("nonsense")); got != tun.Device(fake) {
		t.Fatal("an unknown mode must fall back to the untouched upstream device")
	}
	if got := wrapNetstackTUN(fake, NetstackBatched); got == tun.Device(fake) {
		t.Fatal("NetstackBatched did not wrap the device")
	}
}
