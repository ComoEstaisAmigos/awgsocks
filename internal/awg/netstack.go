package awg

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// NetstackMode selects how packets are handed from the gVisor network stack to
// the AmneziaWG device.
//
// This exists to answer one question experimentally: is the upstream handoff a
// throughput bottleneck worth working around? It is deliberately not reachable
// from configuration. Production always uses NetstackUpstream.
//
// Background. The upstream gVisor adapter (tun/netstack) hands packets over
// like this:
//
//	gVisor TCP sender
//	  -> channel.Endpoint.WritePackets
//	  -> WriteNotify()            called synchronously on the sender goroutine
//	  -> ep.Read()                pops exactly one packet
//	  -> incomingPacket <- view   an UNBUFFERED channel send
//	  -> netTun.Read()            fills buf[0] only, returns 1
//
// and netTun.BatchSize() reports 1. Two consequences follow. The gVisor sender
// blocks inside WriteNotify until the AmneziaWG TUN reader picks the packet up,
// so packet production and packet encryption never overlap for a single
// stream. And because every read returns one packet, the device repeats its
// whole per-iteration cost (peer lookup map, staging, one encryption-queue
// handoff, one sequential-sender handoff) once per packet instead of once per
// batch.
//
// An adapter cannot remove the unbuffered channel in the middle: netTun and its
// endpoint are unexported, so reaching them needs a fork. What an adapter can
// do is keep a reader permanently parked in netTun.Read so the gVisor sender is
// released quickly, and accumulate packets so the device can consume many per
// iteration. Those are the two effects these modes measure separately.
type NetstackMode string

const (
	// NetstackUpstream passes the upstream device through untouched. This is
	// the production path.
	NetstackUpstream NetstackMode = "upstream"

	// NetstackBuffered decouples the gVisor sender from the device reader but
	// still reports a batch size of one. It isolates the cost of the blocking
	// handoff from the cost of per-packet device iteration.
	NetstackBuffered NetstackMode = "buffered"

	// NetstackBatched reports a real batch size so the device consumes many
	// packets per iteration, with only enough queue depth to form a batch.
	NetstackBatched NetstackMode = "batched"

	// NetstackBatchedBuffered combines a real batch size with a deeper queue.
	NetstackBatchedBuffered NetstackMode = "batched-buffered"
)

// Upstream conn.IdealBatchSize. Kept as a local constant so this file does not
// depend on the conn package.
const netstackBatchSize = 128

// wrapNetstackTUN applies the selected experimental handoff to dev. An unknown
// mode is treated as NetstackUpstream so that a mistake can never silently
// change the production data path.
func wrapNetstackTUN(dev tun.Device, mode NetstackMode) tun.Device {
	switch mode {
	case NetstackBuffered:
		return newBatchTun(dev, 1, 256)
	case NetstackBatched:
		return newBatchTun(dev, netstackBatchSize, netstackBatchSize)
	case NetstackBatchedBuffered:
		return newBatchTun(dev, netstackBatchSize, 512)
	default:
		return dev
	}
}

// queuedPacket is one packet read ahead from the upstream device. The buffer is
// owned by exactly one of batchTun.free or batchTun.queue at any moment, which
// is what bounds memory and keeps backpressure intact.
type queuedPacket struct {
	buf []byte
	n   int
}

// batchTun reads ahead from the wrapped device on its own goroutine and serves
// the AmneziaWG device from a bounded queue.
//
// Ordering is preserved: one reader goroutine, one FIFO channel, one consumer.
// No packet is dropped: the reader takes a buffer from a fixed free list and
// blocks when every buffer is in flight, which pushes backpressure through the
// upstream unbuffered channel to the gVisor sender exactly as before, just with
// a fixed number of extra slots in between.
type batchTun struct {
	inner tun.Device
	batch int

	// queue carries filled buffers to the device; free returns them. Both hold
	// the same fixed set of buffers, so a send on either can never block for
	// lack of capacity, and the total memory is fixed at construction.
	queue chan *queuedPacket
	free  chan *queuedPacket

	readErr atomic.Pointer[error]

	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

func newBatchTun(inner tun.Device, batch, depth int) *batchTun {
	if batch < 1 {
		batch = 1
	}
	if depth < batch {
		depth = batch
	}

	// Upstream reads a packet with view.Read(buf[0][offset:]), which copies as
	// much as fits and reports how much it copied. A buffer smaller than the
	// largest packet the stack can emit would therefore truncate silently, so
	// size it like the device's own message buffers.
	const bufferSize = 65535

	t := &batchTun{
		inner: inner,
		batch: batch,
		queue: make(chan *queuedPacket, depth),
		free:  make(chan *queuedPacket, depth),
		done:  make(chan struct{}),
	}
	for i := 0; i < depth; i++ {
		t.free <- &queuedPacket{buf: make([]byte, bufferSize)}
	}

	t.wg.Add(1)
	go t.readLoop()
	return t
}

// readLoop keeps one reader parked inside the upstream device so the gVisor
// sender is released as soon as it offers a packet.
func (t *batchTun) readLoop() {
	defer t.wg.Done()
	defer close(t.queue)

	// The upstream device fills buf[0][offset:] for exactly one packet per
	// call. Read at offset zero into our own buffer: the device's transport
	// offset depends on the current AmneziaWG padding, which this goroutine
	// must not assume, and Read below places the packet at whatever offset the
	// device asks for at that moment.
	one := make([][]byte, 1)
	sizes := make([]int, 1)

	for {
		var p *queuedPacket
		select {
		case p = <-t.free:
		case <-t.done:
			return
		}

		one[0] = p.buf
		sizes[0] = 0
		count, err := t.inner.Read(one, sizes, 0)

		if count > 0 && sizes[0] > 0 {
			p.n = sizes[0]
			select {
			case t.queue <- p:
			case <-t.done:
				return
			}
		} else {
			t.free <- p
		}

		if err != nil {
			t.readErr.Store(&err)
			return
		}
	}
}

// Read delivers at least one and at most BatchSize packets.
//
// It blocks for the first packet and takes whatever else is already queued
// without waiting. Waiting to fill a batch would be a correctness bug, not just
// a latency cost: a connection's first packet is usually the only one in
// flight, so holding it back stalls the exchange that would have produced the
// rest of the batch.
func (t *batchTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	limit := min(len(bufs), len(sizes), t.batch)
	if limit < 1 {
		return 0, nil
	}

	p, ok := <-t.queue
	if !ok {
		return 0, t.readError()
	}
	if err := t.deliver(bufs, sizes, offset, 0, p); err != nil {
		return 0, err
	}
	n := 1

	for n < limit {
		select {
		case p, ok := <-t.queue:
			if !ok {
				return n, nil
			}
			if err := t.deliver(bufs, sizes, offset, n, p); err != nil {
				return n, err
			}
			n++
		default:
			return n, nil
		}
	}
	return n, nil
}

// deliver copies one queued packet into the device's own buffer and returns the
// queue buffer to the free list.
//
// The copy is required, not incidental. The device slices elem.packet out of
// the buffer it passed in and later grows and seals it in place, so the packet
// has to live in that buffer at exactly the requested offset.
func (t *batchTun) deliver(bufs [][]byte, sizes []int, offset, i int, p *queuedPacket) error {
	dst := bufs[i][offset:]
	n := p.n

	// Copy before releasing: once the buffer is back on the free list the
	// reader goroutine may immediately refill it.
	var err error
	if len(dst) < n {
		err = fmt.Errorf("a %d byte packet from the network stack does not fit the %d byte device buffer", n, len(dst))
	} else {
		copy(dst, p.buf[:n])
		sizes[i] = n
	}

	p.n = 0
	t.free <- p
	return err
}

func (t *batchTun) readError() error {
	if p := t.readErr.Load(); p != nil {
		return *p
	}
	return os.ErrClosed
}

// Close stops the reader and releases the wrapped device.
//
// The wrapped device is closed first so that a reader parked inside its Read
// returns instead of waiting forever; done then releases a reader that is
// waiting for a free buffer instead.
func (t *batchTun) Close() error {
	err := t.inner.Close()
	t.closeOnce.Do(func() { close(t.done) })
	t.wg.Wait()
	return err
}

func (t *batchTun) BatchSize() int                               { return t.batch }
func (t *batchTun) Write(bufs [][]byte, offset int) (int, error) { return t.inner.Write(bufs, offset) }
func (t *batchTun) MTU() (int, error)                            { return t.inner.MTU() }
func (t *batchTun) Name() (string, error)                        { return t.inner.Name() }
func (t *batchTun) File() *os.File                               { return t.inner.File() }
func (t *batchTun) Events() <-chan tun.Event                     { return t.inner.Events() }
