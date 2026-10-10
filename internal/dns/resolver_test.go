package dns

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(s))
	for _, v := range s {
		out = append(out, netip.MustParseAddr(v))
	}
	return out
}

// TestCacheServesRepeatLookups is the behaviour that matters for a browser:
// a host asked for many times must reach the tunnel once.
func TestCacheServesRepeatLookups(t *testing.T) {
	var calls atomic.Int64
	r := New(func(ctx context.Context, host string) ([]netip.Addr, error) {
		calls.Add(1)
		return addrs("93.184.216.34"), nil
	})

	for i := 0; i < 20; i++ {
		got, err := r.Lookup(context.Background(), "example.com")
		if err != nil {
			t.Fatalf("lookup failed: %v", err)
		}
		if len(got) != 1 || got[0].String() != "93.184.216.34" {
			t.Fatalf("unexpected result: %v", got)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("exactly 1 query should have reached the tunnel, got %d", n)
	}
	st := r.Stats()
	if st.Hits != 19 || st.Misses != 1 {
		t.Fatalf("cache counters are wrong: %+v", st)
	}
}

// TestConcurrentLookupsAreCoalesced covers the burst a page load creates: six
// parallel connections to one host must not produce six DNS queries.
func TestConcurrentLookupsAreCoalesced(t *testing.T) {
	var calls atomic.Int64
	release := make(chan struct{})
	r := New(func(ctx context.Context, host string) ([]netip.Addr, error) {
		calls.Add(1)
		<-release
		return addrs("1.2.3.4"), nil
	})

	const n = 24
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := r.Lookup(context.Background(), "cdn.example.com")
			if err != nil {
				errs <- err
				return
			}
			if len(got) != 1 {
				errs <- errors.New("unexpected result")
			}
		}()
	}
	// Give every caller a chance to join the single in-flight query.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent lookup failed: %v", err)
	}

	if n := calls.Load(); n != 1 {
		t.Fatalf("expected a single query, got %d", n)
	}
	if st := r.Stats(); st.Coalesced == 0 {
		t.Fatalf("the coalesced counter did not move: %+v", st)
	}
}

func TestNegativeAnswersAreCachedBriefly(t *testing.T) {
	var calls atomic.Int64
	want := errors.New("not found")
	r := New(func(ctx context.Context, host string) ([]netip.Addr, error) {
		calls.Add(1)
		return nil, want
	})

	for i := 0; i < 5; i++ {
		if _, err := r.Lookup(context.Background(), "nonexistent.invalid"); !errors.Is(err, want) {
			t.Fatalf("expected an error, got %v", err)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("a failure should be cached, query count %d", n)
	}
}

func TestConcurrencyIsLimited(t *testing.T) {
	var inFlight, peak atomic.Int64
	r := New(func(ctx context.Context, host string) ([]netip.Addr, error) {
		cur := inFlight.Add(1)
		for {
			p := peak.Load()
			if cur <= p || peak.CompareAndSwap(p, cur) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		inFlight.Add(-1)
		return addrs("1.2.3.4"), nil
	})

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each call uses a different name so coalescing does not kick in.
			r.Lookup(context.Background(), string(rune('a'+i%26))+".example.com."+string(rune('a'+i/26)))
		}(i)
	}
	wg.Wait()

	if p := peak.Load(); p > MaxConcurrent {
		t.Fatalf("the concurrency limit was exceeded: %d > %d", p, MaxConcurrent)
	}
}

func TestFlushDropsCache(t *testing.T) {
	var calls atomic.Int64
	r := New(func(ctx context.Context, host string) ([]netip.Addr, error) {
		calls.Add(1)
		return addrs("1.2.3.4"), nil
	})

	r.Lookup(context.Background(), "example.com")
	r.Flush()
	r.Lookup(context.Background(), "example.com")

	if n := calls.Load(); n != 2 {
		t.Fatalf("the name should be queried again after Flush, query count %d", n)
	}
}

func TestCancelledContextIsNotCached(t *testing.T) {
	var calls atomic.Int64
	r := New(func(ctx context.Context, host string) ([]netip.Addr, error) {
		calls.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	r.Lookup(ctx, "example.com")
	cancel()

	// A cancelled request says nothing about the name, so the second call
	// must really ask again.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	r.Lookup(ctx2, "example.com")
	cancel2()

	if n := calls.Load(); n != 2 {
		t.Fatalf("a cancelled lookup must not be cached, query count %d", n)
	}
}
