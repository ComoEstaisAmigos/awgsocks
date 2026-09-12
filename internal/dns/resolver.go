// Package dns caches and de-duplicates the name lookups AWGSocks performs
// inside the AmneziaWG tunnel.
//
// # Why this exists
//
// A SOCKS5 client that resolves remotely (socks5h) sends a hostname with every
// CONNECT. A browser opens several connections per host and many hosts per
// page, so a single page load can ask for the same name a dozen times within a
// second. Each of those lookups would otherwise become a fresh A and AAAA query
// over UDP inside the tunnel.
//
// That burst is what makes the tunnel lose DNS datagrams, and the upstream
// netstack resolver waits five seconds per server before retrying, so one lost
// query stalls a page resource for five seconds. Collapsing duplicate lookups
// and caching answers removes the burst, which is the actual fix; shorter retry
// timeouts only reduce the damage when a packet is still lost.
//
// The cache holds only what the in-tunnel DNS servers answered. It never
// consults the Windows resolver and never provides an answer that could send
// traffic outside the tunnel.
package dns

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Cache policy.
const (
	// PositiveTTL is how long a successful answer is reused. The upstream
	// netstack resolver does not expose the record TTL, so a fixed, short
	// lifetime is used: long enough to collapse one page load, short enough
	// that DNS-based failover still works.
	PositiveTTL = 60 * time.Second

	// NegativeTTL is how long a failure is remembered. It exists to stop a
	// broken name from being retried once per connection attempt.
	NegativeTTL = 5 * time.Second

	// MaxEntries bounds cache memory.
	MaxEntries = 1024

	// MaxConcurrent limits how many upstream queries may be in flight at once.
	//
	// Opening a page can ask for dozens of distinct names within a few hundred
	// milliseconds. Firing all of them at the in-tunnel resolver at once is what
	// pushes the link, and the public resolver behind it, into dropping
	// datagrams. Queueing beyond this point costs a little latency on a cold
	// cache and avoids the five second stalls that a dropped query causes.
	MaxConcurrent = 8
)

// LookupFunc performs the actual in-tunnel lookup.
type LookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

type entry struct {
	addrs   []netip.Addr
	err     error
	expires time.Time
}

type call struct {
	done  chan struct{}
	addrs []netip.Addr
	err   error
}

// Stats reports cache effectiveness, which is the quickest way to tell whether
// name resolution is the reason a page feels slow.
type Stats struct {
	Hits      uint64 `json:"hits"`
	Misses    uint64 `json:"misses"`
	Coalesced uint64 `json:"coalesced"`
	Entries   int    `json:"entries"`
}

// Resolver caches and de-duplicates lookups performed by lookup.
type Resolver struct {
	lookup LookupFunc
	sem    chan struct{}

	mu       sync.Mutex
	entries  map[string]entry
	inflight map[string]*call

	hits      atomic.Uint64
	misses    atomic.Uint64
	coalesced atomic.Uint64
}

// New creates a resolver in front of lookup.
func New(lookup LookupFunc) *Resolver {
	return &Resolver{
		lookup:   lookup,
		sem:      make(chan struct{}, MaxConcurrent),
		entries:  make(map[string]entry),
		inflight: make(map[string]*call),
	}
}

// Lookup resolves host, serving a cached answer when one is fresh and
// collapsing concurrent lookups for the same name into a single query.
func (r *Resolver) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	now := time.Now()

	r.mu.Lock()
	if e, ok := r.entries[host]; ok && now.Before(e.expires) {
		r.mu.Unlock()
		r.hits.Add(1)
		return e.addrs, e.err
	}
	// Join a query that is already in flight for the same name.
	if c, ok := r.inflight[host]; ok {
		r.mu.Unlock()
		r.coalesced.Add(1)
		select {
		case <-c.done:
			return c.addrs, c.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c := &call{done: make(chan struct{})}
	r.inflight[host] = c
	r.mu.Unlock()

	r.misses.Add(1)
	c.addrs, c.err = r.limitedLookup(ctx, host)

	r.mu.Lock()
	delete(r.inflight, host)
	ttl := PositiveTTL
	if c.err != nil {
		ttl = NegativeTTL
	}
	// An error caused by the caller cancelling says nothing about the name,
	// so it is not cached.
	if c.err == nil || ctx.Err() == nil {
		r.evictLocked(now)
		r.entries[host] = entry{addrs: c.addrs, err: c.err, expires: time.Now().Add(ttl)}
	}
	r.mu.Unlock()

	close(c.done)
	return c.addrs, c.err
}

// limitedLookup runs one upstream query under the concurrency limit. A caller
// whose context expires while queueing gives up rather than adding to the
// burst it was waiting to avoid.
func (r *Resolver) limitedLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return r.lookup(ctx, host)
}

// evictLocked drops expired entries, and if the cache is still full, clears it.
// Callers must hold r.mu.
func (r *Resolver) evictLocked(now time.Time) {
	if len(r.entries) < MaxEntries {
		return
	}
	for k, e := range r.entries {
		if now.After(e.expires) {
			delete(r.entries, k)
		}
	}
	if len(r.entries) >= MaxEntries {
		// Last resort: clearing an entirely fresh cache beats growing without
		// bound or carrying a more complicated LRU.
		clear(r.entries)
	}
}

// Flush drops every cached answer. It is called whenever the tunnel is rebuilt,
// so that a new configuration cannot serve answers from the previous one.
func (r *Resolver) Flush() {
	r.mu.Lock()
	clear(r.entries)
	r.mu.Unlock()
}

// Stats returns a snapshot of cache effectiveness.
func (r *Resolver) Stats() Stats {
	r.mu.Lock()
	n := len(r.entries)
	r.mu.Unlock()
	return Stats{
		Hits:      r.hits.Load(),
		Misses:    r.misses.Load(),
		Coalesced: r.coalesced.Load(),
		Entries:   n,
	}
}
