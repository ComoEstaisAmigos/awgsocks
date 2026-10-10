package localdns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const testHost = "awgsocks-local.test"

var testAnswer = netip.MustParseAddr("192.0.2.7")

func startResponder(t *testing.T) *atomic.Int32 {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not open the local DNS responder: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	prev := port
	port = uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	t.Cleanup(func() { port = prev })

	var queries atomic.Int32
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			queries.Add(1)
			if resp, err := answer(buf[:n]); err == nil {
				pc.WriteTo(resp, from)
			}
		}
	}()
	return &queries
}

func answer(query []byte) ([]byte, error) {
	var p dnsmessage.Parser
	header, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}

	known := strings.EqualFold(strings.TrimSuffix(q.Name.String(), "."), testHost)
	rcode := dnsmessage.RCodeSuccess
	if !known {
		rcode = dnsmessage.RCodeNameError
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 header.ID,
		Response:           true,
		Authoritative:      true,
		RecursionDesired:   header.RecursionDesired,
		RecursionAvailable: true,
		RCode:              rcode,
	})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	if known && q.Type == dnsmessage.TypeA {
		err := b.AResource(dnsmessage.ResourceHeader{
			Name:  q.Name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   60,
		}, dnsmessage.AResource{A: testAnswer.As4()})
		if err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestLookupAsksTheLoopbackServer(t *testing.T) {
	queries := startResponder(t)

	addrs, err := Lookup(testContext(t), netip.MustParseAddr("127.0.0.1"), "ip4", testHost)
	if err != nil {
		t.Fatalf("the local resolver did not answer: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != testAnswer {
		t.Fatalf("expected %s, got %v", testAnswer, addrs)
	}
	if queries.Load() == 0 {
		t.Fatal("the answer did not come from the configured loopback server")
	}
}

func TestLookupReportsANonexistentNameAsNotFound(t *testing.T) {
	startResponder(t)

	_, err := Lookup(testContext(t), netip.MustParseAddr("127.0.0.1"), "ip4", "blocked.awgsocks-local.test")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("expected a not-found DNS error, got %v", err)
	}
}

func TestLookupRefusesANonLoopbackServer(t *testing.T) {
	queries := startResponder(t)

	for _, s := range []string{"1.1.1.1", "192.168.1.1", "2606:4700:4700::1111", "0.0.0.0"} {
		if _, err := Lookup(testContext(t), netip.MustParseAddr(s), "ip", testHost); err == nil {
			t.Errorf("a lookup through %s was allowed", s)
		}
	}
	if queries.Load() != 0 {
		t.Fatal("a refused lookup still sent a query")
	}
}
