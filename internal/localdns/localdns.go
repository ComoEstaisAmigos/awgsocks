package localdns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

var port uint16 = 53

func Lookup(ctx context.Context, server netip.Addr, network, host string) ([]netip.Addr, error) {
	server = server.Unmap()
	if !server.IsLoopback() {
		return nil, fmt.Errorf("a local DNS server must be a loopback address, %s was refused", server)
	}
	target := netip.AddrPortFrom(server, port).String()
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, target)
		},
	}
	addrs, err := r.LookupNetIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.Unmap())
	}
	return out, nil
}
