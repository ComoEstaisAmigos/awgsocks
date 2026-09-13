package service

import (
	"fmt"
	"net"
	"net/netip"
)

// The tunnel steps aside while its own configuration is connected somewhere
// else on this machine.
//
// A WireGuard server keeps one session and one endpoint per client key. Two
// clients using the same key, typically the AmneziaVPN app and AWGSocks started
// from the same exported .conf, take that session from each other on every
// handshake: whichever handshakes last receives the traffic, the other one
// stalls until it handshakes again, and the two keep trading it. When the other
// client is a system wide VPN, every program on the machine loses its
// connection every few seconds, including the ones that never touch the proxy.
//
// There is no protocol message that says "this key is in use elsewhere", but
// there is a reliable local sign. The server gives every client key its own
// tunnel address, the .conf carries it on the Address line, and a system wide
// client assigns it to the Windows adapter it creates. AWGSocks never does:
// its network stack lives inside the process and appears as no adapter. So a
// Windows adapter holding one of the tunnel's own addresses means the same
// configuration is connected through another client.

// hostAddress is one unicast address assigned to a Windows network adapter.
type hostAddress struct {
	Adapter string
	Addr    netip.Addr
}

func (h hostAddress) String() string {
	return fmt.Sprintf("%q (%s)", h.Adapter, h.Addr)
}

// hostAddresses reads the addresses of the adapters that are up. It is a
// variable so the tests in this package can replace it: their configuration
// uses a common default tunnel address, which a VPN connected on the machine
// running them may well hold.
var hostAddresses = systemHostAddresses

func systemHostAddresses() ([]hostAddress, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []hostAddress
	for _, ifc := range ifaces {
		// An adapter that is down carries no traffic, so it cannot be taking
		// the session from anyone, whatever addresses it still lists.
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			out = append(out, hostAddress{Adapter: ifc.Name, Addr: ip.Unmap()})
		}
	}
	return out, nil
}

// configConflict returns the first adapter address that is one of the
// tunnel's own addresses.
func configConflict(tunnel []netip.Prefix, host []hostAddress) (hostAddress, bool) {
	for _, p := range tunnel {
		want := p.Addr().Unmap()
		if !want.IsValid() || want.IsUnspecified() || want.IsLoopback() {
			continue
		}
		for _, h := range host {
			if h.Addr == want {
				return h, true
			}
		}
	}
	return hostAddress{}, false
}
