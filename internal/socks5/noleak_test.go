package socks5

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// allowedNetIdents are the identifiers from the standard net package that the
// SOCKS5 server is permitted to use. They are all either type names or
// address-parsing helpers. Anything that can open an outbound connection or
// perform a name lookup is absent on purpose.
var allowedNetIdents = map[string]bool{
	// Types and helpers, none of which can open a connection.
	"Conn":                true,
	"PacketConn":          true,
	"Listener":            true,
	"Error":               true,
	"Addr":                true,
	"UDPAddr":             true,
	"UDPConn":             true,
	"IPv4":                true,
	"UDPAddrFromAddrPort": true,
	"SplitHostPort":       true,
	"JoinHostPort":        true,

	// Bind operations. These create a listening socket, they never dial out.
	// Both are called exactly once each, with a loopback address, and
	// TestListenersAreLoopbackOnly checks that.
	"Listen":    true,
	"ListenUDP": true,
}

// forbiddenImports must never appear in this package: each of them can reach
// the network over the default Windows path, bypassing the AmneziaWG tunnel.
var forbiddenImports = []string{
	"net/http",
	"crypto/tls",
	"golang.org/x/net/proxy",
}

// TestNoDirectNetworkEgress is the structural guarantee behind the no-fallback
// requirement: if someone later adds net.Dial to this package, this test fails.
//
// Bind calls are allowed because a listening socket cannot reach a remote
// destination on its own. The one case where that is not quite true, a bound
// UDP socket sending to an arbitrary address, is closed separately by
// loopbackPacketConn and TestUDPRelayRefusesNonLoopbackReply.
//
// Test files are excluded, because a test legitimately needs a real socket to
// stand in for a remote server.
func TestNoDirectNetworkEgress(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("could not read the package directory: %v", err)
	}

	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("could not parse %s: %v", name, err)
		}
		checked++

		for _, imp := range file.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			for _, bad := range forbiddenImports {
				if path == bad {
					t.Errorf("%s: forbidden import %q: the SOCKS5 package may only use the injected tunnel dialer",
						name, path)
				}
			}
		}

		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != "net" {
				return true
			}
			if !allowedNetIdents[sel.Sel.Name] {
				pos := fset.Position(sel.Pos())
				t.Errorf("%s: net.%s is forbidden. SOCKS5 egress may only go through the AmneziaWG tunnel; "+
					"opening a direct socket would leak whenever the tunnel is down", pos, sel.Sel.Name)
			}
			return true
		})
	}

	if checked == 0 {
		t.Fatal("no source file was inspected")
	}
}
