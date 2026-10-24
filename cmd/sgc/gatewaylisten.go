package main

import (
	"net"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// withVisitorAddress wraps the listener for the gateway's name
// (proxy.SGCGateway): Traefik passes these connections on unopened and puts a
// PROXY protocol header in front, which says who the visitor is. Every
// connection must start with one, and only from this machine; the
// connection's address is then the visitor's, so the sign-in's lock-out, the
// history and "inside" see the visitor and not Traefik.
//
// A connection without the header fails at its first read (the TLS
// handshake) and is closed. One from elsewhere is closed at once; it cannot
// happen while the listener is on 127.0.0.1, which serve.go insists on.
func withVisitorAddress(l net.Listener) net.Listener {
	return &proxyproto.Listener{
		Listener:          l,
		ReadHeaderTimeout: 10 * time.Second,
		ConnPolicy: func(o proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			if tcp, ok := o.Upstream.(*net.TCPAddr); ok && tcp.IP.IsLoopback() {
				return proxyproto.REQUIRE, nil
			}
			// Closes this connection and goes on listening.
			return proxyproto.REQUIRE, proxyproto.ErrInvalidUpstream
		},
	}
}
