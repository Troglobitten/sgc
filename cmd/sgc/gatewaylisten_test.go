package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// What SGC's page sees on the listener for the gateway's name: the visitor's
// address from Traefik's PROXY header, and nothing at all without one.
func TestTheGatewayListenerSeesTheVisitor(t *testing.T) {
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, r.RemoteAddr)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go server.Serve(withVisitorAddress(plain))
	t.Cleanup(func() { server.Close() })
	address := plain.Addr().String()

	ask := func(header bool) (string, error) {
		conn, err := net.DialTimeout("tcp", address, 5*time.Second)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if header {
			visitor := &net.TCPAddr{IP: net.ParseIP("192.168.1.23"), Port: 51515}
			if _, err := proxyproto.HeaderProxyFromAddrs(2, visitor, conn.RemoteAddr()).WriteTo(conn); err != nil {
				return "", err
			}
		}
		fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: sgc.domain.tld\r\nConnection: close\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		var body strings.Builder
		_, err = bufio.NewReader(resp.Body).WriteTo(&body)
		return body.String(), err
	}

	got, err := ask(true)
	if err != nil {
		t.Fatal(err)
	}
	if got != "192.168.1.23:51515" {
		t.Errorf("with the header SGC sees %q, want the visitor 192.168.1.23:51515", got)
	}
	if got, err := ask(false); err == nil {
		t.Errorf("without the header the request was answered (%q)", got)
	}
	// One refused connection does not stop the listener.
	if got, err := ask(true); err != nil || got != "192.168.1.23:51515" {
		t.Errorf("after a refused connection: %q, %v", got, err)
	}
}
