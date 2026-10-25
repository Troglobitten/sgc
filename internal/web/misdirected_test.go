package web

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A request over a connection opened for another name is sent back with
// 421, so that the browser asks again over a connection of its own; every
// other request passes.
func TestARequestForAnotherNameOnTheConnectionIsSentBack(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := rejectMisdirected(next)
	for _, c := range []struct {
		name, host, sni string
		tls             bool
		want            int
	}{
		{"a service's request on SGC's connection", "web.domain.tld", "sgc.domain.tld", true, http.StatusMisdirectedRequest},
		{"SGC's own name", "sgc.domain.tld", "sgc.domain.tld", true, http.StatusNoContent},
		{"with a port", "sgc.domain.tld:8443", "sgc.domain.tld", true, http.StatusNoContent},
		{"in other letters, with the final dot", "SGC.Domain.TLD.", "sgc.domain.tld", true, http.StatusNoContent},
		{"by address: no name in the handshake", "192.168.1.10:8443", "", true, http.StatusNoContent},
		{"plain http (the proxy's side, development)", "web.domain.tld", "", false, http.StatusNoContent},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = c.host
		if c.tls {
			r.TLS = &tls.ConnectionState{ServerName: c.sni}
		} else {
			r.TLS = nil
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s: %d, want %d", c.name, w.Code, c.want)
		}
	}
}

// Both doors: the page itself checks every request, and the proxy's
// "misdirected" router sends SGC's own name, asked over a connection opened
// for a service, to the internal answer.
func TestBothSidesAnswerMisdirectedRequests(t *testing.T) {
	s, _ := gateServer(t)
	r := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	r.Host = "web.domain.tld"
	r.TLS = &tls.ConnectionState{ServerName: "sgc.domain.tld"}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusMisdirectedRequest {
		t.Errorf("the page: status %d, want 421", w.Code)
	}

	r = httptest.NewRequest(http.MethodGet, "/proxy-misdirected", nil)
	r.Host = "sgc.domain.tld"
	w = httptest.NewRecorder()
	s.InternalHandler().ServeHTTP(w, r)
	if w.Code != http.StatusMisdirectedRequest {
		t.Errorf("the proxy's side: status %d, want 421", w.Code)
	}
}
