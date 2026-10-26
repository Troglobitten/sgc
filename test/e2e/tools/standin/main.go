// Command sgc-standin plays the parts of the outside world that the
// whole-machine test must not touch for real:
//
//   - Zone.eu: its API (one account with one domain, accepting one username
//     and API key) and its name servers, which show the TXT records made
//     through that API;
//   - Let's Encrypt: its certificate authority and its test authority, both
//     played by Pebble, which look for proofs at those name servers;
//   - the service that tells the home's public address (/ip on the API's
//     address: a made-up address of the documentation range);
//   - a WebDAV folder for backups, and an ntfy server that keeps what it
//     was sent (both plain http, this machine only).
//
// It is built by the test-release scripts, copied to the test machine and
// started there by cases.sh. It is not part of any release.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/net/webdav"

	"github.com/Troglobitten/sgc/internal/certcontrol/acmetest"
	"github.com/Troglobitten/sgc/internal/iconpack"
	"github.com/Troglobitten/sgc/internal/services"
	"github.com/Troglobitten/sgc/internal/zone/zonetest"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9100", "address of Zone.eu's API")
	dnsAddress := flag.String("dns", "127.0.0.1:9153", "address of Zone.eu's name servers")
	trial := flag.String("trial", "127.0.0.1:9143", "address of the test authority")
	authority := flag.String("authority", "127.0.0.1:9144", "address of the certificate authority")
	state := flag.String("state", "", "folder for the certificate the two authorities show")
	onlyCertificate := flag.Bool("make-certificate", false, "make that certificate if it is not there, then end")
	username := flag.String("username", "", "the ZoneID username the account accepts")
	apiKey := flag.String("api-key", "", "the API key the account accepts")
	domain := flag.String("domain", "domain.tld", "the domain whose DNS zone is in the account")
	publicIP := flag.String("public-ip", "203.0.113.7", "the address /ip answers with")
	dav := flag.String("webdav", "127.0.0.1:9300", "address of the WebDAV folder")
	ntfy := flag.String("ntfy", "127.0.0.1:9400", "address of the ntfy server")
	icons := flag.String("icons", "127.0.0.1:9500", "address where the icon pack is published")
	lists := flag.String("lists", "127.0.0.1:9600", "address where FireHOL's and DB-IP's lists are published")
	flag.Parse()

	fail := func(err error) {
		fmt.Fprintln(os.Stderr, "sgc-standin:", err)
		os.Exit(1)
	}
	if *state == "" {
		fail(errors.New("--state is needed"))
	}
	certFile, keyFile, err := ensureCertificate(*state)
	if err != nil {
		fail(err)
	}
	if *onlyCertificate {
		fmt.Println(certFile)
		return
	}
	if *username == "" || *apiKey == "" {
		fail(errors.New("--username and --api-key are needed"))
	}

	zone := zonetest.New(*username, *apiKey, *domain)
	dnsInUse, _, err := zone.ListenDNS(*dnsAddress)
	if err != nil {
		fail(err)
	}
	failed := make(chan error, 5)
	serve := func(address string, handler http.Handler, tls bool) {
		server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
		if tls {
			failed <- server.ListenAndServeTLS(certFile, keyFile)
		} else {
			failed <- server.ListenAndServe()
		}
	}
	api := http.NewServeMux()
	api.Handle("/v2/", zone)
	api.HandleFunc("GET /ip", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, *publicIP) })
	go serve(*listen, api, false)
	// The WebDAV folder and what ntfy was sent live under the state folder.
	davDir := filepath.Join(*state, "webdav")
	os.MkdirAll(davDir, 0o755)
	go serve(*dav, &webdav.Handler{FileSystem: webdav.Dir(davDir), LockSystem: webdav.NewMemLS()}, false)
	go serve(*ntfy, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		f, err := os.OpenFile(filepath.Join(*state, "ntfy.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			fmt.Fprintf(f, "%s %s\n", r.Header.Get("Authorization"), body)
			f.Close()
		}
		w.Write([]byte(`{"id":"standin"}`))
	}), false)
	// The icon pack, as published on GitHub: a small one, made at the start
	// by SGC's own builder, with an icon for the test's service "web".
	packDir := filepath.Join(*state, "icons")
	if err := makeIconPack(packDir); err != nil {
		fail(err)
	}
	go serve(*icons, http.StripPrefix("/icons/", http.FileServer(http.Dir(packDir))), false)
	// FireHOL's and DB-IP's lists, as files cases.sh writes into the state
	// folder (firehol/<level>.netset, dbip/dbip-country-lite-<month>.csv.gz),
	// so that the test decides which made-up addresses they name.
	listsDir := filepath.Join(*state, "lists")
	os.MkdirAll(listsDir, 0o755)
	go serve(*lists, http.FileServer(http.Dir(listsDir)), false)
	// Two authorities, as with Let's Encrypt: what SGC tries with the first
	// it then asks of the second.
	go serve(*trial, acmetest.New(dnsInUse), true)
	go serve(*authority, acmetest.New(dnsInUse), true)
	fmt.Printf("standing in for Zone.eu (API on %s, name servers on %s, zone %s) and for Let's Encrypt (test authority on %s, authority on %s)\n",
		*listen, dnsInUse, *domain, *trial, *authority)
	fail(<-failed)
}

// makeIconPack builds a pack of three made-up icons into dir, the way
// .github/workflows/icons.yml builds the real one from the collection.
func makeIconPack(dir string) error {
	source, err := os.MkdirTemp("", "sgc-standin-icons")
	if err != nil {
		return err
	}
	defer os.RemoveAll(source)
	os.MkdirAll(filepath.Join(source, "png"), 0o755)
	os.WriteFile(filepath.Join(source, "metadata.json"), []byte(`{"web": {"aliases": ["Web Page"]}}`), 0o644)
	os.WriteFile(filepath.Join(source, "LICENSE"), []byte("made-up licence of the stand-in pack\n"), 0o644)
	for name, c := range map[string]color.NRGBA{"web": {200, 30, 30, 255}, "media": {30, 30, 200, 255}, "other": {30, 160, 30, 255}} {
		img := image.NewNRGBA(image.Rect(0, 0, 48, 48))
		for y := range 48 {
			for x := range 48 {
				img.Set(x, y, c)
			}
		}
		var b bytes.Buffer
		png.Encode(&b, img)
		os.WriteFile(filepath.Join(source, "png", name+".png"), b.Bytes(), 0o644)
	}
	os.RemoveAll(dir)
	_, err = iconpack.Build(source, "5715d1f00000000000000000000000000000000a", dir, time.Now(), services.Redraw)
	return err
}

// ensureCertificate makes the certificate the two authorities show to
// whoever connects (not what they issue), unless it is there already. SGC is
// told to trust it, so it has to be the same from start to start.
func ensureCertificate(dir string) (certFile, keyFile string, err error) {
	certFile, keyFile = filepath.Join(dir, "authority-cert.pem"), filepath.Join(dir, "authority-key.pem")
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			return certFile, keyFile, nil
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "sgc-standin"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	// The certificate is for SGC to read; the key is this program's alone.
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil
}
