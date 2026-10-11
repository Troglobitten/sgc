// Package tlscert provides the self-signed certificate SGC uses until it has
// a real one from Let's Encrypt.
//
// Even the very first setup screen must be encrypted: it carries the admin
// password, and later the DNS provider's API key. A self-signed certificate
// gives encryption; the installer prints its fingerprint so the owner can
// check that the browser is talking to their gateway and not something else.
package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	certFile = "selfsigned-cert.pem"
	keyFile  = "selfsigned-key.pem"

	// Apple devices reject certificates valid for more than 825 days, even
	// ones the user explicitly accepted.
	validity = 825 * 24 * time.Hour
	// A certificate this close to expiry is replaced at the next start.
	renewBefore = 30 * 24 * time.Hour
)

// LoadOrCreate returns the certificate stored in dir, creating a new one if
// there is none, it cannot be read, or it is about to expire.
func LoadOrCreate(dir string) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, certFile), filepath.Join(dir, keyFile)

	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil &&
			time.Until(leaf.NotAfter) > renewBefore {
			cert.Leaf = leaf
			return cert, nil
		}
	}
	return create(certPath, keyPath)
}

// Fingerprint returns the SHA-256 fingerprint in the form browsers show it:
// AB:CD:EF:...
func Fingerprint(cert tls.Certificate) string {
	sum := sha256.Sum256(cert.Certificate[0])
	hexed := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(hexed); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hexed[i : i+2])
	}
	return b.String()
}

func create(certPath, keyPath string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate certificate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate certificate serial: %w", err)
	}

	hostname, _ := os.Hostname()
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "SGC self-signed (" + hostname + ")"},
		NotBefore:             now.Add(-time.Hour), // tolerate a clock that is slightly behind
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           localAddresses(),
	}
	if hostname != "" {
		template.DNSNames = append(template.DNSNames, hostname)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("encode certificate key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate folder: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	// The key first and readable by the owner only; if writing the
	// certificate then fails, the next start simply creates a fresh pair.
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, fmt.Errorf("store certificate key: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, fmt.Errorf("store certificate: %w", err)
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// localAddresses lists the addresses this machine can be reached at, so the
// certificate matches when the UI is opened by IP address.
func localAddresses() []net.IP {
	ips := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && !ipnet.IP.IsLinkLocalUnicast() {
			ips = append(ips, ipnet.IP)
		}
	}
	return ips
}
