package tlscert

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func TestCreatesOnceThenReusesTheSameCertificate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")

	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}

	// A changing fingerprint would make the browser warn again on every restart.
	if Fingerprint(first) != Fingerprint(second) {
		t.Error("a second call produced a different certificate")
	}
	if !regexp.MustCompile(`^([0-9A-F]{2}:){31}[0-9A-F]{2}$`).MatchString(Fingerprint(first)) {
		t.Errorf("fingerprint %q is not in AB:CD:... form", Fingerprint(first))
	}
}

func TestCertificateIsUsableAndKeyIsPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	cert, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Errorf("certificate does not cover localhost: %v", err)
	}
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("certificate does not cover 127.0.0.1: %v", err)
	}
	if lifetime := leaf.NotAfter.Sub(leaf.NotBefore); lifetime > 826*24*time.Hour {
		t.Errorf("lifetime %v exceeds what Apple devices accept", lifetime)
	}

	info, err := os.Stat(filepath.Join(dir, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file permissions = %o, want 600", perm)
	}
}

func TestUnreadableCertificateIsReplaced(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, certFile), []byte("damaged"), 0o644); err != nil {
		t.Fatal(err)
	}

	second, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("a damaged certificate file should be replaced, got: %v", err)
	}
	if Fingerprint(first) == Fingerprint(second) {
		t.Error("damaged certificate was not replaced")
	}
}
