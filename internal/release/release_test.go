package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"testing"

	"github.com/Troglobitten/sgc"
)

// The files in testdata are the real SHA256SUMS and SHA256SUMS.sig published
// with SGC 0.4.0, signed on GitHub with openssl. This test is what proves
// that Go's verification accepts exactly what the release workflow produces.
func TestAcceptsARealPublishedRelease(t *testing.T) {
	checksums, err := os.ReadFile("testdata/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	signature, err := os.ReadFile("testdata/SHA256SUMS.sig")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParsePublicKeys(sgc.ReleasePublicKeyPEM())
	if err != nil {
		t.Fatalf("built-in release key: %v", err)
	}

	if err := VerifyChecksums(checksums, signature, keys); err != nil {
		t.Fatalf("the published 0.4.0 checksum list was rejected: %v", err)
	}

	// One changed character anywhere in the list must break the signature.
	tampered := bytes.Replace(checksums, []byte("0.4.0"), []byte("0.4.1"), 1)
	if err := VerifyChecksums(tampered, signature, keys); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered list: err = %v, want ErrBadSignature", err)
	}
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func checksumLine(name string, data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) + "  " + name + "\n"
}

func TestSignatureFromAnotherKeyIsRejected(t *testing.T) {
	trusted, _ := newKey(t)
	_, attacker := newKey(t)
	checksums := []byte(checksumLine("sgc-1.0.0-linux-arm64.tar.gz", []byte("archive")))

	signature := ed25519.Sign(attacker, checksums)

	if err := VerifyChecksums(checksums, signature, []ed25519.PublicKey{trusted}); !errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want ErrBadSignature", err)
	}
}

func TestAnyTrustedKeyIsEnough(t *testing.T) {
	// During a key change, releases are signed with the new key while
	// installations still trust both.
	oldKey, _ := newKey(t)
	newPublic, newPrivate := newKey(t)
	checksums := []byte("anything\n")

	signature := ed25519.Sign(newPrivate, checksums)

	if err := VerifyChecksums(checksums, signature, []ed25519.PublicKey{oldKey, newPublic}); err != nil {
		t.Errorf("signature by the second trusted key was rejected: %v", err)
	}
}

func TestVerifyFile(t *testing.T) {
	archive := []byte("the real archive")
	name := ArchiveName("1.2.3", "arm64")
	checksums := []byte(
		checksumLine("sgc-1.2.3-linux-amd64.tar.gz", []byte("other architecture")) +
			checksumLine(name, archive) +
			checksumLine("install.sh", []byte("installer")))

	if err := VerifyFile(checksums, name, archive); err != nil {
		t.Errorf("genuine file rejected: %v", err)
	}
	if err := VerifyFile(checksums, name, append([]byte{}, append(archive, 'x')...)); !errors.Is(err, ErrBadChecksum) {
		t.Errorf("altered file: err = %v, want ErrBadChecksum", err)
	}
	// An older release's archive, even though its own checksum would be
	// genuine, is not in this list under the new name.
	if err := VerifyFile(checksums, ArchiveName("1.2.4", "arm64"), archive); !errors.Is(err, ErrNotListed) {
		t.Errorf("unlisted name: err = %v, want ErrNotListed", err)
	}
	// A file from the list presented under another listed name must not pass.
	if err := VerifyFile(checksums, "install.sh", archive); !errors.Is(err, ErrBadChecksum) {
		t.Errorf("wrong name: err = %v, want ErrBadChecksum", err)
	}
}

func TestParsePublicKeys(t *testing.T) {
	first, _ := newKey(t)
	second, _ := newKey(t)
	encode := func(key ed25519.PublicKey) []byte {
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	}

	keys, err := ParsePublicKeys(append(encode(first), encode(second)...))
	if err != nil || len(keys) != 2 || !keys[0].Equal(first) || !keys[1].Equal(second) {
		t.Errorf("two keys: got %d keys, err %v", len(keys), err)
	}
	if _, err := ParsePublicKeys([]byte("not a key")); err == nil {
		t.Error("garbage was accepted as a key file")
	}
}

func TestVersions(t *testing.T) {
	for _, bad := range []string{"", "1.2", "1.2.3.4", "v1.2.3", "1.2.3-beta", "01.2.3", "1.2.x", "1.2.3 ", "1.2.3;reboot", "../1.2.3", "1.2.3\n", "9999999.0.0"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Errorf("ParseVersion(%q) was accepted", bad)
		}
	}

	parse := func(s string) Version {
		v, err := ParseVersion(s)
		if err != nil {
			t.Fatalf("ParseVersion(%q): %v", s, err)
		}
		if v.String() != s {
			t.Errorf("%q round-trips as %q", s, v.String())
		}
		return v
	}
	newer := [][2]string{{"0.5.1", "0.5.0"}, {"0.6.0", "0.5.9"}, {"1.0.0", "0.99.99"}, {"0.10.0", "0.9.0"}}
	for _, pair := range newer {
		a, b := parse(pair[0]), parse(pair[1])
		if !a.NewerThan(b) {
			t.Errorf("%s should be newer than %s", a, b)
		}
		if b.NewerThan(a) {
			t.Errorf("%s should not be newer than %s", b, a)
		}
	}
	if same := parse("1.2.3"); same.NewerThan(same) {
		t.Error("a version is not newer than itself")
	}
}
