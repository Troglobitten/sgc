package sshkeys

import (
	"errors"
	"strings"
	"testing"
)

// Public keys made for these tests with ssh-keygen; their private halves
// were deleted at once. The fingerprints are the ones ssh-keygen printed, so
// the tests check this package against OpenSSH itself.
const (
	ed25519Key  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID25i1+d/VGOmeRQ2ZPpnryBGMe/B28pdc623ONJVCV1"
	ed25519Sum  = "SHA256:ZcQJrTJFZ1DO2xgEpCKluYro6G3ehPZvDrs/oGfuJG4"
	ecdsa256Key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPVreq0eMFJTk9zDYInx848m3SGkcPGC46O0EGtnxAkhAUhOrarhMEkCuCA+xK+1fKOcPQ50YCVidQ5ot1V8KWA="
	ecdsa256Sum = "SHA256:EK9YSxYni4LEMyR3f3L7KNizY7VbSPpGiC2WRXdlGH0"
	ecdsa384Key = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBGGPCgMGAqunKRhQ3mnknfV5JpFV4mXz6bgSYos21+XLS0NKkURGj+4s5z7cSHLB2ujNd9As/zZCdAe9UtMg0yyOk51fWpHMviWRlGPCTMDZ9B3Tnc41EM0WlL7Mz4+u0g=="
	ecdsa384Sum = "SHA256:4TmHzsFPM1qAJcW9H40mwLnEN1IItW/2y1qBLztWLns"
	rsa3072Key  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCpqgYBMlEGoUWY42eBxkmfYZ2iFROoWIW/vFjWA0Ybl2bw2/qmQcuZhDf01clIBoLFMdOdANKSahr6ggqXmLQv9vKHrM+FHuysUwYioPWWeQIOEOYW4RFgKBuz+K1x6YY/LBGTujlwG6MZuWyt3xZCChXIW/ftUKjwolLwLiwwnHsgZQDxkQDaQXhstQjkMTLX+bKkZkU2MQQ3B1BNiwGW3iZ4cttmUF+w9nUlJZ+jYTrHFf0CFAUFkUgWmqvYt8GJ67p1dTfD6IYQLBdixLAuN9gKPDOsZ+dU4QdOJdyvaA3BgNFK2hMVxnizyN1Wa5RGK6C/UGGflsy7HRBRhf5Y0fT35pdVMB43/KxsNHf6vwlR9r2e7QDfbctk6Y7TR8v/PeKeVi/umw76UeRWT6/7FG+aTCHEIHygzclgCdH5Q+ERzAP2ydLVhGtfsD4I5b1ATiQPrapjm0Z4Yl7gk5JgQsN8umJXxHmtK9iWEkWNeTpxIyyx4HSZcU6TCXzFYzM="
	rsa3072Sum  = "SHA256:551M/cMBMr8FldF3jWJLPzmzuXNkDi6UibzodJRWjX4"
	rsa1024Key  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDQqlsHvXJzlqy4QELdjUfJXutOTKMfT3zpN1TvD+cpbrqO25duYJsH8RQJd6YrBU/u7HcNhW/HMlnZjOlH+75hztx9jtoCWjSFQRs9f9WnKzPI1gp34icupvD16tqv5zU125f7egC+MYApzBz70WH9ggKO9AmVbPybOCEN+ng0DQ=="
)

func TestParseAcceptsWhatOpenSSHMakes(t *testing.T) {
	cases := []struct {
		name, pasted, fingerprint, kind, comment string
	}{
		{"ed25519 with comment", ed25519Key + " alex@laptop", ed25519Sum, "ED25519", "alex@laptop"},
		{"ed25519 alone", ed25519Key, ed25519Sum, "ED25519", ""},
		{"space and a line break around it", "  \n" + ed25519Key + " alex@laptop\r\n", ed25519Sum, "ED25519", "alex@laptop"},
		{"a comment with spaces", ed25519Key + " my work laptop", ed25519Sum, "ED25519", "my work laptop"},
		{"ecdsa 256", ecdsa256Key + " alex@laptop", ecdsa256Sum, "ECDSA", "alex@laptop"},
		{"ecdsa 384", ecdsa384Key, ecdsa384Sum, "ECDSA", ""},
		{"rsa 3072", rsa3072Key + " alex@old-gateway", rsa3072Sum, "RSA", "alex@old-gateway"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key, comment, err := Parse(c.pasted)
			if err != nil {
				t.Fatal(err)
			}
			if key.Fingerprint != c.fingerprint {
				t.Errorf("fingerprint %s, OpenSSH says %s", key.Fingerprint, c.fingerprint)
			}
			if key.Kind() != c.kind || comment != c.comment {
				t.Errorf("kind %q, comment %q", key.Kind(), comment)
			}
			// What gets written is the key alone, whatever came with it.
			if fields := strings.Fields(key.Line()); len(fields) != 2 || fields[0] != key.Type || fields[1] != key.Blob {
				t.Errorf("line = %q", key.Line())
			}
			if !strings.HasPrefix(c.pasted[strings.Index(c.pasted, key.Type):], key.Line()) {
				t.Errorf("line %q is not the pasted key", key.Line())
			}
			// And it survives being stored and checked again.
			again, err := Check(key)
			if err != nil || again != key {
				t.Errorf("Check: %+v, %v", again, err)
			}
		})
	}
}

func TestParseRefusesEverythingElse(t *testing.T) {
	blob := strings.Fields(ed25519Key)[1]
	cases := map[string]string{
		"nothing":                       "",
		"just text":                     "please let me in",
		"a kind without a key":          "ssh-ed25519",
		"a key that is not base64":      "ssh-ed25519 !!!notbase64!!!",
		"a cut-off key":                 "ssh-ed25519 " + blob[:20],
		"a kind that does not match":    "ssh-rsa " + blob,
		"a login option in front":       `command="/bin/sh" ` + ed25519Key,
		"a source restriction in front": `from="203.0.113.5" ` + ed25519Key,
		"several options":               `no-pty,command="x" ` + ed25519Key,
		"two keys":                      ed25519Key + "\n" + ecdsa256Key,
		"a second line of anything":     ed25519Key + "\nPermitRootLogin yes",
		"an old DSA key":                "ssh-dss AAAAB3NzaC1kc3MAAACBAJ",
		"a certificate":                 "ssh-ed25519-cert-v01@openssh.com " + blob,
		"an RSA key that is too short":  rsa1024Key,
		"far too long":                  ed25519Key + " " + strings.Repeat("x", 9000),
		"a private key":                 "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----",
		"the start of a private key":    "-----BEGIN RSA PRIVATE KEY-----",
		"a known_hosts line":            "gateway.example ssh-ed25519 " + blob,
		"a null byte":                   ed25519Key + "\x00",
		"a tab in place of the space":   strings.Replace(ed25519Key, " ", "\t", 1),
	}
	for name, pasted := range cases {
		if key, _, err := Parse(pasted); err == nil {
			t.Errorf("%s: accepted as %+v", name, key)
		}
	}
}

func TestParseSaysWhatIsWrong(t *testing.T) {
	_, _, err := Parse("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----")
	if !errors.Is(err, ErrPrivateKey) {
		t.Errorf("a private key: %v", err)
	}
	if _, _, err := Parse(rsa1024Key); err == nil || !strings.Contains(err.Error(), "1024 bits") {
		t.Errorf("a short RSA key: %v", err)
	}
	if _, _, err := Parse(`command="x" ` + ed25519Key); err == nil || !strings.Contains(err.Error(), "without options") {
		t.Errorf("a key with options: %v", err)
	}
}

func TestCheckRecomputesInsteadOfBelieving(t *testing.T) {
	key, _, err := Parse(ed25519Key)
	if err != nil {
		t.Fatal(err)
	}

	// A fingerprint that does not belong to the key is replaced by the real one.
	lying := key
	lying.Fingerprint = ecdsa256Sum
	checked, err := Check(lying)
	if err != nil || checked.Fingerprint != ed25519Sum {
		t.Errorf("Check kept a wrong fingerprint: %+v, %v", checked, err)
	}

	// Parts that are not a key are refused, including ones that would add a
	// second line or an option to the file they are written into.
	for name, bad := range map[string]Key{
		"kind and key do not match": {Type: "ssh-rsa", Blob: key.Blob},
		"a line break in the key":   {Type: key.Type, Blob: key.Blob + "\nssh-ed25519 " + key.Blob},
		"a line break in the kind":  {Type: "ssh-ed25519\nPermitRootLogin yes\nssh-ed25519", Blob: key.Blob},
		"an option as the kind":     {Type: `command="x" ssh-ed25519`, Blob: key.Blob},
		"a comment after the key":   {Type: key.Type, Blob: key.Blob + " extra"},
		"empty":                     {},
	} {
		if got, err := Check(bad); err == nil {
			t.Errorf("%s: accepted as %+v", name, got)
		}
	}
}
