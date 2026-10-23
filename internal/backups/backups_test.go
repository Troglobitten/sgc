package backups

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/webdav"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/backup"
	"github.com/Troglobitten/sgc/internal/store"
)

func service(t *testing.T) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(context.Background(), filepath.Join(dir, "sgc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	// An export without an admin account is refused when restored.
	if _, err := db.Exec("INSERT INTO admin (id, username, password_hash, created_at) VALUES (1, 'alex', 'x', 0)"); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 10, 23, 3, 30, 0, 0, time.UTC)
	s := New(Config{DB: db, Audit: audit.New(db), Hostname: "old-gateway", Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { clock = clock.Add(time.Second); return clock },
		Export: func(ctx context.Context, w io.Writer, key string) (*backup.Manifest, error) {
			return backup.ExportToKey(ctx, db, w, key, backup.Source{SGCVersion: "0.0.0", Hostname: "old-gateway"}, filepath.Join(dir, "tmp"))
		}})
	return s, dir
}

func TestWebDAV(t *testing.T) {
	folder := t.TempDir()
	server := httptest.NewServer(&webdav.Handler{FileSystem: webdav.Dir(folder), LockSystem: webdav.NewMemLS()})
	defer server.Close()
	s, dir := service(t)
	ctx := context.Background()
	secret, err := s.NewKey(ctx, "alex", "")
	if err != nil || !strings.HasPrefix(secret, "AGE-SECRET-KEY-1") {
		t.Fatalf("key: %q, %v", secret, err)
	}
	settings := Settings{Enabled: true, Target: Target{Kind: KindWebDAV, URL: server.URL + "/"}, Time: "03:30", Keep: 2}
	if err := s.SetSettings(ctx, "alex", "", settings); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := s.BackUp(ctx, "alex"); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(folder)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if len(names) != 2 || !strings.HasPrefix(names[0], "sgc-backup-old-gateway-") {
		t.Fatalf("on the target: %v", names)
	}
	// The newest opens with the secret half, as a restore would.
	data, _ := os.ReadFile(filepath.Join(folder, names[1]))
	if _, err := backup.Stage(ctx, bytes.NewReader(data), secret, filepath.Join(dir, "restore")); err != nil {
		t.Errorf("the backup does not open with the backup key: %v", err)
	}
	if _, err := backup.Stage(ctx, bytes.NewReader(data), "a passphrase that is wrong", filepath.Join(dir, "restore2")); err == nil {
		t.Error("the backup opens with anything")
	}
	status, _ := s.Status(ctx)
	if status.Last == nil || !status.Last.OK || status.Overdue || status.Settings.Target.Password != "" {
		t.Errorf("status: %+v", status)
	}
}

func TestWhatIsRefused(t *testing.T) {
	s, _ := service(t)
	ctx := context.Background()
	for name, settings := range map[string]Settings{
		"no key yet":         {Enabled: true, Target: Target{Kind: KindWebDAV, URL: "https://nas.home/dav"}, Time: "03:30", Keep: 3},
		"an odd time":        {Target: Target{Kind: KindWebDAV, URL: "https://nas.home/dav"}, Time: "25:00", Keep: 3},
		"climbing out":       {Target: Target{Kind: KindSMB, Host: "nas", Share: "backups", Path: "../etc"}, Time: "03:30", Keep: 3},
		"a share with slash": {Target: Target{Kind: KindSMB, Host: "nas", Share: "a/b"}, Time: "03:30", Keep: 3},
		"ftp":                {Target: Target{Kind: KindWebDAV, URL: "ftp://nas.home"}, Time: "03:30", Keep: 3},
		"keep none":          {Target: Target{Kind: KindWebDAV, URL: "https://nas.home/dav"}, Time: "03:30", Keep: 0 - 1},
	} {
		if err := s.SetSettings(ctx, "alex", "", settings); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// sftpServer is an SFTP server for one test, on a free port.
func sftpServer(t *testing.T, root string) (string, ssh.PublicKey) {
	t.Helper()
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(private)
	config := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		if c.User() == "alex" && string(pass) == "a-made-up-password" {
			return nil, nil
		}
		return nil, errors.New("no")
	}}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					channel, requests, _ := ch.Accept()
					go func() {
						for req := range requests {
							req.Reply(req.Type == "subsystem" && string(req.Payload[4:]) == "sftp", nil)
							if req.Type == "subsystem" {
								server, _ := sftp.NewServer(channel, sftp.WithServerWorkingDirectory(root))
								server.Serve()
								channel.Close()
							}
						}
					}()
				}
			}()
		}
	}()
	return listener.Addr().String(), signer.PublicKey()
}

func TestSFTPAndItsKey(t *testing.T) {
	root := t.TempDir()
	address, hostKey := sftpServer(t, root)
	host, port, _ := net.SplitHostPort(address)
	s, _ := service(t)
	ctx := context.Background()
	target := Target{Kind: KindSFTP, Host: host, Username: "alex", Password: "a-made-up-password"}
	target.Port, _ = strconv.Atoi(port)
	// Not confirmed yet: the test says which key the server shows.
	var unknown *ErrUnknownHostKey
	if err := s.Test(ctx, target); !errors.As(err, &unknown) || unknown.Fingerprint != Fingerprint(hostKey) {
		t.Fatalf("an unconfirmed server: %v", err)
	}
	target.HostKey = unknown.Fingerprint
	if err := s.Test(ctx, target); err != nil {
		t.Fatalf("a confirmed server: %v", err)
	}
	s.NewKey(ctx, "alex", "")
	if err := s.SetSettings(ctx, "alex", "", Settings{Enabled: true, Target: target, Time: "03:30", Keep: 5}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BackUp(ctx, "alex"); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".age") {
		t.Errorf("on the server: %v", entries)
	}
	// Another key than the confirmed one is refused.
	target.HostKey = "SHA256:another"
	if err := s.Test(ctx, target); !errors.As(err, &unknown) {
		t.Errorf("another key: %v", err)
	}
}
