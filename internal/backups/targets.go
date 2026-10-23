package backups

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Kinds of target.
const (
	KindSMB    = "smb"
	KindSFTP   = "sftp"
	KindWebDAV = "webdav"
)

// Target is where backups go.
type Target struct {
	Kind string `json:"kind"`
	// SMB and SFTP: the device and its port (0: the usual one).
	Host string `json:"host"`
	Port int    `json:"port"`
	// SMB: the share; SMB and SFTP: the folder in it.
	Share string `json:"share"`
	Path  string `json:"path"`
	// WebDAV: the folder's address.
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	// SFTP: the server's key fingerprint (SHA256:…), confirmed by the
	// owner the first time. A server that shows another key is refused.
	HostKey string `json:"hostKey"`
	// WebDAV over https to a device with a self-signed certificate.
	SkipVerify bool `json:"skipVerify"`
}

// folder is a connection to a target's folder.
type folder interface {
	Put(ctx context.Context, name string, data []byte) error
	List(ctx context.Context) ([]string, error)
	Delete(ctx context.Context, name string) error
	Close() error
}

// ErrUnknownHostKey is an SFTP server whose key the owner has not
// confirmed yet; Fingerprint is what it showed.
type ErrUnknownHostKey struct{ Fingerprint string }

func (e *ErrUnknownHostKey) Error() string {
	return "the server's key " + e.Fingerprint + " is not the one confirmed"
}

func open(ctx context.Context, t Target) (folder, error) {
	switch t.Kind {
	case KindWebDAV:
		return openWebDAV(t)
	case KindSFTP:
		return openSFTP(ctx, t)
	case KindSMB:
		return openSMB(ctx, t)
	}
	return nil, errors.New("unknown kind of target")
}

// --- WebDAV --------------------------------------------------------------------------

type webdav struct {
	base   *url.URL
	t      Target
	client *http.Client
}

func openWebDAV(t Target) (folder, error) {
	base, err := url.Parse(strings.TrimSuffix(t.URL, "/") + "/")
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: t.SkipVerify}} //nolint:gosec // the owner's choice for a home device
	return &webdav{base: base, t: t, client: &http.Client{Timeout: 5 * time.Minute, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (w *webdav) do(ctx context.Context, method, name string, body io.Reader, headers map[string]string) (*http.Response, error) {
	target := w.base.ResolveReference(&url.URL{Path: url.PathEscape(name)})
	req, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, err
	}
	if w.t.Username != "" {
		req.SetBasicAuth(w.t.Username, w.t.Password)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		resp.Body.Close()
		return nil, errors.New("the WebDAV server did not accept the username and password")
	}
	return resp, nil
}

func (w *webdav) Put(ctx context.Context, name string, data []byte) error {
	resp, err := w.do(ctx, http.MethodPut, name, bytes.NewReader(data), map[string]string{"Content-Type": "application/octet-stream"})
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the WebDAV server answered %d (does the folder exist?)", resp.StatusCode)
	}
	return nil
}

type multistatus struct {
	Responses []struct {
		Href string `xml:"href"`
	} `xml:"response"`
}

func (w *webdav) List(ctx context.Context) ([]string, error) {
	resp, err := w.do(ctx, "PROPFIND", "", strings.NewReader(`<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/></d:prop></d:propfind>`),
		map[string]string{"Depth": "1", "Content-Type": "application/xml"})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMultiStatus {
		return nil, fmt.Errorf("the WebDAV server answered %d to a listing", resp.StatusCode)
	}
	var ms multistatus
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&ms); err != nil {
		return nil, err
	}
	var names []string
	for _, r := range ms.Responses {
		href, err := url.PathUnescape(r.Href)
		if err != nil {
			continue
		}
		if name := path.Base(strings.TrimSuffix(href, "/")); name != "" && !strings.HasSuffix(r.Href, "/") {
			names = append(names, name)
		}
	}
	return names, nil
}

func (w *webdav) Delete(ctx context.Context, name string) error {
	resp, err := w.do(ctx, http.MethodDelete, name, nil, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("the WebDAV server answered %d to removing %s", resp.StatusCode, name)
	}
	return nil
}

func (w *webdav) Close() error { return nil }

// --- SFTP ----------------------------------------------------------------------------

type sftpFolder struct {
	conn   *ssh.Client
	client *sftp.Client
	dir    string
}

// Fingerprint is how SGC shows an SSH key: what ssh-keygen -l shows.
func Fingerprint(key ssh.PublicKey) string { return ssh.FingerprintSHA256(key) }

func openSFTP(ctx context.Context, t Target) (folder, error) {
	port := t.Port
	if port == 0 {
		port = 22
	}
	config := &ssh.ClientConfig{
		User: t.Username,
		Auth: []ssh.AuthMethod{ssh.Password(t.Password)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if got := Fingerprint(key); got != t.HostKey {
				return &ErrUnknownHostKey{Fingerprint: got}
			}
			return nil
		},
		Timeout: 20 * time.Second,
	}
	dialer := &net.Dialer{Timeout: 20 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(t.Host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(raw, net.JoinHostPort(t.Host, strconv.Itoa(port)), config)
	if err != nil {
		raw.Close()
		var unknown *ErrUnknownHostKey
		if errors.As(err, &unknown) {
			return nil, unknown
		}
		return nil, err
	}
	conn := ssh.NewClient(c, chans, reqs)
	client, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &sftpFolder{conn: conn, client: client, dir: t.Path}, nil
}

func (f *sftpFolder) Put(_ context.Context, name string, data []byte) error {
	temporary := path.Join(f.dir, name+".part")
	out, err := f.client.Create(temporary)
	if err != nil {
		return fmt.Errorf("make the file (does the folder exist?): %w", err)
	}
	if _, err := out.Write(data); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return f.client.PosixRename(temporary, path.Join(f.dir, name))
}

func (f *sftpFolder) List(context.Context) ([]string, error) {
	entries, err := f.client.ReadDir(f.dirOrDot())
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.Mode().IsRegular() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

func (f *sftpFolder) dirOrDot() string {
	if f.dir == "" {
		return "."
	}
	return f.dir
}

func (f *sftpFolder) Delete(_ context.Context, name string) error {
	return f.client.Remove(path.Join(f.dir, name))
}

func (f *sftpFolder) Close() error {
	f.client.Close()
	return f.conn.Close()
}

// --- SMB -----------------------------------------------------------------------------

type smbFolder struct {
	conn    net.Conn
	session *smb2.Session
	share   *smb2.Share
	dir     string
}

func openSMB(ctx context.Context, t Target) (folder, error) {
	port := t.Port
	if port == 0 {
		port = 445
	}
	dialer := &net.Dialer{Timeout: 20 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(t.Host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	user, domain := t.Username, ""
	if d, u, ok := strings.Cut(t.Username, `\`); ok {
		domain, user = d, u
	}
	session, err := (&smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: user, Password: t.Password, Domain: domain}}).DialContext(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("the share did not accept the username and password: %w", err)
	}
	share, err := session.Mount(t.Share)
	if err != nil {
		session.Logoff()
		conn.Close()
		return nil, fmt.Errorf("the share %q could not be opened: %w", t.Share, err)
	}
	return &smbFolder{conn: conn, session: session, share: share, dir: strings.Trim(strings.ReplaceAll(t.Path, "/", `\`), `\`)}, nil
}

func (f *smbFolder) join(name string) string {
	if f.dir == "" {
		return name
	}
	return f.dir + `\` + name
}

func (f *smbFolder) Put(_ context.Context, name string, data []byte) error {
	temporary := f.join(name + ".part")
	out, err := f.share.Create(temporary)
	if err != nil {
		return fmt.Errorf("make the file (does the folder exist?): %w", err)
	}
	if _, err := out.Write(data); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return f.share.Rename(temporary, f.join(name))
}

func (f *smbFolder) List(context.Context) ([]string, error) {
	dir := f.dir
	if dir == "" {
		dir = "."
	}
	entries, err := f.share.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.Mode().IsRegular() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func (f *smbFolder) Delete(_ context.Context, name string) error { return f.share.Remove(f.join(name)) }

func (f *smbFolder) Close() error {
	f.share.Umount()
	f.session.Logoff()
	return f.conn.Close()
}
