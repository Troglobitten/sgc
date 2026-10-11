package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Troglobitten/sgc/internal/release"
)

// Release describes a published version of SGC.
type Release struct {
	Version     string
	Notes       string
	PublishedAt time.Time
}

// Source is where releases are looked up and downloaded from.
type Source struct {
	latestURL   string
	parseLatest func([]byte) (*Release, error)
	fileURL     func(version, name string) string
	client      *http.Client
	userAgent   string
}

const (
	maxLatestSize = 256 * 1024
	// Release notes are shown in the UI; a novel is not expected.
	maxNotesLength = 20000
)

// GitHubSource looks releases up in a GitHub repository ("owner/name").
func GitHubSource(repository, userAgent string) *Source {
	return &Source{
		latestURL: "https://api.github.com/repos/" + repository + "/releases/latest",
		parseLatest: func(data []byte) (*Release, error) {
			var answer struct {
				TagName     string    `json:"tag_name"`
				Body        string    `json:"body"`
				PublishedAt time.Time `json:"published_at"`
			}
			if err := json.Unmarshal(data, &answer); err != nil {
				return nil, errors.New("GitHub's answer could not be read")
			}
			return &Release{
				Version:     strings.TrimPrefix(answer.TagName, "v"),
				Notes:       answer.Body,
				PublishedAt: answer.PublishedAt,
			}, nil
		},
		fileURL: func(version, name string) string {
			return "https://github.com/" + repository + "/releases/download/v" + version + "/" + name
		},
		client:    newClient(),
		userAgent: userAgent,
	}
}

// MirrorSource looks releases up under a base address laid out as
//
//	<base>/latest.json            {"version": "1.2.3", "notes": "...", "publishedAt": "..."}
//	<base>/v1.2.3/<release files>
//
// It exists for tests and for installations that cannot reach GitHub.
// Pointing SGC at another source is not a way around the signature check:
// whatever is downloaded must still be signed with the release key and be
// newer than what is installed.
func MirrorSource(base, userAgent string) (*Source, error) {
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("%q is not a usable address", base)
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopback(parsed.Hostname())) {
		return nil, errors.New("an update source must use https (plain http is only accepted for this machine itself)")
	}
	base = strings.TrimRight(base, "/")
	return &Source{
		latestURL: base + "/latest.json",
		parseLatest: func(data []byte) (*Release, error) {
			var answer struct {
				Version     string    `json:"version"`
				Notes       string    `json:"notes"`
				PublishedAt time.Time `json:"publishedAt"`
			}
			if err := json.Unmarshal(data, &answer); err != nil {
				return nil, errors.New("the update source's answer could not be read")
			}
			return &Release{Version: answer.Version, Notes: answer.Notes, PublishedAt: answer.PublishedAt}, nil
		},
		fileURL: func(version, name string) string {
			return base + "/v" + version + "/" + name
		},
		client:    newClient(),
		userAgent: userAgent,
	}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func newClient() *http.Client {
	return &http.Client{
		// Long enough for a release archive over a slow line; every request
		// additionally runs under the caller's context.
		Timeout: 10 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			// GitHub redirects downloads to its storage servers. Following
			// is fine, but never from https down to plain http.
			if req.URL.Scheme != "https" && !isLoopback(req.URL.Hostname()) {
				return errors.New("refusing a redirect to an unencrypted address")
			}
			return nil
		},
	}
}

// Latest returns the newest published release.
func (s *Source) Latest(ctx context.Context) (*Release, error) {
	data, err := s.get(ctx, s.latestURL, maxLatestSize)
	if err != nil {
		return nil, err
	}
	latest, err := s.parseLatest(data)
	if err != nil {
		return nil, err
	}
	// The version comes from the network and ends up in file names, so it
	// is checked to be a plain version and nothing else.
	version, err := release.ParseVersion(latest.Version)
	if err != nil {
		return nil, fmt.Errorf("the newest release has an unexpected version: %w", err)
	}
	latest.Version = version.String()
	if len(latest.Notes) > maxNotesLength {
		latest.Notes = latest.Notes[:maxNotesLength]
	}
	return latest, nil
}

// File downloads one file of a release, refusing more than maxSize bytes.
func (s *Source) File(ctx context.Context, version, name string, maxSize int64) ([]byte, error) {
	return s.get(ctx, s.fileURL(version, name), maxSize)
}

func (s *Source) get(ctx context.Context, address string, maxSize int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "application/vnd.github+json, application/json, */*")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach %s: %w", req.URL.Host, cause(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered with status %d", req.URL.Host, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("the download from %s was interrupted", req.URL.Host)
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("the download from %s is larger than expected", req.URL.Host)
	}
	return data, nil
}

// cause strips the request details Go puts around a network error, which
// would repeat the address the message already names.
func cause(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}
