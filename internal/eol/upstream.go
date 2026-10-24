package eol

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Program is a program SGC installs that is neither its own nor Debian's,
// and whose newest release is looked up: when it is newer than the one SGC
// brings, a newer SGC is due. (AdGuard Home publishes no end-of-life dates
// at all; only its newest release gets fixes. Traefik has dates too, in
// Items.)
type Program struct {
	Name string `json:"name"`
	// Repo is its GitHub repository ("traefik/traefik").
	Repo string `json:"repo"`
	// Pinned is the version this SGC brings ("3.7.16").
	Pinned string `json:"pinned"`
	// Newest is its newest release when last looked ("" if not known).
	Newest string `json:"newest"`
	// Behind: Newest is newer than Pinned.
	Behind  bool   `json:"behind"`
	Problem string `json:"problem,omitempty"`
}

// GitHubAPI is where the newest releases are asked for.
const GitHubAPI = "https://api.github.com"

// newest asks GitHub for a repository's newest release (pre-releases are
// never "latest" there) and returns its version without the "v".
func (s *Service) newest(ctx context.Context, repo string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	base := s.cfg.GitHubAPI
	if base == "" {
		base = GitHubAPI
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "sgc")
	resp, err := s.cfg.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub answered %d", resp.StatusCode)
	}
	var answer struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&answer); err != nil {
		return "", err
	}
	version := strings.TrimPrefix(answer.TagName, "v")
	if _, ok := numbers(version); !ok {
		return "", fmt.Errorf("its newest release has an unexpected name (%q)", answer.TagName)
	}
	return version, nil
}

// numbers reads "3.7.16" as its numbers.
func numbers(version string) ([]int, bool) {
	parts := strings.Split(version, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return nil, false
	}
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

// newer says whether version a is newer than b.
func newer(a, b string) bool {
	x, okA := numbers(a)
	y, okB := numbers(b)
	if !okA || !okB {
		return false
	}
	for i := 0; i < max(len(x), len(y)); i++ {
		var p, q int
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		if p != q {
			return p > q
		}
	}
	return false
}

// checkPrograms looks up the newest release of each program.
func (s *Service) checkPrograms(ctx context.Context) []Program {
	out := []Program{}
	for _, p := range s.cfg.Programs {
		newest, err := s.newest(ctx, p.Repo)
		if err != nil {
			p.Problem = "its newest release could not be looked up: " + err.Error()
		} else {
			p.Newest, p.Behind = newest, newer(newest, p.Pinned)
		}
		out = append(out, p)
	}
	return out
}
