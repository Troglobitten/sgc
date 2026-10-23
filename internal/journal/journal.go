// Package journal reads systemd's journal for SGC's log viewer, for the
// root helper (docs/design.md §4.12 and §10). The web process sends a typed
// query: one of a fixed list of SGC's parts, a level, a time, a text to
// look for; nothing of it reaches journalctl as text it chose, except the
// cursor, which is checked to be one.
//
// Standard library only.
package journal

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Parts are what the viewer can show, each a set of units.
var Parts = map[string][]string{
	"sgc":      {"sgc.service"},
	"helper":   {"sgc-helper.service", "sgc-packages.service", "sgc-update@*.service", "sgc-traefik-install.service", "sgc-proxy-apply.service", "sgc-adguard-*.service", "sgc-log2ram-set.service", "sgc-os-updates*.service"},
	"firewall": {"sgc-firewall*.service"},
	"ssh":      {"ssh.service", "sgc-ssh*.service"},
	"dns":      {"sgc-adguard.service"},
	"proxy":    {"sgc-traefik.service"},
	"vpn":      {"sgc-wireguard.service"},
	"updates":  {"unattended-upgrades.service", "apt-daily.service", "apt-daily-upgrade.service"},
}

const (
	maxEntries = 1000
	maxText    = 100
	maxSince   = 31 * 24 * time.Hour
)

// Query is what the web process asks for.
type Query struct {
	Part string `json:"part"`
	// Priority is the least important level shown: 0 (emergencies) to 7
	// (debug); 6 shows information and worse.
	Priority int `json:"priority"`
	// SinceSeconds is how far back to look.
	SinceSeconds int `json:"sinceSeconds"`
	// Text, if not empty, is looked for in each message (not a pattern).
	Text  string `json:"text"`
	Limit int    `json:"limit"`
	// After continues from where an earlier answer ended (live).
	After string `json:"after"`
}

// cursorPattern is what a journal cursor looks like (s=…;i=…;b=…;m=…;t=…;x=…).
var cursorPattern = regexp.MustCompile(`^s=[0-9a-f]{1,64}(;[a-z]=[0-9a-f]{1,64}){1,8}$`)

func (q Query) Validate() error {
	if _, ok := Parts[q.Part]; !ok {
		return errors.New("unknown part")
	}
	if q.Priority < 0 || q.Priority > 7 {
		return errors.New("the level is 0 to 7")
	}
	if q.SinceSeconds < 1 || time.Duration(q.SinceSeconds)*time.Second > maxSince {
		return errors.New("a time back of up to 31 days")
	}
	if len([]rune(q.Text)) > maxText || strings.IndexFunc(q.Text, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		return errors.New("the text to look for is too long or has odd characters")
	}
	if q.Limit < 1 || q.Limit > maxEntries {
		return errors.New("1 to 1000 entries")
	}
	if q.After != "" && !cursorPattern.MatchString(q.After) {
		return errors.New("not a position in the journal")
	}
	return nil
}

// Entry is one line of the journal.
type Entry struct {
	At       time.Time `json:"at"`
	Unit     string    `json:"unit"`
	Priority int       `json:"priority"`
	Message  string    `json:"message"`
}

// Answer is what came back, and where it ended.
type Answer struct {
	Entries []Entry `json:"entries"`
	Cursor  string  `json:"cursor"`
}

// Arguments are what journalctl is given for a checked query.
func (q Query) Arguments(now time.Time) []string {
	args := []string{"--no-pager", "--output=json", "--priority=" + strconv.Itoa(q.Priority),
		"--since=@" + strconv.FormatInt(now.Add(-time.Duration(q.SinceSeconds)*time.Second).Unix(), 10)}
	if q.After != "" {
		args = append(args, "--after-cursor="+q.After)
	} else {
		// The newest, when looking back: journalctl takes the last n.
		args = append(args, "--lines="+strconv.Itoa(maxEntries*5))
	}
	for _, unit := range Parts[q.Part] {
		args = append(args, "--unit="+unit)
	}
	return args
}

// Parse reads journalctl's JSON lines, keeps those with the text, and the
// newest q.Limit of them.
func Parse(output []byte, q Query) Answer {
	answer := Answer{Entries: []Entry{}}
	text := strings.ToLower(q.Text)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		var raw map[string]any
		if json.Unmarshal(scanner.Bytes(), &raw) != nil {
			continue
		}
		if cursor, ok := raw["__CURSOR"].(string); ok {
			answer.Cursor = cursor
		}
		message := messageOf(raw["MESSAGE"])
		if text != "" && !strings.Contains(strings.ToLower(message), text) {
			continue
		}
		entry := Entry{Message: message}
		if unit, ok := raw["_SYSTEMD_UNIT"].(string); ok {
			entry.Unit = unit
		} else if id, ok := raw["SYSLOG_IDENTIFIER"].(string); ok {
			entry.Unit = id
		}
		if p, ok := raw["PRIORITY"].(string); ok {
			entry.Priority, _ = strconv.Atoi(p)
		}
		if us, ok := raw["__REALTIME_TIMESTAMP"].(string); ok {
			if v, err := strconv.ParseInt(us, 10, 64); err == nil {
				entry.At = time.UnixMicro(v).UTC()
			}
		}
		answer.Entries = append(answer.Entries, entry)
	}
	if len(answer.Entries) > q.Limit {
		answer.Entries = answer.Entries[len(answer.Entries)-q.Limit:]
	}
	return answer
}

// messageOf: journalctl writes a message that is not valid UTF-8 as an
// array of bytes.
func messageOf(v any) string {
	switch m := v.(type) {
	case string:
		return m
	case []any:
		b := make([]byte, 0, len(m))
		for _, x := range m {
			if f, ok := x.(float64); ok {
				b = append(b, byte(f))
			}
		}
		return strings.ToValidUTF8(string(b), "?")
	}
	return ""
}

// Read runs journalctl for a checked query.
func Read(ctx context.Context, run func(ctx context.Context, program string, args ...string) ([]byte, error), q Query, now time.Time) (Answer, error) {
	output, err := run(ctx, "/usr/bin/journalctl", q.Arguments(now)...)
	if err != nil && len(output) == 0 {
		return Answer{}, err
	}
	return Parse(output, q), nil
}
