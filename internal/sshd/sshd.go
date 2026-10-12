// Package sshd manages the two things SGC changes about the machine's SSH
// server: which keys may log in, and whether anything but a key may.
//
// SGC does not replace the SSH server's configuration. It adds one file of
// its own to the server's configuration folder, and one file with keys in a
// folder of its own, and both are written from scratch each time from a
// small description (Config). Removing the two files leaves the server
// exactly as the machine had it.
//
// The dangerous change is switching to "keys only": after it, a password no
// longer gets anyone in. So that change is tried out first. It takes effect,
// and it stays only if SGC then sees somebody log in with a key; otherwise
// the previous configuration comes back by itself (system.go). Seeing a key
// login is the one proof that counts here: that SGC's page still answers
// says nothing about SSH.
//
// Root side; used by the helper. No database, no network.
package sshd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Troglobitten/sgc/internal/sshkeys"
)

// Programs the root side runs: fixed paths, fixed arguments.
const (
	sshdProgram = "/usr/sbin/sshd"
	journalctl  = "/usr/bin/journalctl"
	systemctl   = "/usr/bin/systemctl"

	serviceUnit = "ssh.service"
	socketUnit  = "ssh.socket"
)

// maxKeys bounds the list of keys in one configuration.
const maxKeys = 32

// The SSH server's own default for where each account keeps its keys. SGC's
// file is added to these, never put in their place.
const defaultKeyFiles = ".ssh/authorized_keys .ssh/authorized_keys2"

// accountName is what a Linux account name may look like. The name becomes a
// file name, and the SSH server puts it into a path, so nothing else passes.
var accountName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// Config is everything SGC decides about the SSH server.
type Config struct {
	// Account is the Linux account the keys are for. Empty: no keys.
	Account string `json:"account"`
	// Keys may log in as Account, in addition to whatever keys that account
	// keeps in its own home folder.
	Keys []sshkeys.Key `json:"keys"`
	// KeysOnly switches password logins and logins as root off.
	KeysOnly bool `json:"keysOnly"`
}

// managesKeys reports whether this configuration gives the SSH server a file
// with keys.
func (c Config) managesKeys() bool { return c.Account != "" && len(c.Keys) > 0 }

func (c Config) hasKey(fingerprint string) bool {
	return slices.ContainsFunc(c.Keys, func(k sshkeys.Key) bool { return k.Fingerprint == fingerprint })
}

// check returns the configuration with every key checked again, or says
// what is wrong with it. accounts are the accounts on this machine that can
// log in.
func (c Config) check(accounts []string) (Config, error) {
	checked := Config{Account: c.Account, KeysOnly: c.KeysOnly, Keys: []sshkeys.Key{}}
	if len(c.Keys) > maxKeys {
		return Config{}, fmt.Errorf("more than %d keys", maxKeys)
	}
	if c.Account == "" && len(c.Keys) > 0 {
		return Config{}, errors.New("keys without an account to install them for")
	}
	if c.Account != "" {
		if !accountName.MatchString(c.Account) {
			return Config{}, errors.New("that is not the name of an account")
		}
		if !slices.Contains(accounts, c.Account) {
			return Config{}, fmt.Errorf("there is no account %q on this device that can log in", c.Account)
		}
	}
	for _, key := range c.Keys {
		good, err := sshkeys.Check(key)
		if err != nil {
			return Config{}, fmt.Errorf("one of the keys is not usable: %w", err)
		}
		if checked.hasKey(good.Fingerprint) {
			return Config{}, errors.New("the same key twice")
		}
		checked.Keys = append(checked.Keys, good)
	}
	return checked, nil
}

// NeedsProof reports whether going from one configuration to another takes
// away a way of logging in. Such a change only stays if a key login is seen
// afterwards. Everything else (adding a key, allowing passwords again) can
// lock nobody out and takes effect for good at once.
func NeedsProof(from, to Config) bool {
	if !to.KeysOnly {
		return false
	}
	if !from.KeysOnly {
		return true
	}
	// Already keys only: taking a key away, or moving the keys to another
	// account, may remove the one key that still worked.
	if from.managesKeys() && from.Account != to.Account {
		return true
	}
	for _, key := range from.Keys {
		if !to.hasKey(key.Fingerprint) {
			return true
		}
	}
	return false
}

// renderDropIn writes SGC's file for the SSH server's configuration folder.
// An empty result means: no file. keysDir is where SGC keeps its key files.
//
// Nothing from outside ends up in this text: the two switches choose between
// fixed lines, and keysDir is a constant of the caller.
func renderDropIn(cfg Config, keysDir string) string {
	if !cfg.managesKeys() && !cfg.KeysOnly {
		return ""
	}
	var b strings.Builder
	b.WriteString("# Written by SGC. Do not edit: SGC replaces this file.\n")
	b.WriteString("# Removing it puts the SSH server back to this machine's own settings.\n")
	if cfg.managesKeys() {
		b.WriteString("\n# Keys added in SGC's page are kept in a file of SGC's own, in addition to\n")
		b.WriteString("# the ones each account keeps in its home folder. %u is the account's name.\n")
		fmt.Fprintf(&b, "AuthorizedKeysFile %s %s/%%u\n", defaultKeyFiles, keysDir)
	}
	if cfg.KeysOnly {
		b.WriteString("\n# Keys only: no passwords, and nobody logs in as root.\n")
		b.WriteString("PubkeyAuthentication yes\n")
		b.WriteString("PasswordAuthentication no\n")
		b.WriteString("KbdInteractiveAuthentication no\n")
		b.WriteString("PermitRootLogin no\n")
	}
	return b.String()
}

// renderKeys writes the file with the account's keys: one per line, the
// kind and the key, never an option and never a comment.
func renderKeys(cfg Config) string {
	var b strings.Builder
	for _, key := range cfg.Keys {
		b.WriteString(key.Line())
		b.WriteByte('\n')
	}
	return b.String()
}

// --- What the machine says -----------------------------------------------------

// Shells that mean "this account cannot log in".
var noLoginShells = []string{"", "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"}

// accounts lists the accounts a person logs in with: ordinary user IDs and a
// real shell. Root and the accounts services run as are left out.
func accounts(passwdFile string) ([]string, error) {
	data, err := os.ReadFile(passwdFile)
	if err != nil {
		return nil, err
	}
	names := []string{}
	for line := range strings.Lines(string(data)) {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) != 7 {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil || uid < 1000 || uid >= 60000 {
			continue
		}
		if slices.Contains(noLoginShells, fields[6]) || !accountName.MatchString(fields[0]) {
			continue
		}
		names = append(names, fields[0])
	}
	slices.Sort(names)
	return names, nil
}

// Settings are the SSH server's settings SGC cares about, as the server
// itself reports them for the configuration on disk.
type Settings struct {
	// PasswordLogins: can anything but a key get someone in?
	PasswordLogins bool `json:"passwordLogins"`
	// RootLogin is "no", "key" (root may log in, with a key only) or "yes".
	RootLogin string `json:"rootLogin"`
	KeyLogins bool   `json:"keyLogins"`
	// LoginsVisible: does the server log logins? SGC can only see a key
	// login, and so only switch to keys only, if it does.
	LoginsVisible bool `json:"loginsVisible"`
	// KeyFiles is where the server looks for an account's keys.
	KeyFiles string `json:"-"`
}

// parseSettings reads the output of "sshd -T", which lists every setting as
// "name value" in lower case.
func parseSettings(output []byte) (Settings, error) {
	values := map[string]string{}
	for line := range strings.Lines(string(output)) {
		name, value, found := strings.Cut(strings.TrimSpace(line), " ")
		if !found {
			continue
		}
		if _, seen := values[name]; !seen {
			values[name] = value
		}
	}
	for _, name := range []string{"passwordauthentication", "kbdinteractiveauthentication", "permitrootlogin", "pubkeyauthentication", "loglevel", "authorizedkeysfile"} {
		if _, ok := values[name]; !ok {
			return Settings{}, fmt.Errorf("the SSH server did not report its setting %q", name)
		}
	}
	settings := Settings{
		PasswordLogins: values["passwordauthentication"] == "yes" || values["kbdinteractiveauthentication"] == "yes",
		KeyLogins:      values["pubkeyauthentication"] == "yes",
		KeyFiles:       values["authorizedkeysfile"],
	}
	switch values["permitrootlogin"] {
	case "no":
		settings.RootLogin = "no"
	case "yes":
		settings.RootLogin = "yes"
	default: // "without-password", "prohibit-password", "forced-commands-only"
		settings.RootLogin = "key"
	}
	// Logins are written at the level INFO; the quieter levels leave them out.
	settings.LoginsVisible = !slices.Contains([]string{"QUIET", "FATAL", "ERROR"}, strings.ToUpper(values["loglevel"]))
	return settings, nil
}

// Login is one successful login with a key, as the SSH server logged it.
type Login struct {
	Account string `json:"account"`
	// Kind and Fingerprint identify the key: "ED25519", "SHA256:...".
	Kind        string    `json:"kind"`
	Fingerprint string    `json:"fingerprint"`
	At          time.Time `json:"at"`
}

// The SSH server's line for a successful key login. Matched as a whole: the
// account name in it is the server's own, and a login attempt cannot make
// the server write a line that starts like this one.
var acceptedLine = regexp.MustCompile(`^Accepted publickey for ([a-z_][a-z0-9_-]{0,31}) from \S+ port \d+ ssh2: ([A-Z0-9-]+) (SHA256:[A-Za-z0-9+/]{43})$`)

// The line the server writes when it has (re)started listening.
const listeningPrefix = "Server listening on "

type journalEntry struct {
	Message string
	At      time.Time
}

// parseJournal reads "journalctl -o json" output: one JSON object per line.
// Entries whose text is not plain text are skipped.
func parseJournal(output []byte) []journalEntry {
	var entries []journalEntry
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var raw struct {
			Message  any    `json:"MESSAGE"`
			Realtime string `json:"__REALTIME_TIMESTAMP"`
		}
		if json.Unmarshal(scanner.Bytes(), &raw) != nil {
			continue
		}
		message, ok := raw.Message.(string)
		micros, err := strconv.ParseInt(raw.Realtime, 10, 64)
		if !ok || err != nil {
			continue
		}
		entries = append(entries, journalEntry{Message: message, At: time.UnixMicro(micros)})
	}
	return entries
}

// keyLogins picks the successful key logins of the given accounts out of
// journal entries.
func keyLogins(entries []journalEntry, accounts []string) []Login {
	logins := []Login{}
	for _, entry := range entries {
		m := acceptedLine.FindStringSubmatch(entry.Message)
		if m == nil || !slices.Contains(accounts, m[1]) {
			continue
		}
		logins = append(logins, Login{Account: m[1], Kind: m[2], Fingerprint: m[3], At: entry.At.UTC()})
	}
	return logins
}

// journalSince reads what the SSH server logged from a moment on.
func (s *System) journalSince(ctx context.Context, since time.Time) ([]journalEntry, error) {
	// "@seconds" is a point in time for journalctl; one second earlier than
	// asked, because it cuts off the fraction. The caller compares exactly.
	output, err := s.Run(ctx, journalctl, "--unit="+serviceUnit, "--output=json", "--no-pager",
		"--since=@"+strconv.FormatInt(since.Unix()-1, 10))
	if err != nil {
		return nil, fmt.Errorf("read the SSH server's log: %s", lastLine(output, err))
	}
	var entries []journalEntry
	for _, entry := range parseJournal(output) {
		if !entry.At.Before(since) {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// lastLine picks the most telling line of a program's output for a message.
func lastLine(output []byte, err error) string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if last := strings.TrimSpace(lines[len(lines)-1]); last != "" {
		return last
	}
	return err.Error()
}
