package sshd

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Troglobitten/sgc/internal/sshkeys"
)

// go test ./internal/sshd -update rewrites the expected files. Read the
// difference before committing it: it is a change to who can log in.
var update = flag.Bool("update", false, "rewrite the expected files in testdata")

// Throwaway public keys made for the tests (see internal/sshkeys).
var (
	keyOne = mustKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID25i1+d/VGOmeRQ2ZPpnryBGMe/B28pdc623ONJVCV1")
	keyTwo = mustKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIkOC0Rmh/Nll43F/bs3QmA+Y7fKcfDEu+lizV4nuTh2")
)

func mustKey(text string) sshkeys.Key {
	key, _, err := sshkeys.Parse(text)
	if err != nil {
		panic(err)
	}
	return key
}

func TestRender(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"nothing", Config{}},
		{"keys", Config{Account: "alex", Keys: []sshkeys.Key{keyOne, keyTwo}}},
		{"keys-only", Config{KeysOnly: true}},
		{"keys-and-keys-only", Config{Account: "alex", Keys: []sshkeys.Key{keyOne}, KeysOnly: true}},
		// An account without keys gives the SSH server nothing to read.
		{"account-without-keys", Config{Account: "alex"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := "--- settings file ---\n" + renderDropIn(c.cfg, "/etc/sgc/ssh/keys") + "--- keys file ---\n" + renderKeys(c.cfg)
			golden := filepath.Join("testdata", c.name+".txt")
			if *update {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("differs from %s:\n%s", golden, got)
			}
		})
	}
}

func TestNeedsProof(t *testing.T) {
	one := []sshkeys.Key{keyOne}
	both := []sshkeys.Key{keyOne, keyTwo}
	cases := []struct {
		name     string
		from, to Config
		want     bool
	}{
		{"adding a key", Config{}, Config{Account: "alex", Keys: one}, false},
		{"removing a key while passwords still work", Config{Account: "alex", Keys: both}, Config{Account: "alex", Keys: one}, false},
		{"switching to keys only", Config{Account: "alex", Keys: one}, Config{Account: "alex", Keys: one, KeysOnly: true}, true},
		{"switching to keys only without keys of SGC's own", Config{}, Config{KeysOnly: true}, true},
		{"allowing passwords again", Config{KeysOnly: true}, Config{}, false},
		{"allowing passwords again and removing keys", Config{Account: "alex", Keys: one, KeysOnly: true}, Config{}, false},
		{"adding a key under keys only", Config{Account: "alex", Keys: one, KeysOnly: true}, Config{Account: "alex", Keys: both, KeysOnly: true}, false},
		{"removing a key under keys only", Config{Account: "alex", Keys: both, KeysOnly: true}, Config{Account: "alex", Keys: one, KeysOnly: true}, true},
		{"swapping one key for another under keys only", Config{Account: "alex", Keys: one, KeysOnly: true}, Config{Account: "alex", Keys: []sshkeys.Key{keyTwo}, KeysOnly: true}, true},
		{"moving the keys to another account under keys only", Config{Account: "alex", Keys: one, KeysOnly: true}, Config{Account: "robin", Keys: one, KeysOnly: true}, true},
		{"no change", Config{Account: "alex", Keys: one, KeysOnly: true}, Config{Account: "alex", Keys: one, KeysOnly: true}, false},
	}
	for _, c := range cases {
		if got := NeedsProof(c.from, c.to); got != c.want {
			t.Errorf("%s: NeedsProof = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestConfigCheck(t *testing.T) {
	accounts := []string{"alex", "robin"}
	good := Config{Account: "alex", Keys: []sshkeys.Key{keyOne, keyTwo}, KeysOnly: true}
	if checked, err := good.check(accounts); err != nil || !checked.Equal(good) {
		t.Fatalf("a good configuration: %+v, %v", checked, err)
	}
	if _, err := (Config{KeysOnly: true}).check(accounts); err != nil {
		t.Errorf("keys only without keys of SGC's own: %v", err)
	}

	lying := keyOne
	lying.Fingerprint = keyTwo.Fingerprint
	many := make([]sshkeys.Key, maxKeys+1)
	bad := map[string]Config{
		"keys without an account":          {Keys: []sshkeys.Key{keyOne}},
		"an account that does not exist":   {Account: "mallory", Keys: []sshkeys.Key{keyOne}},
		"root":                             {Account: "root", Keys: []sshkeys.Key{keyOne}},
		"a path as account":                {Account: "../../root", Keys: []sshkeys.Key{keyOne}},
		"an account with a line break":     {Account: "alex\nPermitRootLogin yes", Keys: []sshkeys.Key{keyOne}},
		"the same key twice":               {Account: "alex", Keys: []sshkeys.Key{keyOne, keyOne}},
		"the same key twice, disguised":    {Account: "alex", Keys: []sshkeys.Key{keyOne, lying}},
		"something that is not a key":      {Account: "alex", Keys: []sshkeys.Key{{Type: "ssh-ed25519", Blob: "AAAA"}}},
		"a key with a second line":         {Account: "alex", Keys: []sshkeys.Key{{Type: keyOne.Type, Blob: keyOne.Blob + "\n" + keyTwo.Line()}}},
		"a key with an option as its kind": {Account: "alex", Keys: []sshkeys.Key{{Type: `command="x" ssh-ed25519`, Blob: keyOne.Blob}}},
		"too many keys":                    {Account: "alex", Keys: many},
	}
	for name, cfg := range bad {
		if checked, err := cfg.check(accounts); err == nil {
			t.Errorf("%s: accepted as %+v", name, checked)
		}
	}

	// A fingerprint that came with the key is not believed.
	checked, err := (Config{Account: "alex", Keys: []sshkeys.Key{lying}}).check(accounts)
	if err != nil || checked.Keys[0].Fingerprint != keyOne.Fingerprint {
		t.Errorf("a wrong fingerprint was kept: %+v, %v", checked, err)
	}
}

func TestAccounts(t *testing.T) {
	passwd := filepath.Join(t.TempDir(), "passwd")
	os.WriteFile(passwd, []byte(strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
		"sgc:x:999:999::/var/lib/sgc:/usr/sbin/nologin",
		"robin:x:1001:1001:,,,:/home/robin:/bin/zsh",
		"alex:x:1000:1000:Alex:/home/alex:/bin/bash",
		"locked:x:1002:1002::/home/locked:/usr/sbin/nologin",
		"alsolocked:x:1003:1003::/home/alsolocked:/bin/false",
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
		"Odd Name:x:1004:1004::/home/odd:/bin/bash",
		"broken line",
		"",
	}, "\n")), 0o644)
	got, err := accounts(passwd)
	if err != nil || strings.Join(got, ",") != "alex,robin" {
		t.Errorf("accounts = %v, %v", got, err)
	}
}

func TestParseSettings(t *testing.T) {
	report := func(lines ...string) []byte {
		base := []string{"port 22", "usepam yes", "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2"}
		return []byte(strings.Join(append(base, lines...), "\n") + "\n")
	}
	cases := []struct {
		name   string
		output []byte
		want   Settings
	}{
		{"a fresh Raspberry Pi: passwords, root with a key",
			report("passwordauthentication yes", "kbdinteractiveauthentication no", "permitrootlogin without-password", "pubkeyauthentication yes", "loglevel INFO"),
			Settings{PasswordLogins: true, RootLogin: "key", KeyLogins: true, LoginsVisible: true}},
		{"keys only",
			report("passwordauthentication no", "kbdinteractiveauthentication no", "permitrootlogin no", "pubkeyauthentication yes", "loglevel VERBOSE"),
			Settings{PasswordLogins: false, RootLogin: "no", KeyLogins: true, LoginsVisible: true}},
		// Asking for the password through the "keyboard-interactive" way is
		// still a password login.
		{"password through the other door",
			report("passwordauthentication no", "kbdinteractiveauthentication yes", "permitrootlogin yes", "pubkeyauthentication yes", "loglevel INFO"),
			Settings{PasswordLogins: true, RootLogin: "yes", KeyLogins: true, LoginsVisible: true}},
		{"a quiet log",
			report("passwordauthentication yes", "kbdinteractiveauthentication no", "permitrootlogin prohibit-password", "pubkeyauthentication no", "loglevel ERROR"),
			Settings{PasswordLogins: true, RootLogin: "key", KeyLogins: false, LoginsVisible: false}},
	}
	for _, c := range cases {
		got, err := parseSettings(c.output)
		c.want.KeyFiles = defaultKeyFiles
		if err != nil || got != c.want {
			t.Errorf("%s: %+v, %v; want %+v", c.name, got, err, c.want)
		}
	}
	if _, err := parseSettings([]byte("port 22\n")); err == nil {
		t.Error("a report without the settings was accepted")
	}
}

func TestKeyLoginsAreReadStrictly(t *testing.T) {
	at := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	entry := func(message string) journalEntry { return journalEntry{Message: message, At: at} }
	sum := keyOne.Fingerprint
	entries := []journalEntry{
		entry("Accepted publickey for alex from 192.168.1.20 port 50112 ssh2: ED25519 " + sum),
		entry("Accepted publickey for robin from fe80::1%eth0 port 50113 ssh2: RSA " + keyTwo.Fingerprint),
		// Not a key login.
		entry("Accepted password for alex from 192.168.1.20 port 50114 ssh2"),
		// Accounts that do not count: root, a service account, one that does not exist.
		entry("Accepted publickey for root from 192.168.1.20 port 50115 ssh2: ED25519 " + sum),
		entry("Accepted publickey for sgc from 192.168.1.20 port 50116 ssh2: ED25519 " + sum),
		entry("Accepted publickey for mallory from 192.168.1.20 port 50117 ssh2: ED25519 " + sum),
		// What someone can make the server log by choosing a clever user name.
		entry("Invalid user Accepted publickey for alex from 192.168.1.20 port 50118 ssh2: ED25519 " + sum + " from 203.0.113.9 port 4000"),
		entry("Failed password for invalid user Accepted publickey for alex from 192.168.1.20 port 1 ssh2: ED25519 " + sum + " from 203.0.113.9 port 4000 ssh2"),
		entry("Connection closed by authenticating user alex 203.0.113.9 port 4000 [preauth]"),
		// Almost right.
		entry("Accepted publickey for alex from 192.168.1.20 port 50119 ssh2: ED25519 SHA256:tooshort"),
		entry("Accepted publickey for alex from 192.168.1.20 port 50120 ssh2: ED25519 " + sum + " extra"),
		entry(" Accepted publickey for alex from 192.168.1.20 port 50121 ssh2: ED25519 " + sum),
		entry("Accepted publickey for alex from 192.168.1.20 port 50122 ssh2: ED25519-CERT " + sum + " ID alex (serial 1) CA ED25519 " + sum),
	}
	got := keyLogins(entries, []string{"alex", "robin"})
	if len(got) != 2 || got[0].Account != "alex" || got[0].Kind != "ED25519" || got[0].Fingerprint != sum ||
		got[1].Account != "robin" || got[1].Kind != "RSA" || !got[0].At.Equal(at) {
		t.Errorf("logins = %+v", got)
	}
}

func TestParseJournal(t *testing.T) {
	output := strings.Join([]string{
		`{"MESSAGE":"Server listening on 0.0.0.0 port 22.","__REALTIME_TIMESTAMP":"1791800000000000","_COMM":"sshd"}`,
		`{"MESSAGE":[65,66],"__REALTIME_TIMESTAMP":"1791800001000000"}`, // not plain text: skipped
		`not json`,
		`{"MESSAGE":"no time"}`,
		`{"MESSAGE":"Accepted publickey for alex","__REALTIME_TIMESTAMP":"1791800002500000"}`,
	}, "\n")
	entries := parseJournal([]byte(output))
	if len(entries) != 2 || entries[0].Message != "Server listening on 0.0.0.0 port 22." ||
		!entries[1].At.Equal(time.UnixMicro(1791800002500000)) {
		t.Errorf("entries = %+v", entries)
	}
}
