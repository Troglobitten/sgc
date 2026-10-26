package public

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Troglobitten/sgc/internal/firewall"
)

const (
	nftProgram     = "/usr/sbin/nft"
	fail2banClient = "/usr/bin/fail2ban-client"
	systemctl      = "/usr/bin/systemctl"
	envProgram     = "/usr/bin/env"
	fail2banUnit   = "fail2ban.service"
	// The largest list file read: level 4 is about 4 MB, DB-IP's country
	// list about 5 MB compressed.
	maxListFile = 64 << 20
)

// Paths are where the parts live.
type Paths struct {
	// RuleFile is the table as last put in place; sgc-public.service loads
	// it at start-up.
	RuleFile string
	// ListsDir is where the web process puts the lists it downloaded.
	ListsDir string
	// Fail2banDir is fail2ban's settings folder.
	Fail2banDir string
}

func DefaultPaths() Paths {
	return Paths{RuleFile: "/etc/sgc/public.nft", ListsDir: "/var/lib/sgc/public", Fail2banDir: "/etc/fail2ban"}
}

// ListFile is where the web process puts a downloaded list.
func ListFile(dir, name string) string {
	if name == ListCountry {
		return filepath.Join(dir, name+".csv.gz")
	}
	return filepath.Join(dir, name+".netset")
}

// Input is one change: whether anything is reachable from the internet,
// the owner's settings, and the ports (from what Traefik has in place).
type Input struct {
	On       bool
	Settings Settings
	Public   []Port
	Closed   []Port
	Reserved []Port
}

// System does the work, as root.
type System struct {
	Paths Paths
	Run   func(ctx context.Context, program string, args ...string) ([]byte, error)
	Log   *slog.Logger
}

// Fail2banInstalled reports whether Debian's fail2ban is on the device.
func Fail2banInstalled() bool {
	info, err := os.Stat(fail2banClient)
	return err == nil && info.Mode().IsRegular()
}

// Apply puts a change in place: the table for traffic from the internet,
// checked by nftables before it is loaded, and fail2ban's settings.
func (s *System) Apply(ctx context.Context, in Input) error {
	if !in.On {
		return s.off(ctx)
	}
	blocked, countries, err := s.readLists(in.Settings)
	if err != nil {
		return err
	}
	rules, err := Render(Table{Settings: in.Settings, Public: in.Public, Closed: in.Closed, Reserved: in.Reserved,
		Blocked: blocked, Countries: countries})
	if err != nil {
		return err
	}
	if err := s.load(ctx, rules); err != nil {
		return err
	}
	return s.applyFail2ban(ctx, in.Settings)
}

// load checks the rules with nftables, keeps them where start-up finds them,
// and loads them. Rules that are in place already are not loaded again
// (every change to the proxy, a renewed certificate included, comes here).
func (s *System) load(ctx context.Context, rules string) error {
	if current, err := os.ReadFile(s.Paths.RuleFile); err == nil && string(current) == rules {
		if _, err := s.Run(ctx, nftProgram, "list", "chain", "inet", TableName, "input"); err == nil {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(s.Paths.RuleFile), 0o755); err != nil {
		return err
	}
	// A name nftables' own folders would never be read for, in SGC's folder.
	temporary := s.Paths.RuleFile + ".new"
	if err := os.WriteFile(temporary, []byte(rules), 0o644); err != nil {
		return err
	}
	if output, err := s.Run(ctx, nftProgram, "-c", "-f", temporary); err != nil {
		os.Remove(temporary)
		return fmt.Errorf("nftables did not accept the rules for the internet: %s", lastLine(output, err))
	}
	if err := os.Rename(temporary, s.Paths.RuleFile); err != nil {
		return err
	}
	if output, err := s.Run(ctx, nftProgram, "-f", s.Paths.RuleFile); err != nil {
		return fmt.Errorf("the rules for the internet could not be loaded: %s", lastLine(output, err))
	}
	return nil
}

// off switches fail2ban off and removes the table, so nothing from the
// internet is let in. fail2ban first: stopping, it lifts each of its bans in
// the table (seen on the test machine, 2026-10-26). The table goes even when
// fail2ban does not stop.
func (s *System) off(ctx context.Context) error {
	fail2banErr := s.applyFail2ban(ctx, Settings{Fail2ban: Defaults().Fail2ban})
	os.Remove(s.Paths.RuleFile)
	if _, err := os.Stat(nftProgram); err == nil {
		if output, err := s.Run(ctx, nftProgram, "destroy", "table", "inet", TableName); err != nil {
			return fmt.Errorf("the rules for the internet could not be removed: %s", lastLine(output, err))
		}
	}
	return fail2banErr
}

// readLists reads the lists the settings name, each checked against its
// checksum, and returns the ranges to block and those of the countries.
func (s *System) readLists(settings Settings) (blocked, countries []Range, err error) {
	holes := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	holes = append(holes, firewall.InsideV4()...)
	for _, entry := range settings.Allow {
		p, _ := ParseAllow(entry)
		holes = append(holes, p)
	}
	for _, l := range settings.FireHOL {
		data, err := s.readList(l)
		if err != nil {
			return nil, nil, err
		}
		ranges, err := ParseNetset(bytes.NewReader(data))
		if err != nil {
			return nil, nil, fmt.Errorf("FireHOL's %s: %w", l.Name, err)
		}
		blocked = append(blocked, ranges...)
	}
	blocked = Without(Merge(blocked), holes)
	if settings.CountryMode != CountryOff && settings.CountryList != nil {
		data, err := s.readList(*settings.CountryList)
		if err != nil {
			return nil, nil, err
		}
		ranges, err := ParseCountries(bytes.NewReader(data), settings.Countries)
		if err != nil {
			return nil, nil, fmt.Errorf("DB-IP's country list: %w", err)
		}
		countries = Merge(ranges)
		if settings.CountryMode == CountryAllow && len(countries) == 0 {
			return nil, nil, errors.New("the countries chosen have no addresses in DB-IP's list; nobody from the internet would get in")
		}
	}
	return blocked, countries, nil
}

func (s *System) readList(l List) ([]byte, error) {
	f, err := os.OpenFile(ListFile(s.Paths.ListsDir, l.Name), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("the list %s is not there: %w", l.Name, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxListFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxListFile {
		return nil, fmt.Errorf("the list %s is larger than any list SGC uses", l.Name)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != l.SHA256 {
		return nil, fmt.Errorf("the list %s is not the file SGC's page meant (it changed in between)", l.Name)
	}
	return data, nil
}

// applyFail2ban writes SGC's files for fail2ban and switches it on or off.
func (s *System) applyFail2ban(ctx context.Context, settings Settings) error {
	if !Fail2banInstalled() {
		if settings.Fail2ban.Enabled {
			return errors.New("fail2ban is not installed on this device")
		}
		return nil
	}
	files, err := Fail2banFileSet(settings.Fail2ban, settings.Allow)
	if err != nil {
		return err
	}
	changed, err := WriteFail2banFiles(s.Paths.Fail2banDir, files)
	if err != nil {
		return err
	}
	if !settings.Fail2ban.Enabled {
		if output, err := s.fail2banStartUp(ctx, "disable", "--now"); err != nil {
			return fmt.Errorf("fail2ban could not be switched off: %s", lastLine(output, err))
		}
		return nil
	}
	// fail2ban's own check of its settings, before they are used.
	if output, err := s.Run(ctx, fail2banClient, "--test"); err != nil {
		return fmt.Errorf("fail2ban did not accept its settings: %s", lastLine(output, err))
	}
	if output, err := s.fail2banStartUp(ctx, "enable"); err != nil {
		return fmt.Errorf("fail2ban could not be made part of start-up: %s", lastLine(output, err))
	}
	if _, err := s.Run(ctx, systemctl, "is-active", "--quiet", fail2banUnit); err == nil {
		if !changed {
			return nil
		}
		if err := s.fail2banAnswers(ctx); err != nil {
			return err
		}
		if output, err := s.Run(ctx, fail2banClient, "reload"); err != nil {
			return fmt.Errorf("fail2ban did not take its new settings: %s", lastLine(output, err))
		}
		return nil
	}
	if output, err := s.Run(ctx, systemctl, "start", fail2banUnit); err != nil {
		return fmt.Errorf("fail2ban could not be started: %s", lastLine(output, err))
	}
	return s.fail2banAnswers(ctx)
}

// fail2banAnswers waits until fail2ban answers on its socket. systemd says
// it is running at once (Debian's unit is Type=simple), and it answers about
// half a second later (test machine, 2026-10-26); until then neither the
// page's list of bans nor lifting one would work.
func (s *System) fail2banAnswers(ctx context.Context) error {
	deadline := time.Now().Add(15 * time.Second)
	for {
		output, err := s.Run(ctx, fail2banClient, "ping")
		if err == nil && strings.Contains(string(output), "pong") {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("fail2ban started but does not answer: %s", lastLine(output, err))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// fail2banStartUp makes fail2ban part of start-up or takes it out. Without
// systemctl's SysV hooks: fail2ban also ships an init script, and for that
// systemctl runs update-rc.d itself, which cannot write /etc/rc?.d from the
// proxy job's sandbox ("update-rc.d: error: Read-only file system", found by
// the whole-machine test on 2026-10-26). systemd starts the native unit at
// start-up and ignores the script's links while the unit exists (enabled
// that way from the same sandbox on the test machine: "enabled").
func (s *System) fail2banStartUp(ctx context.Context, args ...string) ([]byte, error) {
	return s.Run(ctx, envProgram, append(append([]string{"SYSTEMCTL_SKIP_SYSV=1", systemctl}, args...), fail2banUnit)...)
}

// WriteFail2banFiles writes SGC's files into fail2ban's folder, each in one
// step, owned by root and readable by all (they hold nothing secret). It
// reports whether any of them changed.
func WriteFail2banFiles(dir string, files map[string]string) (bool, error) {
	changed := false
	for name, content := range files {
		path := filepath.Join(dir, name)
		if current, err := os.ReadFile(path); err == nil && string(current) == content {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return changed, err
		}
		// "~" at the end: fail2ban reads only .conf and .local.
		temporary := path + "~"
		if err := os.WriteFile(temporary, []byte(content), 0o644); err != nil {
			return changed, err
		}
		if err := os.Rename(temporary, path); err != nil {
			os.Remove(temporary)
			return changed, err
		}
		changed = true
	}
	return changed, nil
}

// Bans lists the addresses fail2ban has banned now. Run by the helper
// itself, which talks to fail2ban over its socket.
func (s *System) Bans(ctx context.Context) ([]Ban, error) {
	if !Fail2banInstalled() {
		return []Ban{}, nil
	}
	if _, err := s.Run(ctx, systemctl, "is-active", "--quiet", fail2banUnit); err != nil {
		return []Ban{}, nil
	}
	out := []Ban{}
	for _, jail := range []string{JailSignIn, JailDoor} {
		output, err := s.Run(ctx, fail2banClient, "get", jail, "banip", "--with-time")
		if err != nil {
			// A jail that is switched off is not there.
			if strings.Contains(string(output), "does not exist") {
				continue
			}
			return nil, fmt.Errorf("fail2ban could not be asked: %s", lastLine(output, err))
		}
		out = append(out, ParseBans(jail, string(output), time.Local)...)
	}
	return out, nil
}

// Unban lifts a ban on one address, in every jail.
func (s *System) Unban(ctx context.Context, addr netip.Addr) error {
	if !addr.Is4() {
		return errors.New("not an IPv4 address")
	}
	if !Fail2banInstalled() {
		return errors.New("fail2ban is not installed on this device")
	}
	// Not running: it holds no bans (stopping lifts every one of them).
	if _, err := s.Run(ctx, systemctl, "is-active", "--quiet", fail2banUnit); err != nil {
		return nil
	}
	if output, err := s.Run(ctx, fail2banClient, "unban", addr.String()); err != nil {
		return fmt.Errorf("fail2ban did not lift the ban: %s", lastLine(output, err))
	}
	return nil
}

func lastLine(output []byte, err error) string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if last := strings.TrimSpace(lines[len(lines)-1]); last != "" {
		if runes := []rune(last); len(runes) > 240 {
			last = string(runes[:240]) + "…"
		}
		return last
	}
	if err == nil {
		return ""
	}
	return err.Error()
}
