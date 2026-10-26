package public

import (
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// go test ./internal/public -update rewrites the expected files. Read the
// difference: it is a change to what the firewall and fail2ban are told.
var update = flag.Bool("update", false, "rewrite the expected files in testdata")

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Errorf("%s differs from what is expected:\n%s", name, got)
	}
}

func sampleSettings() Settings {
	s := Defaults()
	s.Allow = []string{"198.51.100.7", "203.0.113.0/28"}
	s.FireHOL = []List{{Name: ListLevel1, SHA256: strings.Repeat("a", 64)}, {Name: ListLevel3, SHA256: strings.Repeat("b", 64)}}
	s.CountryMode, s.Countries = CountryAllow, []string{"EE", "NL"}
	s.CountryList = &List{Name: ListCountry, SHA256: strings.Repeat("c", 64)}
	s.Fail2ban.Enabled = true
	return s
}

func r(from, to string) Range { return Range{netip.MustParseAddr(from), netip.MustParseAddr(to)} }

func TestRender(t *testing.T) {
	got, err := Render(Table{
		Settings:  sampleSettings(),
		Public:    []Port{{DoorPort, "tcp"}, {25565, "tcp"}, {27016, "udp"}},
		Closed:    []Port{{7777, "tcp"}},
		Reserved:  []Port{{51820, "udp"}},
		Blocked:   []Range{r("1.2.3.0", "1.2.3.255"), r("5.6.7.8", "5.6.7.8")},
		Countries: []Range{r("2.56.0.0", "2.56.3.255")},
	})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "public.nft", got)
	golden(t, "off.nft", RenderOff())
}

// Nothing in the table can name the device's own ports: SSH, SGC's page,
// DNS, the VPN. That is what makes it safe to change without confirmation.
func TestTheTableCannotNameTheDevicesOwnPorts(t *testing.T) {
	for _, p := range []Port{{22, "tcp"}, {8443, "tcp"}, {53, "udp"}, {443, "tcp"}, {51820, "udp"}} {
		for _, where := range []string{"public", "closed"} {
			table := Table{Settings: Defaults(), Reserved: []Port{{51820, "udp"}}}
			if where == "public" {
				table.Public = []Port{p}
			} else {
				table.Closed = []Port{p}
			}
			if _, err := Render(table); err == nil {
				t.Errorf("port %v was taken as %s", p, where)
			}
		}
	}
	if _, err := Render(Table{Settings: Defaults(), Public: []Port{{25565, "tcp"}}, Closed: []Port{{25565, "tcp"}}}); err == nil {
		t.Error("a port both public and closed was taken")
	}
}

// Every rule that drops something comes after the return for home
// addresses and other families, in the one chain hooked into the input.
func TestEveryDropIsForTrafficFromOutside(t *testing.T) {
	got, err := Render(Table{Settings: sampleSettings(), Public: []Port{{DoorPort, "tcp"}}, Closed: []Port{{7777, "tcp"}}})
	if err != nil {
		t.Fatal(err)
	}
	input := got[strings.Index(got, "chain input {"):]
	home := strings.Index(input, "ip saddr @inside4 return")
	family := strings.Index(input, "meta nfproto != ipv4 return")
	itself := strings.Index(input, `iif "lo" return`)
	if home < 0 || family < 0 || itself < 0 || itself > home {
		t.Fatal("the input chain does not let the device itself, home addresses and IPv6 go first")
	}
	for i, line := range strings.Split(input, "\n") {
		if (strings.Contains(line, " drop") || strings.Contains(line, "jump")) && strings.Index(input, line) < home {
			t.Errorf("line %d drops or jumps before home addresses are let go: %s", i, line)
		}
	}
	// The visitors chain is reached only by a jump from there.
	if strings.Count(got, "jump visitors") != 2 || strings.Contains(got, "goto") {
		t.Error("the visitors chain is reached from elsewhere than the input chain")
	}
}

func TestValidateRefuses(t *testing.T) {
	cases := map[string]func(*Settings){
		"a limit of requests too low":   func(s *Settings) { s.RequestsPerMinute = 1 },
		"a limit of connections at 0":   func(s *Settings) { s.ConnectionsPerMinute = 0 },
		"an allow entry that is a name": func(s *Settings) { s.Allow = []string{"friend.example"} },
		"an allow range too wide":       func(s *Settings) { s.Allow = []string{"0.0.0.0/0"} },
		"an allow range not at its start": func(s *Settings) {
			s.Allow = []string{"203.0.113.7/24"}
		},
		"an IPv6 allow entry":        func(s *Settings) { s.Allow = []string{"2001:db8::1"} },
		"an unknown list":            func(s *Settings) { s.FireHOL = []List{{Name: "firehol_level9", SHA256: strings.Repeat("a", 64)}} },
		"a list twice":               func(s *Settings) { s.FireHOL = append(s.FireHOL, s.FireHOL[0]) },
		"a list without checksum":    func(s *Settings) { s.FireHOL = []List{{Name: ListLevel2}} },
		"a country code in lower":    func(s *Settings) { s.Countries = []string{"ee"} },
		"countries without the list": func(s *Settings) { s.CountryList = nil },
		"an unknown mode":            func(s *Settings) { s.CountryMode = "everything" },
		"countries while off":        func(s *Settings) { s.CountryMode = CountryOff },
		"a ban of no minutes":        func(s *Settings) { s.Fail2ban.BanMinutes = 0 },
		"sign-ins of thousands":      func(s *Settings) { s.Fail2ban.SignIns = 5000 },
	}
	for name, change := range cases {
		s := sampleSettings()
		change(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	if err := sampleSettings().Validate(); err != nil {
		t.Errorf("the sample: %v", err)
	}
	if err := Defaults().Validate(); err != nil {
		t.Errorf("the defaults: %v", err)
	}
}

func TestReadingFireHOLsLists(t *testing.T) {
	ranges, err := ParseNetset(strings.NewReader("# firehol_level1\n#\n1.2.3.0/24\n5.6.7.8\n\n10.0.0.0/8\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []Range{r("1.2.3.0", "1.2.3.255"), r("5.6.7.8", "5.6.7.8"), r("10.0.0.0", "10.255.255.255")}
	if !slices.Equal(ranges, want) {
		t.Errorf("ParseNetset = %v", ranges)
	}
	for _, bad := range []string{"1.2.3.4\nrm -rf /\n", "2001:db8::/32\n", "1.2.3.4/33\n", "# only a comment\n", "1.2.3.4 } accept\n"} {
		if _, err := ParseNetset(strings.NewReader(bad)); err == nil {
			t.Errorf("ParseNetset(%q) took it", bad)
		}
	}
}

// countryFile makes a DB-IP-like file: enough IPv4 rows to look like the
// real one, two of them in the countries asked for, and some IPv6.
func countryFile(t *testing.T, extra string) []byte {
	t.Helper()
	var csv strings.Builder
	csv.WriteString("2.56.0.0,2.56.3.255,EE\n2001:db8::,2001:db8::ffff,EE\n")
	for i := range 1200 {
		fmt.Fprintf(&csv, "%d.%d.0.0,%d.%d.255.255,ZZ\n", 100+i/250, i%250, 100+i/250, i%250)
	}
	csv.WriteString("5.0.0.0,5.0.0.255,NL\n")
	csv.WriteString(extra)
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(csv.String()))
	w.Close()
	return b.Bytes()
}

func TestReadingTheCountryList(t *testing.T) {
	ranges, err := ParseCountries(bytes.NewReader(countryFile(t, "")), []string{"EE", "NL"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []Range{r("2.56.0.0", "2.56.3.255"), r("5.0.0.0", "5.0.0.255")}; !slices.Equal(ranges, want) {
		t.Errorf("ParseCountries = %v", ranges)
	}
	if _, err := ParseCountries(bytes.NewReader(countryFile(t, "1.1.1.1,1.1.1.0,EE\n")), []string{"EE"}); err == nil {
		t.Error("a range that ends before it starts was taken")
	}
	if _, err := ParseCountries(bytes.NewReader(countryFile(t, "1.1.1.1,1.1.1.2,E1\n")), []string{"EE"}); err == nil {
		t.Error("a row without a country code was taken")
	}
	if _, err := ParseCountries(strings.NewReader("not compressed"), []string{"EE"}); err == nil {
		t.Error("an uncompressed file was taken")
	}
}

func TestMergeAndCut(t *testing.T) {
	merged := Merge([]Range{r("1.0.0.5", "1.0.0.9"), r("1.0.0.0", "1.0.0.4"), r("1.0.0.7", "1.0.0.20"), r("2.0.0.0", "2.0.0.0")})
	if want := []Range{r("1.0.0.0", "1.0.0.20"), r("2.0.0.0", "2.0.0.0")}; !slices.Equal(merged, want) {
		t.Errorf("Merge = %v", merged)
	}
	// Level 1 holds every private range; the home network is cut out of
	// what is blocked, and so is the allow list.
	cut := Without([]Range{r("10.0.0.0", "10.255.255.255"), r("198.51.100.0", "198.51.100.255")},
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("198.51.100.7/32")})
	if want := []Range{r("198.51.100.0", "198.51.100.6"), r("198.51.100.8", "198.51.100.255")}; !slices.Equal(cut, want) {
		t.Errorf("Without = %v", cut)
	}
}

func TestFail2bansFiles(t *testing.T) {
	files, err := Fail2banFileSet(sampleSettings().Fail2ban, []string{"198.51.100.7"})
	if err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	for _, name := range []string{Fail2banJail, Fail2banSignInFilter, Fail2banDoorFilter, Fail2banAction} {
		fmt.Fprintf(&all, "==> %s\n%s\n", name, files[name])
	}
	golden(t, "fail2ban.txt", all.String())
	jail := files[Fail2banJail]
	if !strings.Contains(jail, "[sshd]\nenabled = false") {
		t.Error("Debian's SSH jail is not switched off")
	}
	if !strings.Contains(jail, "192.168.0.0/16") || !strings.Contains(jail, "198.51.100.7/32") {
		t.Error("home addresses or the allow list can be banned")
	}
}

func TestReadingBans(t *testing.T) {
	output := "203.0.113.5 \t2026-10-25 12:00:00 + 3600 = 2026-10-25 13:00:00\n" +
		"198.51.100.9 \t2026-10-25 11:00:00 + 600 = 2026-10-25 11:10:00\n" +
		"not a line fail2ban writes\n"
	bans := ParseBans(JailDoor, output, time.UTC)
	if len(bans) != 2 || bans[0].Address != "198.51.100.9" || bans[1].Until != time.Date(2026, 10, 25, 13, 0, 0, 0, time.UTC) {
		t.Errorf("ParseBans = %+v", bans)
	}
}

func TestPorts(t *testing.T) {
	for _, good := range []string{"8446/tcp", "27016/udp"} {
		if p, ok := ParsePort(good); !ok || p.String() != good {
			t.Errorf("ParsePort(%q) = %v, %t", good, p, ok)
		}
	}
	for _, bad := range []string{"8446", "0/tcp", "70000/udp", "53/icmp", "08446/tcp", " 1/tcp"} {
		if _, ok := ParsePort(bad); ok {
			t.Errorf("ParsePort(%q) took it", bad)
		}
	}
}
