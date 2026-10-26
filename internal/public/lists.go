package public

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
)

// The lists come from outside (FireHOL's on GitHub, DB-IP's), unsigned. They
// are read strictly: a line that is not what a list of addresses holds
// makes the whole file unusable, and the last good one stays in place. What
// a bad list can do is limited by where the table uses it: it can keep the
// wrong visitors from the internet out of public services, or let them in;
// never anyone at home.
const (
	maxListLines = 2_000_000
	// DB-IP's country file is about 30 MB unpacked.
	maxCountryBytes = 256 << 20
)

// Range is an inclusive range of IPv4 addresses.
type Range struct {
	From, To netip.Addr
}

func (r Range) String() string {
	if r.From == r.To {
		return r.From.String()
	}
	return r.From.String() + "-" + r.To.String()
}

func toUint(a netip.Addr) uint32 { b := a.As4(); return binary.BigEndian.Uint32(b[:]) }

func fromUint(n uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return netip.AddrFrom4(b)
}

func prefixRange(p netip.Prefix) Range {
	from := toUint(p.Masked().Addr())
	size := uint32(1)<<(32-p.Bits()) - 1
	if p.Bits() == 0 {
		size = ^uint32(0)
	}
	return Range{fromUint(from), fromUint(from + size)}
}

// ParseNetset reads one of FireHOL's lists: an IPv4 address or range per
// line, comments after "#".
func ParseNetset(r io.Reader) ([]Range, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 4096)
	var out []Range
	lines := 0
	for scanner.Scan() {
		lines++
		if lines > maxListLines {
			return nil, errors.New("more lines than a list of addresses has")
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			p, err := netip.ParsePrefix(line)
			if err != nil || !p.Addr().Is4() {
				return nil, fmt.Errorf("line %d is not an IPv4 range", lines)
			}
			out = append(out, prefixRange(p))
			continue
		}
		addr, err := netip.ParseAddr(line)
		if err != nil || !addr.Is4() {
			return nil, fmt.Errorf("line %d is not an IPv4 address", lines)
		}
		out = append(out, Range{addr, addr})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("the list could not be read: %w", err)
	}
	if len(out) == 0 {
		return nil, errors.New("the list holds no addresses")
	}
	return out, nil
}

// ParseCountries reads DB-IP's country list (gzip-compressed CSV: first
// address, last address, country code) and returns the IPv4 ranges of the
// given countries.
func ParseCountries(compressed io.Reader, countries []string) ([]Range, error) {
	unzipped, err := gzip.NewReader(compressed)
	if err != nil {
		return nil, fmt.Errorf("the country list is not compressed as it should be: %w", err)
	}
	defer unzipped.Close()
	want := map[string]bool{}
	for _, c := range countries {
		want[c] = true
	}
	reader := csv.NewReader(io.LimitReader(unzipped, maxCountryBytes))
	reader.FieldsPerRecord = 3
	reader.ReuseRecord = true
	var out []Range
	rows, seen := 0, 0
	for {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("the country list could not be read: %w", err)
		}
		rows++
		if rows > maxListLines*4 {
			return nil, errors.New("more lines than a country list has")
		}
		code := row[2]
		if !countryPattern.MatchString(code) && code != "ZZ" {
			return nil, fmt.Errorf("line %d has no country code", rows)
		}
		from, err1 := netip.ParseAddr(row[0])
		to, err2 := netip.ParseAddr(row[1])
		if err1 != nil || err2 != nil || from.Is4() != to.Is4() || to.Less(from) {
			return nil, fmt.Errorf("line %d is not a range of addresses", rows)
		}
		if !from.Is4() {
			continue
		}
		seen++
		if want[code] {
			out = append(out, Range{from, to})
		}
	}
	// The real list has hundreds of thousands of IPv4 ranges; a file with a
	// handful is not it.
	if seen < 1000 {
		return nil, errors.New("the country list holds too few addresses to be DB-IP's")
	}
	return out, nil
}

// Merge sorts ranges and joins those that touch or overlap, so that the
// firewall gets each address once.
func Merge(ranges []Range) []Range {
	if len(ranges) == 0 {
		return nil
	}
	sorted := slices.Clone(ranges)
	slices.SortFunc(sorted, func(a, b Range) int { return a.From.Compare(b.From) })
	out := []Range{sorted[0]}
	for _, r := range sorted[1:] {
		last := &out[len(out)-1]
		if toUint(r.From) <= toUint(last.To) || toUint(r.From) == toUint(last.To)+1 {
			if last.To.Less(r.To) {
				last.To = r.To
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// Without removes the ranges of the allow list and of the home network
// from a list, so that a block list can never name them (level 1 holds
// every private range, through "fullbogons").
func Without(ranges []Range, holes []netip.Prefix) []Range {
	var cut []Range
	for _, h := range holes {
		cut = append(cut, prefixRange(h))
	}
	cut = Merge(cut)
	var out []Range
	for _, r := range ranges {
		pieces := []Range{r}
		for _, c := range cut {
			var next []Range
			for _, p := range pieces {
				from, to, cf, ct := toUint(p.From), toUint(p.To), toUint(c.From), toUint(c.To)
				if ct < from || cf > to {
					next = append(next, p)
					continue
				}
				if cf > from {
					next = append(next, Range{p.From, fromUint(cf - 1)})
				}
				if ct < to {
					next = append(next, Range{fromUint(ct + 1), p.To})
				}
			}
			pieces = next
		}
		out = append(out, pieces...)
	}
	return out
}
