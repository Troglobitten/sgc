package publiccontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Troglobitten/sgc/internal/audit"
	"github.com/Troglobitten/sgc/internal/dnsprovider"
	"github.com/Troglobitten/sgc/internal/proxy"
	"github.com/Troglobitten/sgc/internal/public"
	"github.com/Troglobitten/sgc/internal/services"
	"github.com/Troglobitten/sgc/internal/store"
)

// A public service needs a public name: an A record at the owner's DNS
// provider pointing at the home's address (inside, AdGuard Home answers the
// same name with the device's own address), and, for a TCP or UDP service
// with a name for it, an SRV record that says which port. SGC makes these,
// keeps the A records at the home's address as it changes, and removes them
// when the service is closed. It never changes a record it did not make: a
// name that already has one is refused when the service is opened.

// made is a record SGC made (SettingRecords).
type made struct {
	Provider string `json:"provider"`
	Domain   string `json:"domain"`
	Kind     string `json:"kind"` // "A" or "SRV"
	Name     string `json:"name"`
	ID       string `json:"id"`
	// Value is an A record's address, or an SRV record's "priority weight
	// port target".
	Value string `json:"value"`
}

// srvWeight and srvPriority: one server per name, so any values do.
const (
	srvPriority = 0
	srvWeight   = 5
)

// RecordState is how a public service's name stands at the DNS provider.
type RecordState struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	OK      bool   `json:"ok"`
	Problem string `json:"problem"`
	// SRV is the service record, "" for none; SRVManual is the record to
	// add by hand where the provider's API has none.
	SRV       string `json:"srv"`
	SRVManual string `json:"srvManual"`
}

// state is SettingState: what the last round found.
type state struct {
	PublicIP  string                 `json:"publicIp"`
	CheckedAt *time.Time             `json:"checkedAt"`
	Problem   string                 `json:"problem"`
	Records   map[string]RecordState `json:"records"`
}

func (s *Service) state(ctx context.Context) state {
	st := state{Records: map[string]RecordState{}}
	if raw, found, err := store.Setting(ctx, s.cfg.DB, SettingState); err == nil && found {
		json.Unmarshal([]byte(raw), &st)
	}
	if st.Records == nil {
		st.Records = map[string]RecordState{}
	}
	return st
}

func (s *Service) keepState(ctx context.Context, st state) {
	before := s.state(ctx)
	if data, err := json.Marshal(st); err == nil {
		store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingState, string(data))
	}
	if st.Problem != "" && st.Problem != before.Problem {
		s.record(ctx, audit.ActorSystem, audit.ActionPublicRecordFailed, st.Problem, "")
		s.cfg.Alert(ctx, "A public name could not be kept up to date", st.Problem)
	}
}

func (s *Service) madeRecords(ctx context.Context) []made {
	var out []made
	if raw, found, err := store.Setting(ctx, s.cfg.DB, SettingRecords); err == nil && found {
		json.Unmarshal([]byte(raw), &out)
	}
	return out
}

func (s *Service) keepMade(ctx context.Context, records []made) {
	if records == nil {
		records = []made{}
	}
	if data, err := json.Marshal(records); err == nil {
		store.SetSetting(context.WithoutCancel(ctx), s.cfg.DB, SettingRecords, string(data))
	}
}

// foreignRecord says, in words, why a service's name cannot be made public:
// the provider has an A record for it that SGC did not make. "" if not.
func (s *Service) foreignRecord(ctx context.Context, label string) string {
	client, account, configured, err := s.cfg.DNS(ctx)
	if err != nil || !configured {
		return ""
	}
	name := label + "." + account.Domain
	records, err := client.ARecords(ctx, account.Domain)
	if err != nil {
		return ""
	}
	mine := s.madeRecords(ctx)
	for _, r := range records {
		if !strings.EqualFold(r.Name, name) {
			continue
		}
		ours := false
		for _, m := range mine {
			if m.Kind == "A" && m.ID == r.ID && strings.EqualFold(m.Name, name) && m.Provider == account.Provider {
				ours = true
			}
		}
		if !ours {
			return fmt.Sprintf("%s already has a record for %s (%s) that SGC did not make. Remove it there first, or choose another name for the service.",
				dnsprovider.Name(account.Provider), name, r.Value)
		}
	}
	return ""
}

type wanted struct {
	kind  string // "A" or "SRV"
	name  string
	value string
	srv   dnsprovider.SRV
	label string // the service it is for
}

// keepRecords brings the public names at the DNS provider in line with the
// public services: once a round, and soon after a change.
func (s *Service) keepRecords(ctx context.Context) {
	s.records.Lock()
	defer s.records.Unlock()
	st := s.state(ctx)
	now := s.cfg.Now().UTC()
	st.CheckedAt, st.Problem = &now, ""
	mine := s.madeRecords(ctx)

	var open []services.Service
	if s.On(ctx) {
		var err error
		if open, err = s.cfg.Catalog.PublicServices(ctx); err != nil {
			s.cfg.Log.Error("list public services", "error", err)
			return
		}
	}
	if len(open) == 0 && len(mine) == 0 {
		st.Records = map[string]RecordState{}
		s.keepState(ctx, st)
		return
	}
	client, account, configured, err := s.cfg.DNS(ctx)
	if err != nil || !configured {
		if err != nil {
			st.Problem = "The DNS provider could not be used for the public names: " + err.Error()
		} else {
			st.Problem = "Public names need your domain and DNS provider (System, Domain and names)."
		}
		s.keepState(ctx, st)
		return
	}
	domain, at := account.Domain, dnsprovider.Name(account.Provider)
	var want []wanted
	if len(open) > 0 {
		address, err := s.cfg.PublicIP(ctx)
		if err != nil {
			st.Problem = "The home's public address could not be found: " + err.Error()
			s.keepState(ctx, st)
			return
		}
		st.PublicIP = address.String()
		if address.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(address) {
			st.Problem = "The internet sees this home at " + address.String() + ", which is not a public address: the provider shares one address between customers (carrier-grade NAT), so nothing at home can be reached from the internet this way. Ask the provider for a public address."
			s.keepState(ctx, st)
			return
		}
		for _, svc := range open {
			name := svc.Name + "." + domain
			want = append(want, wanted{kind: "A", name: name, value: address.String(), label: svc.Name})
			if svc.Kind != proxy.KindHTTP && svc.SRVService != "" {
				srv := dnsprovider.SRV{Name: "_" + svc.SRVService + "._" + svc.Kind + "." + name, Target: name,
					Priority: srvPriority, Weight: srvWeight, Port: svc.ListenPort}
				want = append(want, wanted{kind: "SRV", name: srv.Name, value: srvValue(srv), srv: srv, label: svc.Name})
			}
		}
	}

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	records := map[string]RecordState{}
	for _, w := range want {
		r := records[w.label]
		r.Name, r.Address = w.label+"."+domain, st.PublicIP
		records[w.label] = r
	}
	existingA, err := client.ARecords(ctx, domain)
	if err != nil {
		st.Problem = at + " could not be asked about the public names: " + err.Error()
		s.keepState(ctx, st)
		return
	}
	srvClient, hasSRV := dnsprovider.SupportsSRV(client)
	var existingSRV []dnsprovider.SRV
	if hasSRV {
		if existingSRV, err = srvClient.SRVRecords(ctx, domain); err != nil {
			st.Problem = at + " could not be asked about the service records: " + err.Error()
			s.keepState(ctx, st)
			return
		}
	}

	var kept []made
	// What SGC made and no longer wants, or made at another provider or
	// domain, goes (where it still can be reached).
	for _, m := range mine {
		stillWanted := false
		for _, w := range want {
			if m.Kind == w.kind && strings.EqualFold(m.Name, w.name) && m.Provider == account.Provider && m.Domain == domain {
				stillWanted = true
			}
		}
		if stillWanted {
			kept = append(kept, m)
			continue
		}
		if m.Provider != account.Provider || m.Domain != domain {
			// Another account now: SGC cannot reach that record any more.
			s.record(ctx, audit.ActorSystem, audit.ActionPublicRecordFailed,
				fmt.Sprintf("%s (%s) at %s is no longer SGC's to remove: the DNS account changed", m.Name, m.Kind, dnsprovider.Name(m.Provider)), "")
			continue
		}
		if !stillThere(m, existingA, existingSRV) {
			// Gone at the provider already: removed there by hand, or this
			// is a restored device whose old names went meanwhile.
			s.record(ctx, audit.ActorSystem, audit.ActionPublicRecordChanged, m.Name+" ("+m.Kind+") was already gone at "+at, "")
			continue
		}
		var err error
		if m.Kind == "A" {
			err = client.DeleteA(ctx, domain, m.ID)
		} else if hasSRV {
			err = srvClient.DeleteSRV(ctx, domain, m.ID)
		}
		if err != nil {
			st.Problem = at + " did not remove " + m.Name + ": " + err.Error()
			kept = append(kept, m)
			continue
		}
		s.record(ctx, audit.ActorSystem, audit.ActionPublicRecordChanged, m.Name+" ("+m.Kind+") removed", "")
	}

	for _, w := range want {
		r := records[w.label]
		var own *made
		for i := range kept {
			if kept[i].Kind == w.kind && strings.EqualFold(kept[i].Name, w.name) {
				own = &kept[i]
			}
		}
		switch w.kind {
		case "A":
			present := false
			var foreign string
			for _, e := range existingA {
				if !strings.EqualFold(e.Name, w.name) {
					continue
				}
				if own != nil && e.ID == own.ID {
					present = true
				} else {
					foreign = e.Value
				}
			}
			switch {
			case own != nil && present && own.Value == w.value:
				r.OK = true
			case own != nil && present:
				if err := client.UpdateA(ctx, domain, own.ID, w.name, w.value); err != nil {
					r.Problem = at + " did not take the new address for " + w.name + ": " + err.Error()
					break
				}
				own.Value, r.OK = w.value, true
				s.record(ctx, audit.ActorSystem, audit.ActionPublicRecordChanged, w.name+" → "+w.value, "")
			case foreign != "":
				r.Problem = at + " has a record for " + w.name + " (" + foreign + ") that SGC did not make: the name does not point at your home. Remove that record there, or close the service."
			default:
				if own != nil {
					// Removed at the provider by hand: made again.
					kept = dropMade(kept, *own)
				}
				created, err := client.AddA(ctx, domain, w.name, w.value)
				if err != nil {
					r.Problem = at + " did not take the record for " + w.name + ": " + err.Error()
					break
				}
				kept = append(kept, made{Provider: account.Provider, Domain: domain, Kind: "A", Name: w.name, ID: created.ID, Value: w.value})
				r.OK = true
				s.record(ctx, audit.ActorSystem, audit.ActionPublicRecordChanged, w.name+" → "+w.value+" (new)", "")
			}
		case "SRV":
			if !hasSRV {
				r.SRVManual = fmt.Sprintf("%s SRV %d %d %d %s.", w.name, srvPriority, srvWeight, w.srv.Port, w.srv.Target)
				continue
			}
			present := false
			for _, e := range existingSRV {
				if own != nil && e.ID == own.ID {
					present = srvValue(e) == own.Value
				}
			}
			if own != nil && present && own.Value == w.value {
				r.SRV = w.name
				break
			}
			if own != nil {
				if present {
					srvClient.DeleteSRV(ctx, domain, own.ID)
				}
				kept = dropMade(kept, *own)
			}
			created, err := srvClient.AddSRV(ctx, domain, w.srv)
			if err != nil {
				r.Problem = at + " did not take the service record " + w.name + ": " + err.Error()
				break
			}
			kept = append(kept, made{Provider: account.Provider, Domain: domain, Kind: "SRV", Name: w.name, ID: created.ID, Value: w.value})
			r.SRV = w.name
			s.record(ctx, audit.ActorSystem, audit.ActionPublicRecordChanged, w.name+" → "+w.value+" (new)", "")
		}
		records[w.label] = r
	}
	s.keepMade(ctx, kept)
	st.Records = records
	for _, r := range records {
		if r.Problem != "" && st.Problem == "" {
			st.Problem = r.Problem
		}
	}
	s.keepState(ctx, st)
}

// stillThere reports whether a record SGC made is among those the provider
// listed (every provider lists all of a domain's records of a kind). By its
// number and its name both: a number alone could, after a provider reused
// it, name someone else's record.
func stillThere(m made, a []dnsprovider.Record, srv []dnsprovider.SRV) bool {
	if m.Kind == "A" {
		return slices.ContainsFunc(a, func(e dnsprovider.Record) bool { return e.ID == m.ID && strings.EqualFold(e.Name, m.Name) })
	}
	return slices.ContainsFunc(srv, func(e dnsprovider.SRV) bool { return e.ID == m.ID && strings.EqualFold(e.Name, m.Name) })
}

func srvValue(r dnsprovider.SRV) string {
	return strconv.Itoa(r.Priority) + " " + strconv.Itoa(r.Weight) + " " + strconv.Itoa(r.Port) + " " + strings.TrimSuffix(r.Target, ".")
}

func dropMade(list []made, m made) []made {
	out := list[:0]
	for _, x := range list {
		if x != m {
			out = append(out, x)
		}
	}
	return out
}

// Run keeps the public names and the lists up to date until ctx ends.
func (s *Service) Run(ctx context.Context) {
	minute := time.NewTicker(time.Minute)
	defer minute.Stop()
	first := time.NewTimer(30 * time.Second)
	defer first.Stop()
	rounds := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
			s.keepRecords(ctx)
		case <-s.kick:
			s.keepRecords(ctx)
		case <-minute.C:
			rounds++
			if rounds%5 == 0 {
				s.keepRecords(ctx)
			}
			if s.refreshDue(ctx) {
				s.refresh(ctx)
			}
		}
	}
}

// PublicService is a public service as the page lists it.
type PublicService struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Title string `json:"title"`
	Kind  string `json:"kind"`
	// Port is what the router forwards from the internet: 443 for a web
	// service (to the door), the service's own port otherwise.
	Port      int         `json:"port"`
	LocalPort int         `json:"localPort"`
	URL       string      `json:"url"`
	Record    RecordState `json:"record"`
}

// Status is internet access as the page shows it.
type Status struct {
	Wanted bool `json:"wanted"`
	// DoorPort is where the router sends the internet's port 443.
	DoorPort   int    `json:"doorPort"`
	LANAddress string `json:"lanAddress"`
	PublicIP   string `json:"publicIp"`
	// Problem is what keeping the public names last ran into.
	Problem           string          `json:"problem"`
	Settings          Settings        `json:"settings"`
	Lists             []ListState     `json:"lists"`
	Fail2banInstalled bool            `json:"fail2banInstalled"`
	Services          []PublicService `json:"services"`
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	st := s.state(ctx)
	status := Status{Wanted: s.On(ctx), DoorPort: public.DoorPort, PublicIP: st.PublicIP, Problem: st.Problem,
		Settings: s.Settings(ctx), Lists: s.Lists(ctx), Fail2banInstalled: public.Fail2banInstalled(), Services: []PublicService{}}
	if lan, err := s.cfg.LAN(); err == nil {
		status.LANAddress = lan.Address.String()
	}
	list, err := s.cfg.Catalog.PublicServices(ctx)
	if err != nil {
		return Status{}, err
	}
	for _, svc := range list {
		p := PublicService{ID: svc.ID, Name: svc.Name, Title: svc.Title, Kind: svc.Kind, Port: 443, LocalPort: public.DoorPort, URL: svc.URL,
			Record: st.Records[svc.Name]}
		if svc.Kind != proxy.KindHTTP {
			p.Port, p.LocalPort = svc.ListenPort, svc.ListenPort
		}
		status.Services = append(status.Services, p)
	}
	return status, nil
}
