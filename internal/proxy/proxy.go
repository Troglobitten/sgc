// Package proxy is the root side of SGC's reverse proxy, Traefik: what its
// configuration may contain, how it is written, and how a change is put in
// place and checked (docs/design.md §4.5 and §10).
//
// The web process sends a typed description (Config): which names lead
// where, the certificate, which names are behind the login gate, who may
// reach what. Everything in it is checked here again, and the files Traefik
// reads are written from constants and from those checked values, as JSON
// (which is valid YAML, the format Traefik reads). Nothing the web process
// sends ends up in a file as text it chose.
//
// Used by the root helper: standard library only, no database, no network
// beyond asking Traefik on 127.0.0.1 whether it took the change.
package proxy

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Fixed places and numbers.
const (
	// TraefikAPI is where Traefik answers about itself, on this device only.
	TraefikAPI = "127.0.0.1:8082"
	// SGCInternal is SGC's second listener, for Traefik only: error pages,
	// the login gate, announcements that came through the proxy.
	SGCInternal = "127.0.0.1:8444"
	// GatePath is where a protected name hands the visitor's pass back to
	// SGC (docs/design.md §10).
	GatePath = "/.sgc-gate/"
	// AnnouncePath is where servers announce their services.
	AnnouncePath = "/api/announce"

	maxServices  = 500
	maxAllowList = 256
	maxPEM       = 64 * 1024
	// gateAnswerLimit is the most Traefik reads of SGC's answer to "may
	// this visitor in?" (a redirect or a one-line refusal).
	gateAnswerLimit = 64 * 1024
)

// Kinds of service.
const (
	KindHTTP = "http"
	KindTCP  = "tcp"
	KindUDP  = "udp"
)

// Service is one name the proxy answers for.
type Service struct {
	// Name is the label under the domain (validated like a host name label).
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Upstream and Port are where it really is.
	Upstream string `json:"upstream"`
	Port     int    `json:"port"`
	// Scheme is http or https, for KindHTTP.
	Scheme string `json:"scheme,omitempty"`
	// VerifyTLS: check the upstream's certificate (off by default: home
	// devices usually have a self-signed one).
	VerifyTLS bool `json:"verifyTLS,omitempty"`
	// ListenPort is the gateway's port for a proxied TCP or UDP service.
	ListenPort int `json:"listenPort,omitempty"`
	// Protected puts SGC's login gate in front (KindHTTP only).
	Protected bool `json:"protected,omitempty"`
	// AllowFrom, if not empty, is who may reach it; nobody else may.
	AllowFrom []string `json:"allowFrom,omitempty"`
}

// Config is everything that goes into Traefik's configuration.
type Config struct {
	Enabled bool `json:"enabled"`
	// Domain and GatewayName give the gateway's own name, which redirects
	// to SGC's page on WebPort.
	Domain      string `json:"domain"`
	GatewayName string `json:"gatewayName"`
	WebPort     int    `json:"webPort"`
	// The wildcard certificate for the domain, with its key.
	CertificatePEM string    `json:"certificatePem"`
	PrivateKeyPEM  string    `json:"privateKeyPem"`
	Services       []Service `json:"services"`
	// Reserved are ports the gateway itself uses, which no proxied service
	// may take (SSH, DNS, the VPN's).
	Reserved []int `json:"reserved,omitempty"`
}

// The ports SGC and its parts always use.
var alwaysReserved = []int{53, 80, 443, 3000, 8082, 8443, 8444}

// The ranges an upstream may be in: the home network's private ones. Not
// the device itself (127.0.0.0/8): that would put the proxy in front of
// what listens there only, such as AdGuard Home's page without a login.
var upstreamRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// ValidLabel is the rule for one label of a host name (see internal/gateway,
// which the root side cannot import: it uses the database).
func ValidLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return len(s) < 4 || s[2:4] != "--"
}

// ValidDomain is the rule for the owner's domain: at least two labels.
func ValidDomain(s string) bool {
	if len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !ValidLabel(label) {
			return false
		}
	}
	return true
}

// ValidUpstream reports whether an address may be a service's upstream.
func ValidUpstream(s string) bool {
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Is4() {
		return false
	}
	for _, r := range upstreamRanges {
		if r.Contains(addr) {
			return true
		}
	}
	return false
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

// Validate checks everything in a configuration. The web process checked it
// before sending; this is the check that counts.
func (c Config) Validate(now time.Time) error {
	if !c.Enabled {
		return nil
	}
	if !ValidDomain(c.Domain) {
		return errors.New("the domain is not a valid domain name")
	}
	if !ValidLabel(c.GatewayName) {
		return errors.New("the gateway's name is not a valid name")
	}
	if !validPort(c.WebPort) {
		return errors.New("the port of SGC's page is not a valid port")
	}
	if err := c.checkCertificate(now); err != nil {
		return err
	}
	if len(c.Services) > maxServices {
		return fmt.Errorf("more than %d services", maxServices)
	}
	reserved := map[int]bool{c.WebPort: true}
	for _, p := range append(slices.Clone(alwaysReserved), c.Reserved...) {
		if !validPort(p) {
			return errors.New("a reserved port is not a valid port")
		}
		reserved[p] = true
	}
	names := map[string]bool{c.GatewayName: true, "adguard": true}
	listen := map[string]bool{}
	for _, s := range c.Services {
		if !ValidLabel(s.Name) {
			return fmt.Errorf("%q is not a valid name", s.Name)
		}
		if names[s.Name] {
			return fmt.Errorf("the name %q is used twice", s.Name)
		}
		names[s.Name] = true
		if !ValidUpstream(s.Upstream) {
			return fmt.Errorf("%s: %q is not an address in the home network", s.Name, s.Upstream)
		}
		if !validPort(s.Port) {
			return fmt.Errorf("%s: %d is not a valid port", s.Name, s.Port)
		}
		switch s.Kind {
		case KindHTTP:
			if s.Scheme != "http" && s.Scheme != "https" {
				return fmt.Errorf("%s: the scheme is http or https", s.Name)
			}
			if s.ListenPort != 0 {
				return fmt.Errorf("%s: a web service has no port of its own on the gateway", s.Name)
			}
		case KindTCP, KindUDP:
			if s.Protected {
				return fmt.Errorf("%s: only web services can be behind the login", s.Name)
			}
			if !validPort(s.ListenPort) || reserved[s.ListenPort] {
				return fmt.Errorf("%s: port %d on the gateway is not free for a service", s.Name, s.ListenPort)
			}
			key := s.Kind + strconv.Itoa(s.ListenPort)
			if listen[key] {
				return fmt.Errorf("%s: port %d/%s is taken by another service", s.Name, s.ListenPort, s.Kind)
			}
			listen[key] = true
		default:
			return fmt.Errorf("%s: unknown kind %q", s.Name, s.Kind)
		}
		if len(s.AllowFrom) > maxAllowList {
			return fmt.Errorf("%s: too many entries in who may reach it", s.Name)
		}
		for _, prefix := range s.AllowFrom {
			if p, err := netip.ParsePrefix(prefix); err != nil || !p.Addr().Is4() || p.Masked() != p {
				return fmt.Errorf("%s: %q is not a range of addresses", s.Name, prefix)
			}
		}
	}
	return nil
}

func (c Config) checkCertificate(now time.Time) error {
	if len(c.CertificatePEM) > maxPEM || len(c.PrivateKeyPEM) > maxPEM {
		return errors.New("the certificate is larger than a certificate is")
	}
	pair, err := tls.X509KeyPair([]byte(c.CertificatePEM), []byte(c.PrivateKeyPEM))
	if err != nil {
		return errors.New("the certificate and its key do not fit together")
	}
	if !slices.Contains(pair.Leaf.DNSNames, "*."+c.Domain) {
		return fmt.Errorf("the certificate is not for *.%s", c.Domain)
	}
	if now.After(pair.Leaf.NotAfter) {
		return errors.New("the certificate has expired")
	}
	return nil
}

// ListenPorts returns the entry points the configuration needs beyond 80
// and 443, as "port/protocol", sorted. The firewall lets these in from
// inside.
func (c Config) ListenPorts() []string {
	var out []string
	if !c.Enabled {
		return out
	}
	for _, s := range c.Services {
		if s.Kind == KindTCP || s.Kind == KindUDP {
			out = append(out, strconv.Itoa(s.ListenPort)+"/"+s.Kind)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func entryPointName(port string) string { return strings.ReplaceAll(port, "/", "-") }

// RenderStatic writes Traefik's own settings: where it listens, where its
// routes are, what it logs. Only the entry points depend on the request.
func RenderStatic(cfg Config, dynamicDir string) ([]byte, error) {
	entryPoints := map[string]any{
		// Plain http only ever redirects to https.
		"web": map[string]any{"address": ":80", "http": map[string]any{
			"aliasHeadersStrategy": "delete",
			"redirections": map[string]any{
				"entryPoint": map[string]any{"to": "websecure", "scheme": "https", "permanent": true}}}},
		"websecure": map[string]any{"address": ":443", "http": noAliasHeaders()},
		// Traefik's own API and health answer, on this device only.
		"traefik": map[string]any{"address": TraefikAPI, "http": noAliasHeaders()},
	}
	for _, port := range cfg.ListenPorts() {
		number, protocol, _ := strings.Cut(port, "/")
		entryPoint := map[string]any{"address": ":" + number + "/" + protocol}
		if protocol == "tcp" {
			// Traefik can serve HTTP on any TCP entry point, so the same rule.
			entryPoint["http"] = noAliasHeaders()
		}
		entryPoints[entryPointName(port)] = entryPoint
	}
	static := map[string]any{
		"global":      map[string]any{"checkNewVersion": false, "sendAnonymousUsage": false},
		"entryPoints": entryPoints,
		"providers":   map[string]any{"file": map[string]any{"directory": dynamicDir, "watch": true}},
		// On the "traefik" entry point only, which listens on 127.0.0.1.
		"api":  map[string]any{"insecure": true, "dashboard": false},
		"ping": map[string]any{"entryPoint": "traefik"},
		"log":  map[string]any{"level": "WARN"},
		// Requests go to the journal, without headers (they carry cookies
		// and passwords).
		"accessLog": map[string]any{"format": "json", "fields": map[string]any{
			"defaultMode": "keep", "headers": map[string]any{"defaultMode": "drop"}}},
	}
	return marshal(static)
}

// noAliasHeaders makes Traefik drop request headers whose names stand for
// another header: PHP, CGI and the like read "X_SGC_User" as "X-SGC-User",
// so without this a visitor could pass a name of their choosing to a
// service behind the login gate, which empties only the real header.
func noAliasHeaders() map[string]any {
	return map[string]any{"aliasHeadersStrategy": "delete"}
}

// Names Traefik's routers and services get. Labels contain only letters,
// digits and hyphens, so these never need quoting.
func routerName(s Service) string { return s.Kind + "-" + s.Name }

// RenderDynamic writes the routes: one router and one upstream per service,
// the gateway's own name, the login gate, the friendly error pages.
func RenderDynamic(cfg Config, certFile, keyFile string) ([]byte, error) {
	host := func(label string) string { return "Host(`" + label + "." + cfg.Domain + "`)" }
	internal := "http://" + SGCInternal
	httpRouters := map[string]any{}
	httpServices := map[string]any{
		"sgc-internal": map[string]any{"loadBalancer": map[string]any{"servers": []any{map[string]any{"url": internal}}}},
	}
	middlewares := map[string]any{
		// The gateway's own name opens SGC's page, which SGC serves itself.
		"to-sgc-page": map[string]any{"redirectRegex": map[string]any{
			"regex": `^https://[^/]+(/.*)?$`, "replacement": "https://" + cfg.GatewayName + "." + cfg.Domain + ":" + strconv.Itoa(cfg.WebPort) + "${1}"}},
		"to-adguard-page": map[string]any{"redirectRegex": map[string]any{
			"regex": `^https://[^/]+.*$`, "replacement": "https://" + cfg.GatewayName + "." + cfg.Domain + ":" + strconv.Itoa(cfg.WebPort) + "/adguard/"}},
		// A friendly page when the device behind a name does not answer.
		"friendly-errors": map[string]any{"errors": map[string]any{
			"status": []string{"502-504"}, "service": "sgc-internal", "query": "/proxy-error/{status}"}},
		"login-gate": map[string]any{"forwardAuth": map[string]any{
			"address": internal + "/gate/check", "trustForwardHeader": false,
			"authResponseHeaders": []string{"X-SGC-User"},
			// SGC's answers here are a few hundred bytes; Traefik reads any
			// size unless told.
			"maxResponseBodySize": gateAnswerLimit}},
		// Visitors cannot pretend to be someone through this header.
		"no-user-header": map[string]any{"headers": map[string]any{"customRequestHeaders": map[string]any{"X-SGC-User": ""}}},
		"unknown-name":   map[string]any{"replacePath": map[string]any{"path": "/proxy-unknown"}},
	}
	tlsOn := map[string]any{}
	httpRouters["gateway"] = map[string]any{"rule": host(cfg.GatewayName), "entryPoints": []string{"websecure"},
		"service": "noop@internal", "middlewares": []string{"to-sgc-page"}, "tls": tlsOn}
	httpRouters["gateway-announce"] = map[string]any{"rule": host(cfg.GatewayName) + " && Path(`" + AnnouncePath + "`)",
		"entryPoints": []string{"websecure"}, "service": "sgc-internal", "tls": tlsOn, "priority": 10000}
	httpRouters["adguard"] = map[string]any{"rule": host("adguard"), "entryPoints": []string{"websecure"},
		"service": "noop@internal", "middlewares": []string{"to-adguard-page"}, "tls": tlsOn}
	// Any other name under the domain: SGC says that it does not know it.
	httpRouters["unknown"] = map[string]any{"rule": "HostRegexp(`^.+$`)", "entryPoints": []string{"websecure"},
		"service": "sgc-internal", "middlewares": []string{"unknown-name"}, "tls": tlsOn, "priority": 1}

	tcpRouters, tcpServices := map[string]any{}, map[string]any{}
	udpRouters, udpServices := map[string]any{}, map[string]any{}
	tcpMiddlewares := map[string]any{}
	transports := map[string]any{"skip-verify": map[string]any{"insecureSkipVerify": true}}
	for _, s := range cfg.Services {
		name := routerName(s)
		switch s.Kind {
		case KindHTTP:
			chain := []string{}
			if len(s.AllowFrom) > 0 {
				middlewares["allow-"+s.Name] = map[string]any{"ipAllowList": map[string]any{"sourceRange": s.AllowFrom}}
				chain = append(chain, "allow-"+s.Name)
			}
			chain = append(chain, "no-user-header")
			if s.Protected {
				chain = append(chain, "login-gate")
				// The gate's return path on this name goes to SGC.
				httpRouters["gate-"+s.Name] = map[string]any{"rule": host(s.Name) + " && PathPrefix(`" + GatePath + "`)",
					"entryPoints": []string{"websecure"}, "service": "sgc-internal", "tls": tlsOn, "priority": 10000}
			}
			chain = append(chain, "friendly-errors")
			httpRouters[name] = map[string]any{"rule": host(s.Name), "entryPoints": []string{"websecure"},
				"service": name, "middlewares": chain, "tls": tlsOn, "priority": 100}
			balancer := map[string]any{"servers": []any{map[string]any{"url": s.Scheme + "://" + s.Upstream + ":" + strconv.Itoa(s.Port)}},
				"passHostHeader": true}
			if s.Scheme == "https" && !s.VerifyTLS {
				balancer["serversTransport"] = "skip-verify"
			}
			httpServices[name] = map[string]any{"loadBalancer": balancer}
		case KindTCP:
			router := map[string]any{"entryPoints": []string{entryPointName(strconv.Itoa(s.ListenPort) + "/tcp")},
				"rule": "HostSNI(`*`)", "service": name}
			if len(s.AllowFrom) > 0 {
				tcpMiddlewares["allow-"+s.Name] = map[string]any{"ipAllowList": map[string]any{"sourceRange": s.AllowFrom}}
				router["middlewares"] = []string{"allow-" + s.Name}
			}
			tcpRouters[name] = router
			tcpServices[name] = map[string]any{"loadBalancer": map[string]any{"servers": []any{
				map[string]any{"address": s.Upstream + ":" + strconv.Itoa(s.Port)}}}}
		case KindUDP:
			// UDP has no middlewares in Traefik; who may reach a UDP port is
			// left to the firewall.
			udpRouters[name] = map[string]any{"entryPoints": []string{entryPointName(strconv.Itoa(s.ListenPort) + "/udp")}, "service": name}
			udpServices[name] = map[string]any{"loadBalancer": map[string]any{"servers": []any{
				map[string]any{"address": s.Upstream + ":" + strconv.Itoa(s.Port)}}}}
		}
	}
	dynamic := map[string]any{
		"http": map[string]any{"routers": httpRouters, "services": httpServices, "middlewares": middlewares, "serversTransports": transports},
		"tls": map[string]any{
			"certificates": []any{map[string]any{"certFile": certFile, "keyFile": keyFile}},
			"stores":       map[string]any{"default": map[string]any{"defaultCertificate": map[string]any{"certFile": certFile, "keyFile": keyFile}}},
			"options":      map[string]any{"default": map[string]any{"minVersion": "VersionTLS12"}},
		},
	}
	if len(tcpRouters) > 0 {
		tcp := map[string]any{"routers": tcpRouters, "services": tcpServices}
		if len(tcpMiddlewares) > 0 {
			tcp["middlewares"] = tcpMiddlewares
		}
		dynamic["tcp"] = tcp
	}
	if len(udpRouters) > 0 {
		dynamic["udp"] = map[string]any{"routers": udpRouters, "services": udpServices}
	}
	label, err := generationOf(dynamic, cfg.CertificatePEM)
	if err != nil {
		return nil, err
	}
	// No router uses it; it is there for Traefik to report (see Generation).
	middlewares[GenerationPrefix+label] = map[string]any{"headers": map[string]any{
		"customRequestHeaders": map[string]any{"X-SGC-Config": label}}}
	return marshal(dynamic)
}

// GenerationPrefix starts the name of the middleware that labels a routes
// file. Traefik reads a changed file a second or two after it was written
// (seen with 3.7.16), keeps the previous one when it cannot read the new
// one, and does not notice certificate files that change under the same
// name. So the label is a fingerprint of the routes and the certificate:
// a renewed certificate changes the routes file, which makes Traefik read
// the certificate again, and a change counts as in place only once Traefik
// reports the new label.
const GenerationPrefix = "config-"

func generationOf(dynamic map[string]any, certificatePEM string) (string, error) {
	routes, err := json.Marshal(dynamic)
	if err != nil {
		return "", err
	}
	sum := sha256.New()
	sum.Write(routes)
	sum.Write([]byte{0})
	sum.Write([]byte(certificatePEM))
	return hex.EncodeToString(sum.Sum(nil))[:16], nil
}

// Generation returns the label of a routes file RenderDynamic wrote, "" if
// it has none.
func Generation(routesFile []byte) string {
	var parsed struct {
		HTTP struct {
			Middlewares map[string]json.RawMessage `json:"middlewares"`
		} `json:"http"`
	}
	if json.Unmarshal(routesFile[bytes.IndexByte(routesFile, '\n')+1:], &parsed) != nil {
		return ""
	}
	for name := range parsed.HTTP.Middlewares {
		if label, ok := strings.CutPrefix(name, GenerationPrefix); ok {
			return label
		}
	}
	return ""
}

// ExpectedRouters lists the routers Traefik must report as enabled once a
// configuration is in place, by protocol ("http", "tcp", "udp").
func ExpectedRouters(cfg Config) map[string][]string {
	out := map[string][]string{"http": {"gateway@file", "gateway-announce@file", "adguard@file", "unknown@file"}}
	for _, s := range cfg.Services {
		out[s.Kind] = append(out[s.Kind], routerName(s)+"@file")
		if s.Protected {
			out["http"] = append(out["http"], "gate-"+s.Name+"@file")
		}
	}
	for kind := range out {
		slices.Sort(out[kind])
	}
	return out
}

// marshal writes JSON with sorted keys (encoding/json sorts map keys), so
// the same configuration always gives the same file.
func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("# Written by SGC from its database. Do not edit: SGC replaces this file.\n")
	encoder := json.NewEncoder(&b)
	// "&&" in a rule stays readable; nothing here is read by a browser.
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
