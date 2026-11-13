package main

import (
	"errors"
	"net"
	"sort"
	"strings"
)

// Rule is the method policy of one proxy host.
type Rule struct {
	Enabled     bool     `json:"enabled"`      // when false the host is not filtered at all
	Methods     []string `json:"methods"`      // allowed HTTP methods (upper case)
	BlockHTTP10 bool     `json:"block_http10"` // also refuse HTTP/1.0 (and older) requests
	Status      int      `json:"status"`       // status code answered to refused requests
}

// Config maps the primary hostname of a proxy host to its rule.
type Config struct {
	Rules map[string]*Rule `json:"rules"`
}

// HostEntry is a proxy host known to Zoraxy, with its alias hostnames.
type HostEntry struct {
	Domain  string
	Aliases []string
}

// Verdict is the outcome of checking one request against the config.
type Verdict struct {
	Host   string // primary hostname the request was matched to ("" when unknown)
	Block  bool
	Reason string // "method" or "http10", only set when Block is true
	Status int
	Allow  []string // allowed methods, for the Allow response header
}

const DefaultStatus = 405

// StandardMethods are the methods offered as checkboxes in the UI.
var StandardMethods = []string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE"}

// DefaultMethods is the allow-list proposed for a host that has no rule yet.
var DefaultMethods = []string{"GET", "HEAD", "POST", "PUT", "DELETE"}

// NormalizeHost lower-cases a Host header value and strips port and trailing dot.
func NormalizeHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	return strings.TrimSuffix(h, ".")
}

// matchPattern reports whether host matches a Zoraxy hostname, which may be a
// wildcard such as "*.example.com".
func matchPattern(pattern, host string) bool {
	pattern = NormalizeHost(pattern)
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(host, pattern[1:]) && len(host) > len(pattern)-1
	}
	return false
}

// ResolveHost maps a request hostname to the primary hostname of its proxy
// host. Exact names win over wildcards. When the host list is not available
// the request hostname is returned unchanged, so rules keep working.
func ResolveHost(reqHost string, hosts []HostEntry) string {
	h := NormalizeHost(reqHost)
	wildcard := ""
	for _, e := range hosts {
		for _, name := range append([]string{e.Domain}, e.Aliases...) {
			if NormalizeHost(name) == h {
				return NormalizeHost(e.Domain)
			}
			if wildcard == "" && matchPattern(name, h) {
				wildcard = NormalizeHost(e.Domain)
			}
		}
	}
	if wildcard != "" {
		return wildcard
	}
	return h
}

// Decide checks one request. Requests for hosts without an enabled rule are
// never blocked.
func (c *Config) Decide(reqHost, method string, protoMajor, protoMinor int, hosts []HostEntry) Verdict {
	v := Verdict{Host: ResolveHost(reqHost, hosts)}
	rule, ok := c.Rules[v.Host]
	if !ok || rule == nil || !rule.Enabled {
		return v
	}
	v.Status = rule.Status
	if v.Status == 0 {
		v.Status = DefaultStatus
	}
	v.Allow = rule.Methods
	if rule.BlockHTTP10 && (protoMajor < 1 || (protoMajor == 1 && protoMinor < 1)) {
		v.Block, v.Reason = true, "http10"
		return v
	}
	for _, m := range rule.Methods {
		if m == method { // HTTP methods are case-sensitive (RFC 9110)
			return v
		}
	}
	v.Block, v.Reason = true, "method"
	return v
}

func isToken(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

// Sanitize validates and normalizes a config received from the UI or disk.
func (c *Config) Sanitize() error {
	if c.Rules == nil {
		c.Rules = map[string]*Rule{}
	}
	clean := map[string]*Rule{}
	for host, r := range c.Rules {
		h := NormalizeHost(host)
		if h == "" || r == nil {
			return errors.New("empty host name or rule")
		}
		seen := map[string]bool{}
		methods := []string{}
		for _, m := range r.Methods {
			m = strings.ToUpper(strings.TrimSpace(m))
			if m == "" || seen[m] {
				continue
			}
			if !isToken(m) {
				return errors.New("invalid HTTP method name: " + m)
			}
			seen[m] = true
			methods = append(methods, m)
		}
		sort.Strings(methods)
		if r.Enabled && len(methods) == 0 {
			return errors.New(h + ": an enabled rule needs at least one allowed method")
		}
		if r.Status == 0 {
			r.Status = DefaultStatus
		}
		if r.Status < 400 || r.Status > 599 {
			return errors.New(h + ": status code must be between 400 and 599")
		}
		clean[h] = &Rule{Enabled: r.Enabled, Methods: methods, BlockHTTP10: r.BlockHTTP10, Status: r.Status}
	}
	c.Rules = clean
	return nil
}
