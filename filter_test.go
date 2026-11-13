package main

import "testing"

var hosts = []HostEntry{
	{Domain: "app.example.com", Aliases: []string{"www.example.com"}},
	{Domain: "*.wild.example.org"},
	{Domain: "open.example.com"},
}

func cfg() *Config {
	return &Config{Rules: map[string]*Rule{
		"app.example.com":    {Enabled: true, Methods: []string{"GET", "HEAD", "POST"}, BlockHTTP10: true, Status: 405},
		"*.wild.example.org": {Enabled: true, Methods: []string{"GET"}, Status: 403},
		"off.example.com":    {Enabled: false, Methods: []string{"GET"}, Status: 405},
	}}
}

func TestDecide(t *testing.T) {
	cases := []struct {
		name, host, method string
		major, minor       int
		block              bool
		reason             string
		status             int
	}{
		{"allowed method", "app.example.com", "GET", 1, 1, false, "", 405},
		{"allowed over h2", "app.example.com", "POST", 2, 0, false, "", 405},
		{"refused method", "app.example.com", "OPTIONS", 1, 1, true, "method", 405},
		{"unknown method", "app.example.com", "PROPFIND", 1, 1, true, "method", 405},
		{"lower case is another method", "app.example.com", "get", 1, 1, true, "method", 405},
		{"port and case in host", "APP.Example.com:443", "DELETE", 1, 1, true, "method", 405},
		{"alias uses the rule of its host", "www.example.com", "PATCH", 1, 1, true, "method", 405},
		{"http 1.0 refused", "app.example.com", "GET", 1, 0, true, "http10", 405},
		{"http 1.0 allowed when not asked", "a.wild.example.org", "GET", 1, 0, false, "", 403},
		{"wildcard host", "a.wild.example.org", "POST", 1, 1, true, "method", 403},
		{"wildcard does not match apex", "wild.example.org", "POST", 1, 1, false, "", 0},
		{"host without rule", "open.example.com", "TRACE", 1, 1, false, "", 0},
		{"disabled rule", "off.example.com", "TRACE", 1, 1, false, "", 0},
		{"unknown host", "nope.example.net", "TRACE", 1, 1, false, "", 0},
	}
	for _, c := range cases {
		v := cfg().Decide(c.host, c.method, c.major, c.minor, hosts)
		if v.Block != c.block || v.Reason != c.reason || v.Status != c.status {
			t.Errorf("%s: got block=%v reason=%q status=%d, want block=%v reason=%q status=%d",
				c.name, v.Block, v.Reason, v.Status, c.block, c.reason, c.status)
		}
	}
}

func TestDecideWithoutHostList(t *testing.T) {
	v := cfg().Decide("app.example.com:8443", "TRACE", 1, 1, nil)
	if !v.Block {
		t.Error("rules must still apply by exact hostname when the host list is unavailable")
	}
}

func TestSanitize(t *testing.T) {
	c := &Config{Rules: map[string]*Rule{"App.Example.com:443": {Enabled: true, Methods: []string{" get", "GET", "post"}}}}
	if err := c.Sanitize(); err != nil {
		t.Fatal(err)
	}
	r := c.Rules["app.example.com"]
	if r == nil || len(r.Methods) != 2 || r.Methods[0] != "GET" || r.Methods[1] != "POST" || r.Status != 405 {
		t.Errorf("unexpected sanitized rule: %+v", r)
	}
	for name, bad := range map[string]*Config{
		"empty allow-list": {Rules: map[string]*Rule{"a.example.com": {Enabled: true}}},
		"bad method":       {Rules: map[string]*Rule{"a.example.com": {Enabled: true, Methods: []string{"GE T"}}}},
		"bad status":       {Rules: map[string]*Rule{"a.example.com": {Enabled: true, Methods: []string{"GET"}, Status: 200}}},
	} {
		if bad.Sanitize() == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
