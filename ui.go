package main

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
)

type hostView struct {
	Domain   string     `json:"domain"`
	Aliases  []string   `json:"aliases"`
	Tags     []string   `json:"tags"`
	Disabled bool       `json:"disabled"` // host disabled in Zoraxy
	Known    bool       `json:"known"`    // false: a rule exists but Zoraxy has no such host any more
	HasRule  bool       `json:"has_rule"`
	Rule     Rule       `json:"rule"`
	Stats    *hostStats `json:"stats,omitempty"`
}

type stateView struct {
	Hosts           []hostView `json:"hosts"`
	StandardMethods []string   `json:"standard_methods"`
	SuggestedTag    string     `json:"suggested_tag"`
	HostsError      string     `json:"hosts_error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (a *app) handleState(w http.ResponseWriter, r *http.Request) {
	a.refreshHosts()
	cfg := a.cfg.Load()
	a.mu.RLock()
	defer a.mu.RUnlock()

	view := stateView{StandardMethods: StandardMethods, SuggestedTag: suggestedTag, HostsError: a.hostsErr, Hosts: []hostView{}}
	seen := map[string]bool{}
	add := func(domain string, hv hostView) {
		key := NormalizeHost(domain)
		seen[key] = true
		hv.Domain = key
		if rule, ok := cfg.Rules[key]; ok {
			hv.HasRule, hv.Rule = true, *rule
		} else {
			hv.Rule = Rule{Enabled: false, Methods: DefaultMethods, Status: DefaultStatus}
		}
		if st, ok := a.stats[key]; ok {
			c := *st
			hv.Stats = &c
		}
		view.Hosts = append(view.Hosts, hv)
	}
	for _, h := range a.hosts {
		add(h.RootOrMatchingDomain, hostView{Aliases: h.MatchingDomainAlias, Tags: h.Tags, Disabled: h.Disabled, Known: true})
	}
	orphans := []string{}
	for host := range cfg.Rules {
		if !seen[host] {
			orphans = append(orphans, host)
		}
	}
	sort.Strings(orphans)
	for _, host := range orphans {
		add(host, hostView{Known: len(a.hosts) == 0 && a.hostsErr != ""})
	}
	writeJSON(w, http.StatusOK, view)
}

func (a *app) handleSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	cfg := &Config{}
	if err := json.Unmarshal(body, cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	if err := cfg.Sanitize(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := saveConfig(cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot save: " + err.Error()})
		return
	}
	a.cfg.Store(cfg)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "saved"})
}
