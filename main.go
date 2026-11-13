// Zoraxy plugin: per-host allow-list of HTTP methods.
//
// Zoraxy forwards every method to the upstream. This plugin uses dynamic
// capture to refuse requests whose method is not in the allow-list of the
// host (and, optionally, HTTP/1.0 requests). Everything is configured from
// the plugin UI inside Zoraxy.
package main

import (
	"embed"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	plugin "github.com/fdefilippo/zoraxy-method-filter/mod/zoraxy_plugin"
)

const (
	pluginID      = "org.defilippo.zoraxy.methodfilter"
	uiPath        = "/ui"
	sniffPath     = "/d_sniff"
	capturePath   = "/d_capture"
	suggestedTag  = "method-filter"
	hostsRefresh  = 30 * time.Second
	pendingMaxAge = 30 * time.Second
)

//go:embed www/*
var content embed.FS

type hostStats struct {
	Allowed     uint64 `json:"allowed"`
	Blocked     uint64 `json:"blocked"`
	LastSeen    int64  `json:"last_seen"`    // unix seconds of the last request seen for this host
	LastBlocked string `json:"last_blocked"` // short description of the last refused request
}

type pendingVerdict struct {
	v  Verdict
	at time.Time
}

type app struct {
	cfg atomic.Pointer[Config]

	mu       sync.RWMutex
	hosts    []zoraxyHost
	entries  []HostEntry
	hostsErr string
	stats    map[string]*hostStats

	pending sync.Map // request UUID -> pendingVerdict

	zoraxyPort int
	apiKey     string
}

func (a *app) refreshHosts() {
	hosts, err := fetchHosts(a.zoraxyPort, a.apiKey)
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.hostsErr = err.Error() // keep the previous list: rules must keep working
		return
	}
	entries := make([]HostEntry, 0, len(hosts))
	for _, h := range hosts {
		entries = append(entries, HostEntry{Domain: h.RootOrMatchingDomain, Aliases: h.MatchingDomainAlias})
	}
	a.hosts, a.entries, a.hostsErr = hosts, entries, ""
}

func (a *app) sniff(dsfr *plugin.DynamicSniffForwardRequest) plugin.SniffResult {
	reqHost := dsfr.Host
	if reqHost == "" {
		reqHost = dsfr.Hostname
	}
	a.mu.RLock()
	entries := a.entries
	a.mu.RUnlock()
	v := a.cfg.Load().Decide(reqHost, dsfr.Method, dsfr.ProtoMajor, dsfr.ProtoMinor, entries)

	a.mu.Lock()
	st := a.stats[v.Host]
	if st == nil {
		st = &hostStats{}
		a.stats[v.Host] = st
	}
	st.LastSeen = time.Now().Unix()
	if v.Block {
		st.Blocked++
		st.LastBlocked = fmt.Sprintf("%s %s %.40s %s from %s", time.Now().Format("2006-01-02 15:04:05"), v.Reason, dsfr.Method, dsfr.Proto, dsfr.RemoteAddr)
	} else {
		st.Allowed++
	}
	a.mu.Unlock()

	if !v.Block {
		return plugin.SniffResultSkip
	}
	a.pending.Store(dsfr.GetRequestUUID(), pendingVerdict{v: v, at: time.Now()})
	return plugin.SniffResultAccept
}

// capture answers a request that sniff decided to refuse.
func (a *app) capture(w http.ResponseWriter, r *http.Request) {
	status, allow := DefaultStatus, []string(nil)
	if p, ok := a.pending.LoadAndDelete(r.Header.Get("X-Zoraxy-RequestID")); ok {
		status, allow = p.(pendingVerdict).v.Status, p.(pendingVerdict).v.Allow
	}
	if status == http.StatusMethodNotAllowed && len(allow) > 0 {
		w.Header().Set("Allow", strings.Join(allow, ", "))
	}
	w.Header().Set("Connection", "close")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, "%d %s\n", status, http.StatusText(status))
}

func (a *app) janitor() {
	for range time.Tick(pendingMaxAge) {
		a.pending.Range(func(k, v any) bool {
			if time.Since(v.(pendingVerdict).at) > pendingMaxAge {
				a.pending.Delete(k)
			}
			return true
		})
	}
}

func main() {
	runtimeCfg, err := plugin.ServeAndRecvSpec(&plugin.IntroSpect{
		ID:            pluginID,
		Name:          "HTTP Method Filter",
		Author:        "Defilippo srl",
		AuthorContact: "info@defilippo.org",
		Description:   "Per-host allow-list of HTTP methods (and optional HTTP/1.0 block), configured from the UI. Add the plugin to a tag and put that tag on the hosts to filter.",
		URL:           "https://github.com/fdefilippo/zoraxy-method-filter",
		Type:          plugin.PluginType_Router,
		VersionMajor:  1,
		VersionMinor:  0,
		VersionPatch:  1,

		DynamicCaptureSniff:   sniffPath,
		DynamicCaptureIngress: capturePath,
		UIPath:                uiPath,

		PermittedAPIEndpoints: []plugin.PermittedAPIEndpoint{{
			Method:   http.MethodPost,
			Endpoint: proxyListEndpoint,
			Reason:   "List the proxy hosts (names, aliases, tags) so a method rule can be set for each of them",
		}},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "method-filter: cannot start:", err)
		os.Exit(1)
	}

	a := &app{stats: map[string]*hostStats{}, zoraxyPort: runtimeCfg.ZoraxyPort, apiKey: runtimeCfg.APIKey}
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "method-filter: config ignored, starting with no rules:", err)
	}
	a.cfg.Store(cfg)
	a.refreshHosts()
	go func() {
		for range time.Tick(hostsRefresh) {
			a.refreshHosts()
		}
	}()
	go a.janitor()

	mux := http.NewServeMux()
	router := plugin.NewPathRouter()
	router.RegisterDynamicSniffHandler(sniffPath, mux, a.sniff)
	router.RegisterDynamicCaptureHandle(capturePath, mux, a.capture)

	ui := plugin.NewPluginEmbedUIRouter(pluginID, &content, "/www", uiPath)
	ui.RegisterTerminateHandler(func() {}, mux)
	mux.HandleFunc(uiPath+"/api/state", a.handleState)
	mux.HandleFunc(uiPath+"/api/save", a.handleSave)
	mux.Handle(uiPath+"/", ui.Handler())

	addr := "127.0.0.1:" + strconv.Itoa(runtimeCfg.Port)
	fmt.Println("method-filter listening on", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, "method-filter:", err)
		os.Exit(1)
	}
}
