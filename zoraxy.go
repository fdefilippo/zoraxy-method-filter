package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// zoraxyHost is the subset of Zoraxy's ProxyEndpoint that the plugin needs.
type zoraxyHost struct {
	RootOrMatchingDomain string
	MatchingDomainAlias  []string
	Disabled             bool
	Tags                 []string
}

const proxyListEndpoint = "/plugin/api/proxy/list"

var zoraxyClient = &http.Client{Timeout: 5 * time.Second}

// fetchHosts asks Zoraxy for the list of HTTP proxy hosts.
func fetchHosts(zoraxyPort int, apiKey string) ([]zoraxyHost, error) {
	form := url.Values{"type": {"host"}}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d%s", zoraxyPort, proxyListEndpoint), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := zoraxyClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("zoraxy answered %d: %.200s", resp.StatusCode, body)
	}
	var hosts []zoraxyHost
	if err := json.Unmarshal(body, &hosts); err != nil {
		return nil, fmt.Errorf("unexpected answer from zoraxy: %.200s", body)
	}
	return hosts, nil
}
