package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"golang.org/x/net/html"
)

// ---------------------------------------------------------------------------
// Discovery: SPF records
// ---------------------------------------------------------------------------

func extractIPsFromSPF(domain string) ([]string, error) {
	var ips []string
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return nil, err
	}

	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1") {
			parts := strings.Fields(txt)
			for _, part := range parts {
				if strings.HasPrefix(part, "ip4:") {
					ip := strings.TrimPrefix(part, "ip4:")
					if strings.Contains(ip, "/") {
						rangedIps, err := expandIPRange(ip)
						if err != nil {
							continue
						}
						ips = append(ips, rangedIps...)
					} else {
						ips = append(ips, ip)
					}
				} else if strings.HasPrefix(part, "ip6:") {
					ip := strings.TrimPrefix(part, "ip6:")
					ips = append(ips, ip)
				}
			}
		}
	}
	return ips, nil
}

// ---------------------------------------------------------------------------
// Discovery: MX records
// ---------------------------------------------------------------------------

func extractIPsFromMX(domain string) ([]string, error) {
	var ips []string
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return nil, err
	}

	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		lowerHost := strings.ToLower(host)
		if strings.Contains(lowerHost, "google") ||
			strings.Contains(lowerHost, "outlook") ||
			strings.Contains(lowerHost, "microsoft") ||
			strings.Contains(lowerHost, "mimecast") ||
			strings.Contains(lowerHost, "proofpoint") ||
			strings.Contains(lowerHost, "barracuda") ||
			strings.Contains(lowerHost, "pphosted") {
			continue
		}

		addrs, err := net.LookupHost(host)
		if err != nil {
			continue
		}
		ips = append(ips, addrs...)
	}
	return ips, nil
}

// ---------------------------------------------------------------------------
// Discovery: Common subdomains
// ---------------------------------------------------------------------------

func extractIPsFromSubdomains(ctx context.Context, domain string, customFile string, verbose bool) []string {
	var ips []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	subs := append([]string{}, originSubdomains...)
	if customFile != "" {
		f, err := os.Open(customFile)
		if err != nil {
			logWarn("Error opening custom subdomains file: %v", err)
		} else {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			count := 0
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					subs = append(subs, line)
					count++
				}
			}
			if err := scanner.Err(); err != nil {
				logWarn("Error reading custom subdomains file: %v", err)
			}
			if count > 0 {
				logInfo("Loaded %d custom subdomains from %s.", count, customFile)
			}
		}
	}

	// Deduplicate
	subMap := make(map[string]bool)
	var finalSubs []string
	for _, s := range subs {
		if !subMap[s] {
			subMap[s] = true
			finalSubs = append(finalSubs, s)
		}
	}

	for _, sub := range finalSubs {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}

			fqdn := subdomain
			// If it looks like a URL, extract host
			if strings.Contains(fqdn, "://") {
				if parts := strings.Split(fqdn, "://"); len(parts) > 1 {
					fqdn = parts[1]
				}
			}
			// Remove path/port if present
			if idx := strings.IndexAny(fqdn, "/:"); idx != -1 {
				fqdn = fqdn[:idx]
			}

			// If it doesn't contain the main domain, append it
			if !strings.HasSuffix(fqdn, "."+domain) && fqdn != domain {
				fqdn = fqdn + "." + domain
			}

			addrs, err := net.LookupHost(fqdn)
			if err != nil {
				return
			}
			mu.Lock()
			for _, addr := range addrs {
				if !isWAFIP(addr) && !isPrivateIP(addr) {
					ips = append(ips, addr)
					logVerbose(verbose, "Subdomain %s → %s", fqdn, addr)
				}
			}
			mu.Unlock()
		}(sub)
	}
	wg.Wait()
	return ips
}

// ---------------------------------------------------------------------------
// Discovery: Certificate Transparency (crt.sh)
// ---------------------------------------------------------------------------

func extractIPsFromCrtSh(ctx context.Context, domain string, verbose bool) ([]string, error) {
	urlStr := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}

	resp, err := doWithRetry(ctx, appHTTPClient, req, 1)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	var entries []CrtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("failed to parse crt.sh response: %w", err)
	}

	subdomainSet := make(map[string]bool)
	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")
			if name != "" && !subdomainSet[name] {
				subdomainSet[name] = true
			}
		}
	}

	logInfo("Found %d unique subdomains in CT logs.", len(subdomainSet))

	var ips []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for subdomain := range subdomainSet {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}
			sem <- struct{}{}
			defer func() { <-sem }()

			addrs, err := net.LookupHost(sub)
			if err != nil {
				return
			}
			mu.Lock()
			for _, addr := range addrs {
				if !isWAFIP(addr) && !isPrivateIP(addr) {
					ips = append(ips, addr)
					logVerbose(verbose, "CT subdomain %s → %s", sub, addr)
				}
			}
			mu.Unlock()
		}(subdomain)
	}
	wg.Wait()
	return ips, nil
}

// ---------------------------------------------------------------------------
// Discovery: AlienVault OTX (free, optional API key)
// ---------------------------------------------------------------------------

func fetchIPsFromOTX(ctx context.Context, domain, apiKey string) ([]string, error) {
	var ips []string
	urlStr := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	if apiKey != "" {
		req.Header.Set("X-OTX-API-KEY", apiKey)
	}

	resp, err := doWithRetry(ctx, appHTTPClient, req, 1)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("OTX returned status %d", resp.StatusCode)
	}

	var result struct {
		PassiveDNS []struct {
			Address    string `json:"address"`
			RecordType string `json:"record_type"`
		} `json:"passive_dns"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse OTX response: %v", err)
	}

	for _, record := range result.PassiveDNS {
		if record.RecordType == "A" || record.RecordType == "AAAA" {
			if net.ParseIP(record.Address) != nil {
				ips = append(ips, record.Address)
			}
		}
	}
	return ips, nil
}

// ---------------------------------------------------------------------------
// Discovery: RapidDNS (free, no key)
// ---------------------------------------------------------------------------

func fetchIPsFromRapidDNS(ctx context.Context, domain string, verbose bool) ([]string, error) {
	urlStr := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := doWithRetry(ctx, appHTTPClient, req, 1)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("RapidDNS returned status %d", resp.StatusCode)
	}

	// Parse HTML table to find subdomains
	subdomains := make(map[string]bool)
	z := html.NewTokenizer(resp.Body)
	inTD := false
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		token := z.Token()
		if token.Type == html.StartTagToken && token.Data == "td" {
			inTD = true
			continue
		}
		if token.Type == html.EndTagToken && token.Data == "td" {
			inTD = false
			continue
		}
		if inTD && token.Type == html.TextToken {
			text := strings.TrimSpace(token.Data)
			if strings.Contains(text, domain) && !strings.Contains(text, " ") {
				subdomains[text] = true
			}
		}
	}

	logInfo("Found %d subdomains from RapidDNS.", len(subdomains))

	// Resolve to IPs
	var ips []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for sub := range subdomains {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}
			sem <- struct{}{}
			defer func() { <-sem }()
			addrs, err := net.LookupHost(s)
			if err != nil {
				return
			}
			mu.Lock()
			for _, addr := range addrs {
				if !isWAFIP(addr) && !isPrivateIP(addr) {
					ips = append(ips, addr)
					logVerbose(verbose, "RapidDNS %s → %s", s, addr)
				}
			}
			mu.Unlock()
		}(sub)
	}
	wg.Wait()
	return ips, nil
}

// ---------------------------------------------------------------------------
// Discovery: HackerTarget (free, 50 req/day)
// ---------------------------------------------------------------------------

func fetchIPsFromHackerTarget(ctx context.Context, domain string) ([]string, error) {
	var ips []string
	urlStr := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, err
	}

	resp, err := doWithRetry(ctx, appHTTPClient, req, 0)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HackerTarget returned status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "error") || strings.HasPrefix(line, "API") {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		if len(parts) == 2 {
			ip := strings.TrimSpace(parts[1])
			if net.ParseIP(ip) != nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips, nil
}

// ---------------------------------------------------------------------------
// Discovery: Wayback Machine CDX API (free, no key)
// ---------------------------------------------------------------------------

func fetchIPsFromWayback(ctx context.Context, domain string, verbose bool) ([]string, error) {
	urlStr := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s&output=json&fl=original&collapse=urlkey&limit=500", url.QueryEscape(domain))

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, err
	}

	resp, err := doWithRetry(ctx, appHTTPClient, req, 1)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Wayback CDX returned status %d", resp.StatusCode)
	}

	var rows [][]string
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("failed to parse Wayback response: %v", err)
	}

	// Extract unique hostnames from URLs
	hostnames := make(map[string]bool)
	for i, row := range rows {
		if i == 0 {
			continue // skip header row
		}
		if len(row) < 1 {
			continue
		}
		parsed, err := url.Parse(row[0])
		if err != nil {
			continue
		}
		host := parsed.Hostname()
		if host != "" && strings.Contains(host, domain) {
			hostnames[host] = true
		}
	}

	logInfo("Found %d unique hostnames from Wayback Machine.", len(hostnames))

	// Resolve to IPs
	var ips []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for host := range hostnames {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}
			sem <- struct{}{}
			defer func() { <-sem }()
			addrs, err := net.LookupHost(h)
			if err != nil {
				return
			}
			mu.Lock()
			for _, addr := range addrs {
				if !isWAFIP(addr) && !isPrivateIP(addr) {
					ips = append(ips, addr)
					logVerbose(verbose, "Wayback %s → %s", h, addr)
				}
			}
			mu.Unlock()
		}(host)
	}
	wg.Wait()
	return ips, nil
}

// ---------------------------------------------------------------------------
// Discovery: ViewDNS (API key required, free tier: 250 requests)
// ---------------------------------------------------------------------------

func fetchIPsFromViewDNS(ctx context.Context, domain, apiKey string) ([]string, error) {
	var ips []string
	urlStr := fmt.Sprintf("https://api.viewdns.info/iphistory/?domain=%s&apikey=%s&output=json", domain, apiKey)

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, err
	}

	resp, err := doWithRetry(ctx, appHTTPClient, req, 1)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("received non-200 response code: %d", resp.StatusCode)
	}

	var result struct {
		Query    map[string]string `json:"query"`
		Response struct {
			Records []struct {
				IP string `json:"ip"`
			} `json:"records"`
		} `json:"response"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	for _, record := range result.Response.Records {
		ips = append(ips, record.IP)
	}
	return ips, nil
}

// ---------------------------------------------------------------------------
// Discovery: SecurityTrails (API key required, free tier available)
// ---------------------------------------------------------------------------

func fetchIPsFromSecurityTrails(ctx context.Context, domain, apiKey string) ([]string, error) {
	var ips []string
	urlStr := fmt.Sprintf("https://api.securitytrails.com/v1/history/%s/dns/a", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("APIKEY", apiKey)

	resp, err := doWithRetry(ctx, appHTTPClient, req, 1)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("received non-200 response code: %d", resp.StatusCode)
	}

	var result struct {
		Records []struct {
			Values []struct {
				IP string `json:"ip"`
			} `json:"values"`
		} `json:"records"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	for _, record := range result.Records {
		for _, value := range record.Values {
			ips = append(ips, value.IP)
		}
	}
	return ips, nil
}

// ---------------------------------------------------------------------------
// Discovery: Censys SSL certificate search (API key required, paid)
// ---------------------------------------------------------------------------

func fetchIPsFromCensys(ctx context.Context, domain, token, orgID string) ([]string, error) {
	var ips []string

	searchURL := "https://api.platform.censys.io/v3/global/search/query"
	if orgID != "" {
		searchURL += "?organization_id=" + orgID
	}

	query := fmt.Sprintf("cert.names: %s", domain)
	bodyData := fmt.Sprintf(`{"query":"%s","page_size":50}`, query)

	req, err := http.NewRequestWithContext(ctx, "POST", searchURL, strings.NewReader(bodyData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if orgID != "" {
		req.Header.Set("X-Organization-ID", orgID)
	}

	resp, err := doWithRetry(ctx, appHTTPClient, req, 1)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		hint := ""
		if resp.StatusCode == 403 {
			hint = " (Censys API requires a paid license with an Organization ID — free accounts cannot use the API)"
		}
		if resp.StatusCode == 401 {
			hint = " (check your PAT is valid at https://app.censys.io/account/api)"
		}
		return nil, fmt.Errorf("Censys Platform API returned status %d%s: %s", resp.StatusCode, hint, truncateStr(string(body), 200))
	}

	var searchResult struct {
		Result struct {
			Hits []struct {
				IP       string `json:"ip"`
				Services []struct {
					IP string `json:"ip"`
				} `json:"services"`
			} `json:"hits"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&searchResult); err != nil {
		return nil, fmt.Errorf("failed to parse Censys response: %v", err)
	}

	for _, hit := range searchResult.Result.Hits {
		if hit.IP != "" && !isWAFIP(hit.IP) {
			ips = append(ips, hit.IP)
		}
		for _, svc := range hit.Services {
			if svc.IP != "" && !isWAFIP(svc.IP) {
				ips = append(ips, svc.IP)
			}
		}
	}

	return ips, nil
}

// ---------------------------------------------------------------------------
// Discovery: Shodan (API key required, free tier available)
// ---------------------------------------------------------------------------

func fetchIPsFromShodan(ctx context.Context, domain, apiKey string, mmh3Hash int32) ([]string, error) {
	var allIPs []string

	queries := []string{
		fmt.Sprintf("ssl.cert.subject.cn:%s", domain),
		fmt.Sprintf("hostname:%s", domain),
	}
	if mmh3Hash != 0 {
		queries = append(queries, fmt.Sprintf("http.favicon.hash:%d", mmh3Hash))
	}

	for _, query := range queries {
		if ctx.Err() != nil {
			break
		}
		urlStr := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s&minify=true",
			apiKey, url.QueryEscape(query))

		req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
		if err != nil {
			continue
		}

		resp, err := doWithRetry(ctx, appHTTPClient, req, 1)
		if err != nil {
			continue
		}

		var result struct {
			Matches []struct {
				IPStr string `json:"ip_str"`
			} `json:"matches"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		for _, match := range result.Matches {
			if match.IPStr != "" {
				allIPs = append(allIPs, match.IPStr)
			}
		}
	}

	return allIPs, nil
}

// ---------------------------------------------------------------------------
// Discovery: DNSDB/Farsight (API key required, free Community Edition: 500 queries/month)
// ---------------------------------------------------------------------------

func fetchIPsFromDNSDB(ctx context.Context, domain, apiKey string) ([]string, error) {
	var ips []string
	urlStr := fmt.Sprintf("https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/*.%s/A", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Accept", "application/x-ndjson")

	resp, err := doWithRetry(ctx, appHTTPClient, req, 1)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DNSDB returned status %d", resp.StatusCode)
	}

	// Parse NDJSON
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var entry struct {
			Obj struct {
				RData []string `json:"rdata"`
			} `json:"obj"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		for _, rdata := range entry.Obj.RData {
			ip := strings.TrimSpace(rdata)
			if net.ParseIP(ip) != nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips, nil
}
