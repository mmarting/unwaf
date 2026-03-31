package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"
)

const version = "3.0.0"

func main() {
	domain := flag.String("domain", "", "The domain to check")
	flag.StringVar(domain, "d", "", "The domain to check (shorthand)")
	source := flag.String("source", "", "The source HTML file to compare")
	flag.StringVar(source, "s", "", "The source HTML file to compare (shorthand)")
	configPath := flag.String("config", filepath.Join(os.Getenv("HOME"), ".unwaf.conf"), "The config file path")
	flag.StringVar(configPath, "c", filepath.Join(os.Getenv("HOME"), ".unwaf.conf"), "The config file path (shorthand)")
	threshold := flag.Float64("threshold", 60, "Similarity threshold percentage")
	flag.Float64Var(threshold, "t", 60, "Similarity threshold percentage (shorthand)")
	numWorkers := flag.Int("workers", 50, "Number of concurrent workers")
	flag.IntVar(numWorkers, "w", 50, "Number of concurrent workers (shorthand)")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	flag.BoolVar(verbose, "v", false, "Enable verbose output (shorthand)")
	quiet := flag.Bool("quiet", false, "Silent mode: only output bypass IPs, one per line")
	flag.BoolVar(quiet, "q", false, "Silent mode (shorthand)")
	help := flag.Bool("help", false, "Display help information")
	flag.BoolVar(help, "h", false, "Display help information (shorthand)")

	// New flags
	showVersion := flag.Bool("version", false, "Print version and exit")
	timeoutSec := flag.Int("timeout", 10, "HTTP timeout in seconds")
	rateLimit := flag.Int("rate-limit", 0, "Max HTTP requests per second (0=unlimited)")
	proxyURL := flag.String("proxy", "", "Proxy URL (http:// or socks5://)")
	scanNeighbors := flag.Bool("scan-neighbors", false, "Scan /24 neighbors of confirmed bypass IPs")
	jsonOutput := flag.Bool("json", false, "Output results as JSON")
	listFile := flag.String("list", "", "File containing domains to check, one per line")
	flag.StringVar(listFile, "l", "", "File containing domains (shorthand)")
	outputFile := flag.String("output", "", "Write results to file")
	flag.StringVar(outputFile, "o", "", "Write results to file (shorthand)")
	ipListFile := flag.String("ip-list", "", "File containing custom IPs to check, one per line")
	flag.StringVar(ipListFile, "I", "", "File containing custom IPs (shorthand)")

	flag.Parse()

	if *showVersion {
		fmt.Printf("unwaf v%s\n", version)
		os.Exit(0)
	}

	if *help || (*domain == "" && *listFile == "") {
		showUsage()
		os.Exit(1)
	}

	// Set up context with signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Initialize HTTP client
	timeout := time.Duration(*timeoutSec) * time.Second
	appHTTPClient = newHTTPClient(timeout, *proxyURL)

	// Initialize rate limiter
	if *rateLimit > 0 {
		rateLimiter = rate.NewLimiter(rate.Limit(*rateLimit), *rateLimit)
	}

	// Silent mode for JSON or quiet
	silent = *quiet || *jsonOutput

	// Collect domains
	var domains []string
	if *listFile != "" {
		f, err := os.Open(*listFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening list file: %v\n", err)
			os.Exit(1)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			d := sanitizeDomain(line)
			if d != "" {
				domains = append(domains, d)
			}
		}
		f.Close()
		if len(domains) == 0 {
			fmt.Fprintln(os.Stderr, "Error: no valid domains in list file.")
			os.Exit(1)
		}
	}
	if *domain != "" {
		d := sanitizeDomain(*domain)
		if d == "" {
			fmt.Fprintln(os.Stderr, "Error: invalid domain after sanitization.")
			os.Exit(1)
		}
		domains = append(domains, d)
	}

	if len(domains) == 0 {
		showUsage()
		os.Exit(1)
	}

	// Collect custom IPs
	var customIPs []string
	if *ipListFile != "" {
		f, err := os.Open(*ipListFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening IP list file: %v\n", err)
			os.Exit(1)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Basic IP validation
			if ip := net.ParseIP(line); ip != nil {
				customIPs = append(customIPs, line)
			}
		}
		f.Close()
	}

	portTimeout := timeout / 5
	if portTimeout < 2*time.Second {
		portTimeout = 2 * time.Second
	}

	opts := &processOptions{
		source:        *source,
		configPath:    *configPath,
		threshold:     *threshold,
		workers:       *numWorkers,
		verbose:       *verbose,
		scanNeighbors: *scanNeighbors,
		jsonMode:      *jsonOutput,
		outputFile:    *outputFile,
		portTimeout:   portTimeout,
		customIPs:     customIPs,
	}

	if *jsonOutput && len(domains) > 1 {
		// Batch JSON: array of results
		var allOutputs []JSONOutput
		for _, d := range domains {
			if ctx.Err() != nil {
				break
			}
			result := processDomain(ctx, d, opts)
			if result != nil {
				allOutputs = append(allOutputs, *result)
			}
		}
		data, _ := json.MarshalIndent(allOutputs, "", "  ")
		if *outputFile != "" {
			os.WriteFile(*outputFile, data, 0644)
		} else {
			fmt.Println(string(data))
		}
	} else if *jsonOutput {
		result := processDomain(ctx, domains[0], opts)
		if result != nil {
			writeJSONOutput(result, *outputFile)
		}
	} else {
		for _, d := range domains {
			if ctx.Err() != nil {
				break
			}
			if !silent {
				fmt.Print(logo)
				dimWhite.Printf("  v%s — Passive WAF bypass tool by Martín Martín\n", version)
				dimWhite.Printf("  Target: %s\n", d)
			}
			result := processDomain(ctx, d, opts)
			if !*jsonOutput && *outputFile != "" && result != nil && len(result.Bypasses) > 0 {
				writeTextOutput(result.Bypasses, *outputFile)
			}
		}
	}
}

type processOptions struct {
	source        string
	configPath    string
	threshold     float64
	workers       int
	verbose       bool
	scanNeighbors bool
	jsonMode      bool
	outputFile    string
	portTimeout   time.Duration
	customIPs     []string
}

type discoveryStep struct {
	name    string
	label   string
	enabled bool
	run     func() ([]string, error)
}

func processDomain(ctx context.Context, domain string, opts *processOptions) *JSONOutput {
	config, err := loadConfig(opts.configPath)
	if err != nil {
		config = &Config{}
	}

	mainDomain := extractMainDomain(domain)

	jsonOut := &JSONOutput{
		Version:   version,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Domain:    domain,
		Sources:   make(map[string]int),
	}

	// ── Dynamic Cloudflare CIDRs ──
	beforeCF := wafCIDRCount()
	fetchCloudflareRanges(ctx, appHTTPClient)
	afterCF := wafCIDRCount()
	if diff := afterCF - beforeCF; diff > 0 {
		logVerbose(opts.verbose, "Added %d dynamic Cloudflare CIDRs", diff)
	}

	// ── WAF Detection ──
	sectionHeader("WAF Detection")

	currentIPs, dnsErr := net.LookupHost(domain)
	if dnsErr != nil {
		logError("Could not resolve domain %s: %v", domain, dnsErr)
		return nil
	}

	jsonOut.CurrentIPs = currentIPs

	currentIPSet := make(map[string]bool)
	for _, ip := range currentIPs {
		currentIPSet[ip] = true
	}

	behindWAF := false
	for _, ip := range currentIPs {
		if isWAFIP(ip) {
			behindWAF = true
			break
		}
	}

	wafName := detectWAF(ctx, domain, appHTTPClient)

	if wafName != "Unknown" {
		logFound("Detected WAF: %s", wafName)
		behindWAF = true
	} else if behindWAF {
		logFound("Domain resolves to known WAF/CDN IP range.")
	}

	jsonOut.WAFDetected = behindWAF
	jsonOut.WAFName = wafName

	logInfo("Current DNS A records: %s", strings.Join(currentIPs, ", "))

	if !behindWAF {
		logWarn("Domain does NOT appear to be behind a WAF/CDN.")
		logWarn("Current IPs (%s) are not in known WAF/CDN ranges.", strings.Join(currentIPs, ", "))
		logWarn("The domain may be directly accessible — no bypass needed.")
		logInfo("Continuing anyway in case of an unrecognized WAF...")
	}

	// ── Favicon Hashes ──
	sectionHeader("Favicon Fingerprint")
	faviconHashes := getFaviconHashes(ctx, domain)
	var mmh3Hash int32
	if faviconHashes != nil {
		logFound("Favicon MD5:    %s", faviconHashes.MD5)
		logFound("Favicon SHA256: %s", faviconHashes.SHA256)
		logFound("Favicon MMH3:   %d", faviconHashes.MMH3)
		logInfo("Shodan query: http.favicon.hash:%d", faviconHashes.MMH3)
		mmh3Hash = faviconHashes.MMH3
		jsonOut.FaviconMD5 = faviconHashes.MD5
		jsonOut.FaviconSHA256 = faviconHashes.SHA256
		jsonOut.FaviconMMH3 = faviconHashes.MMH3
	} else {
		logWarn("No favicon found or could not be fetched.")
	}

	// ── Fetch original HTML + headers ──
	sectionHeader("Reference HTML")
	var originalHTML string
	var originalStatusCode int
	var originalHeaders http.Header
	if opts.source != "" {
		content, err := os.ReadFile(opts.source)
		if err != nil {
			logError("Error reading source HTML file: %v", err)
			return nil
		}
		originalHTML = string(content)
		logFound("Loaded reference HTML from file: %s", opts.source)
	} else {
		var fetchErr error
		originalHTML, originalStatusCode, originalHeaders, fetchErr = fetchHTMLWithHeaders(ctx, "https://"+domain, "")
		if fetchErr != nil {
			originalHTML, originalStatusCode, originalHeaders, fetchErr = fetchHTMLWithHeaders(ctx, "http://"+domain, "")
			if fetchErr != nil {
				logError("Error fetching original HTML. The WAF might be blocking.")
				logInfo("Try providing the HTML manually using --source / -s.")
				return nil
			}
		}
		logFound("Fetched reference HTML from %s (%d chars, status %d)", domain, len(originalHTML), originalStatusCode)
		if originalStatusCode >= 400 {
			logWarn("Reference response returned HTTP %d — the WAF may be blocking our request.", originalStatusCode)
			logWarn("Results may be unreliable (comparing against an error page).")
			logInfo("Consider providing the real HTML manually using --source / -s.")
		}
	}

	// ── IP Discovery ──
	sectionHeader("IP Discovery")
	var allIPs []string
	ipSources := make(map[string]string)

	addIPs := func(source string, ips []string) {
		for _, ip := range ips {
			if !isWAFIP(ip) && !isPrivateIP(ip) {
				if _, exists := ipSources[ip]; !exists {
					ipSources[ip] = source
				}
			}
		}
		allIPs = append(allIPs, ips...)
		jsonOut.Sources[source] = len(ips)
	}

	// Add custom IPs first if provided
	if len(opts.customIPs) > 0 {
		addIPs("Custom IP List", opts.customIPs)
	}

	// Build dynamic discovery steps
	steps := []discoveryStep{
		{name: "SPF", label: "SPF Records", enabled: true, run: func() ([]string, error) {
			return extractIPsFromSPF(mainDomain)
		}},
		{name: "MX", label: "MX Records", enabled: true, run: func() ([]string, error) {
			return extractIPsFromMX(mainDomain)
		}},
		{name: "Subdomain", label: "Common Origin Subdomains", enabled: true, run: func() ([]string, error) {
			return extractIPsFromSubdomains(ctx, mainDomain, opts.verbose), nil
		}},
		{name: "CT/crt.sh", label: "Certificate Transparency (crt.sh)", enabled: true, run: func() ([]string, error) {
			return extractIPsFromCrtSh(ctx, mainDomain, opts.verbose)
		}},
		{name: "OTX", label: "AlienVault OTX Passive DNS", enabled: true, run: func() ([]string, error) {
			return fetchIPsFromOTX(ctx, mainDomain, config.OTXAPIKey)
		}},
		{name: "RapidDNS", label: "RapidDNS Subdomains", enabled: true, run: func() ([]string, error) {
			return fetchIPsFromRapidDNS(ctx, mainDomain, opts.verbose)
		}},
		{name: "HackerTarget", label: "HackerTarget Host Search", enabled: true, run: func() ([]string, error) {
			return fetchIPsFromHackerTarget(ctx, mainDomain)
		}},
		{name: "Wayback", label: "Wayback Machine Archives", enabled: true, run: func() ([]string, error) {
			return fetchIPsFromWayback(ctx, mainDomain, opts.verbose)
		}},
		{name: "ViewDNS", label: "ViewDNS IP History", enabled: config.ViewDNS != "", run: func() ([]string, error) {
			return fetchIPsFromViewDNS(ctx, mainDomain, config.ViewDNS)
		}},
		{name: "SecurityTrails", label: "SecurityTrails DNS History", enabled: config.SecurityTrails != "", run: func() ([]string, error) {
			return fetchIPsFromSecurityTrails(ctx, mainDomain, config.SecurityTrails)
		}},
		{name: "Censys", label: "Censys SSL Certificate Search", enabled: config.CensysToken != "", run: func() ([]string, error) {
			return fetchIPsFromCensys(ctx, mainDomain, config.CensysToken, config.CensysOrgID)
		}},
		{name: "Shodan", label: "Shodan Host Search", enabled: config.ShodanAPIKey != "", run: func() ([]string, error) {
			return fetchIPsFromShodan(ctx, mainDomain, config.ShodanAPIKey, mmh3Hash)
		}},
		{name: "DNSDB", label: "DNSDB Historical DNS", enabled: config.DNSDBAPIKey != "", run: func() ([]string, error) {
			return fetchIPsFromDNSDB(ctx, mainDomain, config.DNSDBAPIKey)
		}},
	}

	totalSteps := 0
	for _, s := range steps {
		if s.enabled {
			totalSteps++
		}
	}

	stepNum := 0
	for _, step := range steps {
		if ctx.Err() != nil {
			break
		}

		if step.enabled {
			stepNum++
			if !silent {
				fmt.Println()
				boldWhite.Printf("  [%d/%d] %s\n", stepNum, totalSteps, step.label)
			}
			ips, err := step.run()
			if err != nil {
				logWarn("%s error: %v", step.name, err)
			} else {
				logInfo("Found %d IP(s) from %s.", len(ips), step.name)
				addIPs(step.name, ips)
			}
		} else if !silent {
			// Show skipped API steps
			switch step.name {
			case "ViewDNS":
				fmt.Println()
				boldWhite.Printf("  [skip] %s\n", step.label)
				dimWhite.Println("    Skipped — no API key. Add viewdns=<key> to config.")
			case "SecurityTrails":
				fmt.Println()
				boldWhite.Printf("  [skip] %s\n", step.label)
				dimWhite.Println("    Skipped — no API key. Add securitytrails=<key> to config.")
			case "Censys":
				fmt.Println()
				boldWhite.Printf("  [skip] %s\n", step.label)
				dimWhite.Println("    Skipped — no API key. Add censys_token + censys_org_id to config.")
				dimWhite.Println("    Note: Censys API requires a paid license with an Organization ID.")
			case "Shodan":
				fmt.Println()
				boldWhite.Printf("  [skip] %s\n", step.label)
				dimWhite.Println("    Skipped — no API key. Add shodan_api_key=<key> to config.")
			case "DNSDB":
				fmt.Println()
				boldWhite.Printf("  [skip] %s\n", step.label)
				dimWhite.Println("    Skipped — no API key. Add dnsdb_api_key=<key> to config.")
			}
		}
	}

	// Filter and deduplicate
	uniqueIPs := unique(allIPs)

	var candidateIPs []string
	for _, ip := range uniqueIPs {
		if !isWAFIP(ip) && !isPrivateIP(ip) && !currentIPSet[ip] {
			candidateIPs = append(candidateIPs, ip)
		}
	}

	sectionHeader("Summary")
	logInfo("Total IPs collected: %d", len(allIPs))
	logInfo("Unique IPs: %d", len(uniqueIPs))
	logInfo("After filtering WAF/CDN + current domain IPs: %d candidate(s)", len(candidateIPs))
	jsonOut.CandidateIPs = len(candidateIPs)

	if len(candidateIPs) == 0 {
		if !silent {
			fmt.Println()
			boldRed.Println("  ✗ No candidate IPs found. WAF bypass not possible with passive methods.")
			fmt.Println()
		}
		return jsonOut
	}

	// ── Port Scanning ──
	sectionHeader("Web Server Detection")
	logInfo("Scanning %d candidate IPs on ports %v...", len(candidateIPs), webPorts)

	var webServers []webServerResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, opts.workers)

	bar := newProgressBar(len(candidateIPs), "Scanning")

	for _, ip := range candidateIPs {
		wg.Add(1)
		go func(ip string) {
			sem <- struct{}{}
			defer func() { <-sem }()
			checkWebServer(ctx, ip, opts.portTimeout, &wg, &mu, &webServers, bar, len(candidateIPs))
		}(ip)
	}
	wg.Wait()
	bar.Finish()

	if !silent {
		fmt.Printf("  Scanning complete: %d/%d IPs have a web server.\n", len(webServers), len(candidateIPs))
	}

	jsonOut.WebServers = len(webServers)

	if len(webServers) == 0 {
		if !silent {
			fmt.Println()
			boldRed.Println("  ✗ No web servers found on candidate IPs. WAF bypass not found.")
			fmt.Println()
		}
		return jsonOut
	}

	// ── HTML Comparison + Verification ──
	sectionHeader("Origin Server Verification")
	logInfo("Comparing HTML responses from %d web servers (threshold: %.0f%%)...", len(webServers), opts.threshold)
	logInfo("Testing both direct IP access and Host-header injection.")

	var bypassResults []BypassResult

	verifyBar := newProgressBar(len(webServers), "Verifying")

	for _, ws := range webServers {
		if ctx.Err() != nil {
			break
		}
		for _, port := range ws.Ports {
			var scheme string
			if isTLSPort(port) {
				scheme = "https"
			} else {
				scheme = "http"
			}

			urlStr := fmt.Sprintf("%s://%s:%d", scheme, ws.IP, port)

			// Method 1: Direct IP access
			fetchedHTML, statusCode, candHeaders, fetchErr := fetchHTMLWithHeaders(ctx, urlStr, "")
			if fetchErr == nil && statusCode < 500 && !responseHasWAFHeaders(candHeaders) {
				htmlSim := compareHTML(originalHTML, fetchedHTML)

				var certMatch float64
				if isTLSPort(port) {
					certMatch = compareTLSCerts(ctx, domain, ws.IP, port)
				}

				headerMatch := compareResponseHeaders(originalHeaders, candHeaders)
				// Suppress header match for error responses — generic error pages
				// return common headers that don't indicate origin identity
				if statusCode >= 400 {
					headerMatch = 0
				}
				overallScore := calculateOverallScore(htmlSim, certMatch, headerMatch, originalStatusCode, statusCode) * 100

				if overallScore > opts.threshold {
					src := ipSources[ws.IP]
					if src == "" {
						src = "unknown"
					}
					bypassResults = append(bypassResults, BypassResult{
						IP:           ws.IP,
						Port:         port,
						Similarity:   htmlSim * 100,
						Method:       "direct",
						StatusCode:   statusCode,
						CertMatch:    certMatch * 100,
						HeaderMatch:  headerMatch * 100,
						OverallScore: overallScore,
						Source:       src,
					})
				}
			}

			// Method 2: Host header injection
			fetchedHTML2, statusCode2, candHeaders2, fetchErr2 := fetchHTMLWithHeaders(ctx, urlStr, domain)
			if fetchErr2 == nil && statusCode2 < 500 && !responseHasWAFHeaders(candHeaders2) {
				htmlSim2 := compareHTML(originalHTML, fetchedHTML2)

				var certMatch2 float64
				if isTLSPort(port) {
					certMatch2 = compareTLSCerts(ctx, domain, ws.IP, port)
				}

				headerMatch2 := compareResponseHeaders(originalHeaders, candHeaders2)
				// Suppress header match for error responses — generic error pages
				// return common headers that don't indicate origin identity
				if statusCode2 >= 400 {
					headerMatch2 = 0
				}
				overallScore2 := calculateOverallScore(htmlSim2, certMatch2, headerMatch2, originalStatusCode, statusCode2) * 100

				if overallScore2 > opts.threshold {
					src := ipSources[ws.IP]
					if src == "" {
						src = "unknown"
					}
					bypassResults = append(bypassResults, BypassResult{
						IP:           ws.IP,
						Port:         port,
						Similarity:   htmlSim2 * 100,
						Method:       "host-header",
						StatusCode:   statusCode2,
						CertMatch:    certMatch2 * 100,
						HeaderMatch:  headerMatch2 * 100,
						OverallScore: overallScore2,
						Source:       src,
					})
				}
			}
		}
		verifyBar.Increment()
	}
	verifyBar.Finish()

	// ── Neighbor Scanning ──
	if opts.scanNeighbors && len(bypassResults) > 0 {
		sectionHeader("Neighbor Scanning (/24)")
		confirmedIPs := make([]string, 0)
		seen := make(map[string]bool)
		for _, r := range bypassResults {
			if !seen[r.IP] {
				confirmedIPs = append(confirmedIPs, r.IP)
				seen[r.IP] = true
			}
		}

		neighborIPs := expandToNeighborhood(confirmedIPs)
		logInfo("Scanning %d neighbor IPs from /24 subnets...", len(neighborIPs))

		if len(neighborIPs) > 0 {
			var neighborWebServers []webServerResult
			var nmu sync.Mutex
			var nwg sync.WaitGroup
			nsem := make(chan struct{}, opts.workers)

			nbar := newProgressBar(len(neighborIPs), "Neighbor scan")

			for _, ip := range neighborIPs {
				if ctx.Err() != nil {
					break
				}
				nwg.Add(1)
				go func(ip string) {
					nsem <- struct{}{}
					defer func() { <-nsem }()
					checkWebServer(ctx, ip, opts.portTimeout, &nwg, &nmu, &neighborWebServers, nbar, len(neighborIPs))
				}(ip)
			}
			nwg.Wait()
			nbar.Finish()

			logInfo("Found %d web servers in neighbor IPs.", len(neighborWebServers))

			for _, ws := range neighborWebServers {
				if ctx.Err() != nil {
					break
				}
				for _, port := range ws.Ports {
					var scheme string
					if isTLSPort(port) {
						scheme = "https"
					} else {
						scheme = "http"
					}
					urlStr := fmt.Sprintf("%s://%s:%d", scheme, ws.IP, port)

					fetchedHTML, statusCode, candHeaders, fetchErr := fetchHTMLWithHeaders(ctx, urlStr, domain)
					if fetchErr == nil && statusCode < 500 && !responseHasWAFHeaders(candHeaders) {
						htmlSim := compareHTML(originalHTML, fetchedHTML)

						var certMatch float64
						if isTLSPort(port) {
							certMatch = compareTLSCerts(ctx, domain, ws.IP, port)
						}

						headerMatch := compareResponseHeaders(originalHeaders, candHeaders)
						if statusCode >= 400 {
							headerMatch = 0
						}
						overallScore := calculateOverallScore(htmlSim, certMatch, headerMatch, originalStatusCode, statusCode) * 100

						if overallScore > opts.threshold {
							bypassResults = append(bypassResults, BypassResult{
								IP:           ws.IP,
								Port:         port,
								Similarity:   htmlSim * 100,
								Method:       "host-header (neighbor)",
								StatusCode:   statusCode,
								CertMatch:    certMatch * 100,
								HeaderMatch:  headerMatch * 100,
								OverallScore: overallScore,
								Source:       "Neighbor /24",
							})
						}
					}
				}
			}
		}
	}

	// ── Results ──
	sectionHeader("Results")

	if len(bypassResults) > 0 {
		// Sort by OverallScore descending
		sort.Slice(bypassResults, func(i, j int) bool {
			return bypassResults[i].OverallScore > bypassResults[j].OverallScore
		})

		// Deduplicate by IP+Port, keeping highest score
		seen := make(map[string]bool)
		var dedupResults []BypassResult
		for _, r := range bypassResults {
			key := fmt.Sprintf("%s:%d", r.IP, r.Port)
			if !seen[key] {
				seen[key] = true
				dedupResults = append(dedupResults, r)
			}
		}

		// ASN lookup for final results
		if len(dedupResults) > 0 {
			lookupASNBatch(ctx, dedupResults, appHTTPClient)
		}

		jsonOut.Bypasses = dedupResults

		if !opts.jsonMode {
			if silent {
				// Silent mode: one IP per line
				printedIPs := make(map[string]bool)
				for _, r := range dedupResults {
					if !printedIPs[r.IP] {
						fmt.Println(r.IP)
						printedIPs[r.IP] = true
					}
				}
			} else {
				for _, r := range dedupResults {
					var scheme string
					if isTLSPort(r.Port) {
						scheme = "https"
					} else {
						scheme = "http"
					}

					fmt.Println()
					boldGreen.Printf("  ✓ POSSIBLE WAF BYPASS FOUND\n")
					logInfo("IP:           %s", r.IP)
					logInfo("Port:         %d", r.Port)
					logInfo("Method:       %s", r.Method)
					logInfo("Overall:      %.1f%%", r.OverallScore)
					logInfo("  HTML sim:   %.1f%%", r.Similarity)
					logInfo("  Cert match: %.1f%%", r.CertMatch)
					logInfo("  Header:     %.1f%%", r.HeaderMatch)
					logInfo("Status:       %d", r.StatusCode)
					logInfo("Source:       %s", r.Source)
					if r.ASN != "" {
						logInfo("ASN:          %s %s", r.ASN, r.ASNOrg)
					}
					logInfo("Verify:       curl -sk -H \"Host: %s\" %s://%s:%d/", domain, scheme, r.IP, r.Port)
				}
			}
		}
	} else {
		jsonOut.Bypasses = []BypassResult{}
		if !opts.jsonMode && !silent {
			boldRed.Println("  ✗ WAF bypass not found with passive techniques.")
			fmt.Println()
			logInfo("Suggestions:")
			logInfo("  • Try lowering the threshold with -t 40")
			logInfo("  • Provide the HTML manually with -s if the WAF blocks fetching")
			logInfo("  • Add API keys for ViewDNS, SecurityTrails, Censys, Shodan, DNSDB")
			logInfo("  • Search Shodan manually with the favicon hashes above")
			logInfo("  • Try --scan-neighbors to scan /24 neighborhoods")
			logInfo("  • Look for SSRF vulnerabilities to induce outbound connections")
		}
	}
	if !silent {
		fmt.Println()
	}

	return jsonOut
}
