package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
	"github.com/sergi/go-diff/diffmatchpatch"
)

const logo = `
░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓████████▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░   
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█████████████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
                                                                     `

const usage = `
Author:
  Name:               Martín Martín
  LinkedIn:           https://www.linkedin.com/in/martinmarting/
  Twitter/X:          https://x.com/mmrecon
  GitHub:             https://github.com/mmarting/unwaf

Usage:
  -d, --domain        The domain to check (required)
  -s, --source        The source HTML file to compare (optional)
  -c, --config        The config file path (optional, default: $HOME/.unwaf.conf)
  -h, --help          Display help information

Examples:
  1. Check a domain:
     unwaf -d example.com

  2. Check a domain with a manually provided HTML file:
     unwaf -d example.com -s original.html

  3. Check a domain with a custom location for the config file:
     unwaf -d example.com -c /path/to/config

Note:
  Unwaf requires API keys for viewdns & securitytrails in order to be able to check DNS history records. Add them to the config file: $HOME/.unwaf.conf 
`

type Config struct {
	ViewDNS        string `json:"viewdns"`
	SecurityTrails string `json:"securitytrails"`
}

var apiKeyRegex = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

func showUsage() {
	fmt.Println(logo)
	fmt.Println(usage)
}

func createDefaultConfig(configPath string) error {
	defaultConfig := `#Unwaf will try to find this config file in $HOME/.unwaf.conf
viewdns=""
securitytrails=""
`
	return os.WriteFile(configPath, []byte(defaultConfig), 0644)
}

func loadConfig(configPath string) (*Config, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := createDefaultConfig(configPath); err != nil {
			return nil, err
		}
	}

	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &Config{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "=")
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], strings.Trim(parts[1], `"`)
		if !apiKeyRegex.MatchString(value) {
			continue
		}
		switch key {
		case "viewdns":
			config.ViewDNS = value
		case "securitytrails":
			config.SecurityTrails = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return config, nil
}

func extractMainDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}

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
							return nil, err
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

func expandIPRange(cidr string) ([]string, error) {
	var ips []string
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	if len(ips) <= 2 {
		return ips, nil
	}
	return ips[1 : len(ips)-1], nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func fetchHTML(url string) (string, int, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", 0, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 500 {
		return "", resp.StatusCode, fmt.Errorf("internal server error")
	}

	reader, err := charset.NewReader(resp.Body, resp.Header.Get("Content-Type"))
	if err != nil {
		return "", resp.StatusCode, err
	}
	z := html.NewTokenizer(reader)
	var b strings.Builder
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		token := z.Token()
		if token.Type == html.TextToken {
			b.WriteString(token.Data)
		}
	}
	return b.String(), resp.StatusCode, nil
}

func checkWebServer(ip string, wg *sync.WaitGroup, mu *sync.Mutex, webServerIPs *[]string, runningCounter *int, checkedCounter *int, total int) {
	defer wg.Done()
	isRunning := isPortOpen(ip, 80) || isPortOpen(ip, 443)
	mu.Lock()
	if isRunning {
		*webServerIPs = append(*webServerIPs, ip)
		(*runningCounter)++
	}
	(*checkedCounter)++
	fmt.Printf("\r  %d/%d IPs are running a web server: Completed: %.2f%%.", *runningCounter, total, float64(*checkedCounter)/float64(total)*100)
	mu.Unlock()
}

func isPortOpen(ip string, port int) bool {
	timeout := 1 * time.Second
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func compareHTML(original, fetched string) float64 {
	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(original, fetched, false)
	similarity := 0
	for _, diff := range diffs {
		if diff.Type == diffmatchpatch.DiffEqual {
			similarity += len(diff.Text)
		}
	}
	totalLength := len(original) + len(fetched)
	if totalLength == 0 {
		return 1.0
	}
	return float64(similarity*2) / float64(totalLength)
}

func fetchIPsFromViewDNS(domain, apiKey string) ([]string, error) {
	var ips []string
	url := fmt.Sprintf("https://api.viewdns.info/iphistory/?domain=%s&apikey=%s&output=json", domain, apiKey)
	resp, err := http.Get(url)
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

func fetchIPsFromSecurityTrails(domain, apiKey string) ([]string, error) {
	var ips []string
	url := fmt.Sprintf("https://api.securitytrails.com/v1/history/%s/dns/a", domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("APIKEY", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
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

func processDomain(domain, source, configPath string) {
	config, err := loadConfig(configPath)
	if err != nil {
		config = &Config{}
	}

	mainDomain := extractMainDomain(domain)

	var originalHTML string
	if source != "" {
		content, err := os.ReadFile(source)
		if err != nil {
			fmt.Println("Error reading source HTML file.")
			return
		}
		originalHTML = string(content)
	} else {
		originalHTML, _, err = fetchHTML("http://" + domain)
		if err != nil {
			fmt.Println("Error fetching original HTML. The WAF might be blocking the request. Please provide the HTML file manually using the --source or -s option.")
			return
		}
	}

	fmt.Printf("Looking for possible IPs for the web server behind %s:\n", domain)
	ips, err := extractIPsFromSPF(mainDomain)
	if err != nil {
		fmt.Println("  Error fetching SPF record.")
		return
	}
	fmt.Printf("  Found %d IPs in SPF record.\n", len(ips))

	if config.ViewDNS != "" {
		viewdnsIPs, err := fetchIPsFromViewDNS(mainDomain, config.ViewDNS)
		if err != nil {
			fmt.Println("  Error fetching IPs from ViewDNS:", err)
		} else {
			fmt.Printf("  Found %d IPs in ViewDNS history.\n", len(viewdnsIPs))
			ips = append(ips, viewdnsIPs...)
		}
	} else {
		fmt.Println("  Avoiding ViewDNS. No API key provided.")
	}

	if config.SecurityTrails != "" {
		securityTrailsIPs, err := fetchIPsFromSecurityTrails(mainDomain, config.SecurityTrails)
		if err != nil {
			fmt.Println("  Error fetching IPs from SecurityTrails:", err)
		} else {
			fmt.Printf("  Found %d IPs in SecurityTrails history.\n", len(securityTrailsIPs))
			ips = append(ips, securityTrailsIPs...)
		}
	} else {
		fmt.Println("  Avoiding SecurityTrails. No API key provided.")
	}

	uniqueIPs := unique(ips)
	fmt.Printf("  Total unique IPs found: %d.\n\n", len(uniqueIPs))

	if len(uniqueIPs) == 0 {
		fmt.Println(color.New(color.Bold, color.FgRed).Sprint("WAF bypass not found."))
		return
	}

	fmt.Println("Checking which IPs are running a web server (port 80/443):")
	var webServerIPs []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	runningCounter := 0
	checkedCounter := 0
	fmt.Printf("  0/%d IPs are running a web server: Completed: 0.00%%.", len(uniqueIPs))
	for _, ip := range uniqueIPs {
		wg.Add(1)
		go checkWebServer(ip, &wg, &mu, &webServerIPs, &runningCounter, &checkedCounter, len(uniqueIPs))
	}
	wg.Wait()
	fmt.Printf("\r  %d/%d IPs are running a web server: Completed: 100.00%%.\n", runningCounter, len(uniqueIPs))

	if runningCounter == 0 {
		fmt.Println(color.New(color.Bold, color.FgRed).Sprint("\nWAF bypass not found."))
		return
	}

	fmt.Println("\nChecking if any of the IPs is the direct web server IP:")
	bypassIPs := []string{}
	fmt.Printf("  Checking 0/%d IP/s for WAF bypass. Completed: 0.00%%.", len(webServerIPs))
	for i, ip := range webServerIPs {
		fetchedHTML, _, err := fetchHTML("http://" + ip)
		if err != nil {
			continue
		}
		similarity := compareHTML(originalHTML, fetchedHTML) * 100
		fmt.Printf("\r  Checking %d/%d IP/s for WAF bypass. Completed: %.2f%%.", i+1, len(webServerIPs), float64(i+1)/float64(len(webServerIPs))*100)
		if similarity > 60 {
			bypassIPs = append(bypassIPs, ip)
		}
	}

	if len(bypassIPs) > 0 {
		for _, ip := range bypassIPs {
			fmt.Printf("\n%s", color.New(color.Bold, color.FgGreen).Sprintf("\nPossible WAF bypass detected. Web server seems to be directly accessible using the IP: %s", ip))
		}
	} else {
		fmt.Println(color.New(color.Bold, color.FgRed).Sprint("\nWAF bypass not found."))
	}
	fmt.Println()
}

func unique(stringSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range stringSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func main() {
	domain := flag.String("domain", "", "The domain to check")
	flag.StringVar(domain, "d", "", "The domain to check (shorthand)")
	source := flag.String("source", "", "The source HTML file to compare")
	flag.StringVar(source, "s", "", "The source HTML file to compare (shorthand)")
	configPath := flag.String("config", filepath.Join(os.Getenv("HOME"), ".unwaf.conf"), "The config file path")
	flag.StringVar(configPath, "c", filepath.Join(os.Getenv("HOME"), ".unwaf.conf"), "The config file path (shorthand)")
	help := flag.Bool("help", false, "Display help information")
	flag.BoolVar(help, "h", false, "Display help information (shorthand)")

	flag.Parse()

	if *help || *domain == "" {
		showUsage()
		os.Exit(1)
	}

	processDomain(*domain, *source, *configPath)
}

