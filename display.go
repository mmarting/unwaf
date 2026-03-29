package main

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

const logo = `
                           __
 _   _ _ ____      ____ _ / _|
| | | | '_ \ \ /\ / / _` + "`" + ` | |_
| |_| | | | \ V  V / (_| |  _|
 \__,_|_| |_|\_/\_/ \__,_|_|
`

const usageText = `
Author:
  Name:               Martín Martín
  Website:            https://mmartin.me/
  LinkedIn:           https://www.linkedin.com/in/martinmarting/
  GitHub:             https://github.com/mmarting/unwaf

Usage:
  -d, --domain        The domain to check (required)
  -s, --source        The source HTML file to compare (optional)
  -c, --config        The config file path (optional, default: $HOME/.unwaf.conf)
  -t, --threshold     Similarity threshold percentage (optional, default: 60)
  -w, --workers       Number of concurrent workers (optional, default: 50)
  -v, --verbose       Enable verbose output
  -q, --quiet         Silent mode: only output bypass IPs (for piping/automation)
  --timeout           HTTP timeout in seconds (optional, default: 10)
  --rate-limit        Max HTTP requests per second, 0=unlimited (optional, default: 0)
  --proxy             Proxy URL (http:// or socks5://) (optional)
  --scan-neighbors    Scan /24 neighbors of confirmed bypass IPs (optional)
  --json              Output results as JSON
  -l, --list          File containing domains to check, one per line
  -sb, --subdomains   File containing custom subdomains to probe
  -o, --output        Write results to file
  --version           Print version and exit
  -h, --help          Display help information

Examples:
  1. Check a domain:
     unwaf -d example.com

  2. Check a domain with a manually provided HTML file:
     unwaf -d example.com -s original.html

  3. Check a domain with a custom location for the config file:
     unwaf -d example.com -c /path/to/config

  4. Check a domain with a lower similarity threshold:
     unwaf -d example.com -t 40

  5. Check with more concurrent workers:
     unwaf -d example.com -w 100

  6. JSON output for automation:
     unwaf -d example.com --json

  7. Batch mode with domain list:
     unwaf -l domains.txt --json -o results.json

  8. Use a proxy:
     unwaf -d example.com --proxy socks5://127.0.0.1:9050

  9. Scan /24 neighbors of bypass IPs:
     unwaf -d example.com --scan-neighbors

  10. Use custom subdomains for discovery:
      unwaf -d example.com -sb custom_subs.txt

Discovery methods:
  [FREE]    SPF records (ip4/ip6 mechanisms)
  [FREE]    MX records (mail server IPs)
  [FREE]    Common mail/origin subdomains (DNS resolution)
  [FREE]    Certificate Transparency logs (crt.sh)
  [FREE]    WAF detection (fingerprinting)
  [FREE]    Favicon hash fingerprinting (MD5, SHA256, MMH3 for Shodan)
  [FREE]    AlienVault OTX passive DNS (optional key raises rate limits)
  [FREE]    RapidDNS subdomain enumeration
  [FREE]    HackerTarget host search
  [FREE]    Wayback Machine archived URLs
  [API free] Shodan host search (free API key, by SSL cert/hostname/favicon)
  [API free] SecurityTrails DNS history (free tier, 50 req/month)
  [API paid] ViewDNS IP history
  [API paid] Censys SSL certificate search (paid license required)
  [API paid] DNSDB/Farsight historical DNS

Note:
  API-based methods require keys in the config file: $HOME/.unwaf.conf.
  The tool will create an example config file after first execution.
  Censys requires a paid license with an Organization ID for API access.
`

var (
	boldGreen  = color.New(color.Bold, color.FgGreen)
	boldRed    = color.New(color.Bold, color.FgRed)
	boldYellow = color.New(color.Bold, color.FgYellow)
	boldCyan   = color.New(color.Bold, color.FgCyan)
	boldWhite  = color.New(color.Bold, color.FgWhite)
	dimWhite   = color.New(color.Faint)
)

var silent bool

func showUsage() {
	fmt.Print(logo)
	fmt.Print(usageText)
}

func sectionHeader(title string) {
	if silent {
		return
	}
	padLen := 60 - len(title)
	if padLen < 0 {
		padLen = 0
	}
	fmt.Println()
	boldCyan.Printf("── %s %s", title, strings.Repeat("─", padLen))
	fmt.Println()
}

func logInfo(format string, a ...interface{}) {
	if silent {
		return
	}
	fmt.Printf("  "+format+"\n", a...)
}

func logFound(format string, a ...interface{}) {
	if silent {
		return
	}
	boldGreen.Printf("  ✓ "+format+"\n", a...)
}

func logWarn(format string, a ...interface{}) {
	if silent {
		return
	}
	boldYellow.Printf("  ⚠ "+format+"\n", a...)
}

func logError(format string, a ...interface{}) {
	if silent {
		return
	}
	boldRed.Printf("  ✗ "+format+"\n", a...)
}

func logVerbose(verbose bool, format string, a ...interface{}) {
	if silent {
		return
	}
	if verbose {
		dimWhite.Printf("    "+format+"\n", a...)
	}
}
