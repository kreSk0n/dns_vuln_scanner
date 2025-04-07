#!/bin/bash

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No color

output="dns_scan_results.txt"
> "$output"

vuln_found=0

print_usage() {
    echo -e "${YELLOW}Usage:${NC} $0 <domain>            # Scan single domain"
    echo -e "       $0 <domains.txt>      # Scan list of domains"
    exit 1
}

# Check arguments
if [ -z "$1" ]; then
    print_usage
fi

# Determine if input is a domain or a file
if [[ -f "$1" ]]; then
    domains=$(cat "$1")
else
    domains="$1"
fi

echo -e "${CYAN}[*] Starting DNS vulnerability scan...${NC}"

for domain in $domains; do
    echo -e "\n${YELLOW}===== Scanning: $domain =====${NC}" | tee -a "$output"

    echo -e "${CYAN}[1] Checking AXFR (Zone Transfer)...${NC}" | tee -a "$output"
    dnsrecon -d "$domain" -t axfr 2>/dev/null | tee -a "$output" | grep -q "AXFR Successful" && {
        echo -e "${RED}[!!] AXFR is OPEN on $domain!${NC}" | tee -a "$output"
        vuln_found=1
    }

    echo -e "${CYAN}[2] Checking DNS Cache Snooping...${NC}" | tee -a "$output"
    for ns in $(dig NS "$domain" +short); do
        if dig +nocmd google.com @"$ns" +noquestion +nocomments +noauthority +noadditional | grep -q "NOERROR"; then
            echo -e "${RED}[!!] Cache snooping possible on NS: $ns${NC}" | tee -a "$output"
            vuln_found=1
        fi
    done

    echo -e "${CYAN}[3] Checking Wildcard / DNS Rebinding...${NC}" | tee -a "$output"
    wildcard=$(dig asdfasdf12345."$domain" +short)
    [ ! -z "$wildcard" ] && {
        echo -e "${RED}[!!] Possible wildcard DNS enabled: $wildcard${NC}" | tee -a "$output"
        vuln_found=1
    }

    echo -e "${CYAN}[4] Subdomain Takeover (Basic CNAME check)...${NC}" | tee -a "$output"
    cname=$(dig CNAME www."$domain" +short)
    if [[ "$cname" == *"github.io."* || "$cname" == *"herokudns.com."* || "$cname" == *"amazonaws.com."* ]]; then
        echo -e "${RED}[!!] www.$domain points to external service: $cname — possible takeover${NC}" | tee -a "$output"
        vuln_found=1
    fi

    echo -e "${CYAN}[5] SPF / DMARC / DKIM Records...${NC}" | tee -a "$output"
    echo -e "- SPF: $(dig TXT "$domain" +short | grep "v=spf1")" | tee -a "$output"
    echo -e "- DMARC: $(dig TXT _dmarc."$domain" +short)" | tee -a "$output"
    echo -e "- DKIM (default selector): $(dig TXT default._domainkey."$domain" +short)" | tee -a "$output"

    echo -e "${CYAN}[6] DNSSEC status...${NC}" | tee -a "$output"
    dnssec=$(dig +dnssec "$domain" | grep RRSIG)
    [ ! -z "$dnssec" ] && \
        echo -e "${GREEN}[i] DNSSEC is ENABLED${NC}" | tee -a "$output" || {
        echo -e "${RED}[!!] DNSSEC is NOT configured${NC}" | tee -a "$output"
        vuln_found=1
    }

done

# Final summary
if [[ "$vuln_found" == 1 ]]; then
    echo -e "\n${RED}[!] One or more vulnerabilities were found.${NC}"
fi

echo -e "${GREEN}[✓] Scan completed. Results saved in $output${NC}"
