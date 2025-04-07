DNS Vulnerability Scanner
A simple Bash script to scan domains for common DNS misconfigurations and vulnerabilities, such as:

🛑 Open Zone Transfers (AXFR)

🧠 DNS Cache Snooping

🎯 Wildcard DNS / Rebinding

⚠️ Potential Subdomain Takeovers

✉️ SPF / DKIM / DMARC Record Checks

🔐 DNSSEC Validation

🚀 Features
Scan a single domain or a list of domains from a file

🔍 Highlights only vulnerable findings

💾 Saves full scan results to dns_scan_results.txt

🎨 Color-coded terminal output for readability

# Scan a single domain
./dns_vuln_scan.sh example.com

# Scan a list of domains
./dns_vuln_scan.sh domains.txt
