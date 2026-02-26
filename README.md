<h1 align="center">CTFR - Certificate Transparency Recon</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.1-blue" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.x-green" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-orange" alt="License">
</p>

CTFR is a powerful subdomain enumeration tool that abuses Certificate Transparency (CT) logs to discover subdomains for any HTTPS website in seconds.

Unlike traditional methods, CTFR does not use dictionary attacks or brute-force techniques. Instead, it queries public Certificate Transparency logs to harvest subdomains from SSL/TLS certificates.

For more information about Certificate Transparency, visit [certificate-transparency.org](https://www.certificate-transparency.org) or check [crt.sh](https://crt.sh/).

## How It Works

1. **Queries CT Log Servers** - Connects to public Certificate Transparency logs (crt.sh, Google, DigiCert, etc.)
2. **Extracts Certificates** - Retrieves all SSL/TLS certificates issued for the target domain
3. **Parses SANs** - Extracts Subject Alternative Names from certificates to find subdomains
4. **Resolves IPs** - Optionally resolves each subdomain to its IP address
5. **Filters Valid Certs** - Can filter to show only currently valid (non-expired) certificates

**Why It Works**
- Every SSL/TLS certificate is publicly logged in CT databases
- Even expired certificates reveal subdomains that once existed
- No brute-forcing or dictionary attacks - just querying public data

## Features

- Subdomain enumeration via Certificate Transparency logs
- IP resolution for subdomains
- Certificate details extraction (issuer, validity, serial)
- Filter valid (non-expired) certificates
- Multiple domain support (file or stdin)
- Proxy support (HTTP/HTTPS/SOCKS5)
- Multi-threaded resolution
- Multiple CT log sources support
- JSON output support
- Custom User-Agent

## Installation

```bash
git clone https://github.com/manojxshrestha/ctfr.git
cd ctfr
pip3 install -r requirements.txt
```

## Usage

```bash
# Basic enumeration
python3 ctfr.py -d target.com

# Save to file (auto-resolves IPs)
python3 ctfr.py -d target.com -o subs.txt

# Quiet mode
python3 ctfr.py -d target.com -q

# Multiple domains from file
python3 ctfr.py -dL domains.txt -o output.txt

# Filter valid certificates only
python3 ctfr.py -d target.com --alive

# With proxy
python3 ctfr.py -d target.com --proxy http://127.0.0.1:8080

# Custom threads
python3 ctfr.py -d target.com -t 10

# Show certificate details
python3 ctfr.py -d target.com -c

# JSON output
python3 ctfr.py -d target.com --json

# Custom CT sources
python3 ctfr.py -d target.com --sources crtsh,google,digicert
```

## Options

| Flag | Description |
|------|-------------|
| `-d, --domain` | Target domain |
| `-dL, --domain-list` | File containing domains (one per line) |
| `-o, --output` | Output file (auto-resolves IPs) |
| `-q, --quiet` | Quiet mode (suppress banner) |
| `-s, --silent` | Silent mode (stats only) |
| `-a, --alive` | Filter only valid (non-expired) certificates |
| `-i, --resolve-ip` | Resolve subdomains to IP addresses |
| `-c, --cert-details` | Show certificate details |
| `-t, --threads` | Number of threads (default: 10) |
| `--proxy` | Proxy URL (http/https/socks5) |
| `--sources` | CT sources (comma-separated: crtsh,google,digicert) |
| `--json` | JSON output |
| `--user-agent` | Custom User-Agent |
| `--timeout` | Request timeout in seconds (default: 180) |
| `--retries` | Number of retries on failure (default: 3) |

## Examples

### Basic Enumeration
```bash
python3 ctfr.py -d target.com
```

### Save Results with IP Resolution
```bash
python3 ctfr.py -d target.com -o subs.txt
```

### Multiple Domains
```bash
python3 ctfr.py -dL domains.txt -o output.txt
```

### Filter Valid Certificates
```bash
python3 ctfr.py -d target.com --alive
```

### With Proxy
```bash
python3 ctfr.py -d target.com --proxy http://localhost:8080
```

### Show Certificate Details
```bash
python3 ctfr.py -d target.com -c
```

### JSON Output
```bash
python3 ctfr.py -d target.com --json
```

## License

MIT License

## Author

- Original by Sheila A. Berta ([UnaPibaGeek](https://github.com/UnaPibaGeek))
- Updated by [manojxshrestha](https://github.com/manojxshrestha)
