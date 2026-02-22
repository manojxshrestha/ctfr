# CTFR - Certificate Transparency Recon

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.x-green" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-orange" alt="License">
</p>

Do you miss AXFR technique? CTFR allows you to get subdomains from HTTPS websites in seconds.  
How it works? CTFR does not use dictionary attack nor brute-force, it abuses Certificate Transparency logs.  
For more information about CT logs, check [www.certificate-transparency.org](https://www.certificate-transparency.org) and [crt.sh](https://crt.sh/).

## Features

- Subdomain enumeration via Certificate Transparency logs
- IP resolution for subdomains
- Certificate details extraction (issuer, validity, serial)
- Filter valid (non-expired) certificates
- Multiple domain support (file or stdin)
- Proxy support (HTTP/HTTPS/SOCKS5)
- Multi-threaded resolution
- Multiple CT log sources support

## Installation

```bash
git clone https://github.com/UnaPibaGeek/ctfr.git
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
| `-t, --threads` | Number of threads (default: 5) |
| `--proxy` | Proxy URL (http/https/socks5) |
| `--sources` | CT sources (comma-separated: crtsh,google,digicert) |
| `--json` | JSON output |
| `--user-agent` | Custom User-Agent |

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

## License

MIT License

## Author

- Original by Sheila A. Berta ([UnaPibaGeek](https://github.com/UnaPibaGeek))
- Updated by [manojxshrestha](https://github.com/manojxshrestha)
