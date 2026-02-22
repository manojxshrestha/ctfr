#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
------------------------------------------------------------------------------
    CTFR v2.0 - Enhanced Certificate Transparency Recon Tool
    Original by Sheila A. Berta (UnaPibaGeek)
    Enhanced with IP resolution, cert details, threading, proxy support
------------------------------------------------------------------------------
"""

import re
import sys
import json
import socket
import requests
import threading
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

version = "2.0"


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RESET = "\033[0m"


def parse_args():
    import argparse

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="CTFR v2.0 - Certificate Transparency Recon Tool",
    )
    parser.add_argument("-d", "--domain", type=str, help="Target domain")
    parser.add_argument(
        "-dL", "--domain-list", type=str, help="File containing domains (one per line)"
    )
    parser.add_argument(
        "-o", "--output", type=str, help="Output file (auto-resolves IPs)"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Quiet mode (suppress banner)"
    )
    parser.add_argument(
        "-s", "--silent", action="store_true", help="Silent mode (stats only)"
    )
    parser.add_argument(
        "-a",
        "--alive",
        action="store_true",
        help="Filter only valid (non-expired) certificates",
    )
    parser.add_argument(
        "-i",
        "--resolve-ip",
        action="store_true",
        default=False,
        help="Resolve subdomains to IP addresses (auto-enabled with -o)",
    )
    parser.add_argument(
        "-c",
        "--cert-details",
        action="store_true",
        default=False,
        help="Show certificate details",
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=5, help="Number of threads (default: 5)"
    )
    parser.add_argument("--proxy", type=str, help="Proxy URL (http/https/socks5)")
    parser.add_argument(
        "--sources",
        type=str,
        default="crtsh",
        help="CT sources (comma-separated: crtsh,google,digicert)",
    )
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument(
        "--user-agent",
        type=str,
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        help="Custom User-Agent",
    )
    return parser.parse_args()


def banner():
    b = r"""
          ____ _____ _____ ____  
         / ___|_   _|  ___|  _ \ 
        | |     | | | |_  | |_) |
        | |___  | | |  _| |  _ < 
         \____| |_| |_|   |_| \_\

     v2.0 - Certificate Transparency Recon
    by ~/. (UnaPibaGeek) X (manojxshrestha)
    """.format(v=version)
    print(b)


def clear_url(target):
    return re.sub(r".*www\.", "", target, count=1).split("/")[0].strip()


def save_output(line, output_file):
    with open(output_file, "a") as f:
        f.write(line + "\n")


def is_certificate_valid(not_before, not_after):
    try:
        not_before_date = datetime.strptime(not_before.split("T")[0], "%Y-%m-%d")
        not_after_date = datetime.strptime(not_after.split("T")[0], "%Y-%m-%d")
        now = datetime.now()
        return not_before_date <= now <= not_after_date
    except:
        return True


def get_proxies(proxy_url):
    if not proxy_url:
        return None
    return {"http": proxy_url, "https": proxy_url}


def clean_subdomains(subdomains, target):
    """Clean and deduplicate subdomains."""
    cleaned = []
    seen = set()

    for sub in subdomains:
        # Skip entries with weird patterns (like ----)
        if "----" in sub or "--" in sub:
            continue

        # Skip if contains multiple domains (not ending with target)
        if not sub.endswith(target):
            continue

        # Skip wildcards for now (can add back if needed)
        # if sub.startswith('*.'):
        #     sub = sub[2:]

        # Clean the subdomain
        sub = sub.strip()

        # Skip duplicates
        if sub and sub not in seen:
            seen.add(sub)
            cleaned.append(sub)

    return sorted(cleaned)


def get_ct_data(target, source, proxy, user_agent, filter_alive):
    subdomains = []
    cert_details = []

    headers = {"User-Agent": user_agent}

    sources_map = {
        "crtsh": f"https://crt.sh/?q=%.{target}&output=json",
        "google": f"https://transparencyreport.google.com/transparencyreport/api/v3/cert/report?domain={target}",
        "digicert": f"https://www.digicert.com/services/v2/enrollment/forgot-password/certsearch?search={target}",
    }

    url = sources_map.get(source.lower(), sources_map["crtsh"])

    try:
        req = requests.get(url, headers=headers, proxies=get_proxies(proxy), timeout=30)

        if req.status_code == 200 and req.text.strip():
            if source.lower() == "crtsh":
                data = req.json()
                if data:
                    for entry in data:
                        if filter_alive:
                            if "not_before" in entry and "not_after" in entry:
                                if not is_certificate_valid(
                                    entry["not_before"], entry["not_after"]
                                ):
                                    continue

                        name = entry.get("name_value") or entry.get("common_name")
                        if name:
                            subdomains.append(name)

                            if args.cert_details:
                                cert_info = {
                                    "subdomain": name,
                                    "issuer": entry.get("issuer_name", "N/A"),
                                    "not_before": entry.get("not_before", "N/A"),
                                    "not_after": entry.get("not_after", "N/A"),
                                    "serial": entry.get("serial_number", "N/A"),
                                    "fingerprint": entry.get("fingerprint", "N/A"),
                                }
                                cert_details.append(cert_info)
            else:
                pass

    except Exception as e:
        if not args.silent:
            print(f"[!] Error fetching {source}: {e}")

    return subdomains, cert_details


def resolve_ip(subdomain):
    try:
        ip = socket.gethostbyname(subdomain)
        return ip
    except:
        return None


def resolve_ips_batch(subdomains):
    ips = {}
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_sub = {executor.submit(resolve_ip, sub): sub for sub in subdomains}
        for future in as_completed(future_to_sub):
            sub = future_to_sub[future]
            try:
                ip = future.result()
                if ip:
                    if sub not in ips:
                        ips[sub] = []
                    ips[sub].append(ip)
            except:
                pass
    return ips


def process_domain(target, sources, output):
    all_subdomains = []
    all_cert_details = []

    for source in sources:
        subs, certs = get_ct_data(
            target, source, args.proxy, args.user_agent, args.alive
        )
        all_subdomains.extend(subs)
        all_cert_details.extend(certs)

    # Clean and deduplicate subdomains
    all_subdomains = clean_subdomains(all_subdomains, target)

    results = []

    if args.resolve_ip:
        if not args.silent:
            print(f"[*] Resolving {len(all_subdomains)} subdomains to IPs...")
        ip_map = resolve_ips_batch(all_subdomains)

        for sub in all_subdomains:
            if sub in ip_map:
                results.append(f"{sub} -> {', '.join(ip_map[sub])}")
            else:
                results.append(sub)
    else:
        results = all_subdomains

    for line in results:
        print(line)
        if output:
            save_output(line, output)

    if args.cert_details and all_cert_details:
        # Clean certs list too
        clean_certs = [
            c
            for c in all_cert_details
            if c["subdomain"].endswith(target) and "----" not in c["subdomain"]
        ]
        if not args.silent:
            print("\n" + "=" * 60)
            print("CERTIFICATE DETAILS")
            print("=" * 60)
            for cert in clean_certs[:20]:
                print(f"\nSubdomain: {cert['subdomain']}")
                print(f"  Issuer: {cert['issuer']}")
                print(f"  Valid: {cert['not_before']} to {cert['not_after']}")
                print(f"  Serial: {cert['serial']}")
                if output:
                    save_output(
                        f"[CERT] {cert['subdomain']} | {cert['issuer']} | {cert['not_before']} to {cert['not_after']}",
                        output,
                    )

    return len(all_subdomains)


def main():
    global args
    args = parse_args()

    # Auto-enable IP resolution when output file is provided
    if args.output and not args.resolve_ip:
        args.resolve_ip = True

    if not args.quiet and not args.silent:
        banner()

    domains = []

    if not sys.stdin.isatty():
        domains = [line.strip() for line in sys.stdin if line.strip()]

    if not args.domain and not args.domain_list and not domains:
        print("""
Examples:
  python3 ctfr.py -d target.com                 # Basic enumeration
  python3 ctfr.py -d target.com -o subs.txt   # Save to file (auto-resolve IP)
  python3 ctfr.py -d target.com -q             # Quiet mode
  python3 ctfr.py -dL domains.txt -o out.txt  # Multiple domains
  python3 ctfr.py -d target.com --alive        # Filter valid certs only
  python3 ctfr.py -d target.com --proxy http://localhost:8080
  python3 ctfr.py -d target.com -t 10          # Custom threads
""")
        exit(1)

    if args.domain:
        domains.append(args.domain)

    if args.domain_list:
        try:
            with open(args.domain_list, "r") as f:
                domains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[X] File not found: {args.domain_list}")
            exit(1)

    sources = [s.strip() for s in args.sources.split(",")]

    total_found = 0
    for target in domains:
        target = clear_url(target)
        if not args.silent:
            print(f"\n{'=' * 60}")
            print(f"TARGET: {target}")
            print(f"{'=' * 60}")

        count = process_domain(target, sources, args.output)
        total_found += count

        if not args.silent:
            print(f"\n[!] Found {count} subdomains for {target}")

    if not args.silent:
        print(f"\n[!] Total: {total_found} subdomains from {len(domains)} domain(s)")
        print("[!] Done. Have a nice day! ;).")


if __name__ == "__main__":
    main()
