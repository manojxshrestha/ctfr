#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
------------------------------------------------------------------------------
    CTFR v2.0 - Enhanced Certificate Transparency Recon Tool
    Original by Sheila A. Berta (UnaPibaGeek)
    Features: IP resolution, cert details, threading, proxy support, retries
------------------------------------------------------------------------------
"""
import re
import sys
import json
import socket
import requests
import time
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

version = "2.1-fixed"

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RESET = "\033[0m"

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

def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="CTFR v2.1 - Certificate Transparency Subdomain Recon Tool"
    )
    parser.add_argument("-d", "--domain", type=str, help="Target domain")
    parser.add_argument("-dL", "--domain-list", type=str, help="File with domains (one per line)")
    parser.add_argument("-o", "--output", type=str, help="Output file (auto-resolves IPs)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (no banner)")
    parser.add_argument("-s", "--silent", action="store_true", help="Silent mode (stats only)")
    parser.add_argument("--alive", action="store_true", help="Filter only currently valid certificates")
    parser.add_argument("--resolve-ip", action="store_true", default=False, help="Resolve subdomains to IPs")
    parser.add_argument("--cert-details", action="store_true", default=False, help="Show certificate details")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads for IP resolution (default: 10)")
    parser.add_argument("--proxy", type=str, help="Proxy URL (http/https/socks5)")
    parser.add_argument("--timeout", type=int, default=180, help="Request timeout in seconds (default: 180)")
    parser.add_argument("--retries", type=int, default=3, help="Number of retries on failure (default: 3)")
    parser.add_argument("--user-agent", type=str,
                        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        help="Custom User-Agent")
    return parser.parse_args()

def clear_url(target):
    return re.sub(r".*www\.", "", target, count=1).split("/")[0].strip().lower()

def save_output(line, output_file):
    with open(output_file, "a", encoding="utf-8") as f:
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
    cleaned = set()
    for sub in subdomains:
        sub = sub.strip().lower()
        # Remove wildcard prefix
        if sub.startswith('*.'):
            sub = sub[2:]
        # Skip invalid / junk entries
        if not sub or "--" in sub or "----" in sub or " " in sub:
            continue
        # Must end with the target domain
        if not sub.endswith(target):
            continue
        cleaned.add(sub)
    return sorted(cleaned)

def fetch_crtsh(target, proxy, user_agent, timeout, retries, filter_alive):
    subdomains = []
    cert_details = []
    url = f"https://crt.sh/?q=%.{target}&output=json"
    headers = {"User-Agent": user_agent}
    proxies = get_proxies(proxy)

    for attempt in range(retries + 1):
        try:
            req = requests.get(url, headers=headers, proxies=proxies, timeout=timeout)
            if req.status_code == 200 and req.text.strip():
                data = req.json()
                for entry in data:
                    if filter_alive:
                        if "not_before" in entry and "not_after" in entry:
                            if not is_certificate_valid(entry["not_before"], entry["not_after"]):
                                continue

                    name_value = entry.get("name_value", "")
                    if name_value:
                        for line in name_value.splitlines():
                            sub = line.strip().lstrip("*.")
                            if sub and sub.endswith(target):
                                subdomains.append(sub)

                    if args.cert_details:
                        cert_info = {
                            "subdomain": sub,
                            "issuer": entry.get("issuer_name", "N/A"),
                            "not_before": entry.get("not_before", "N/A"),
                            "not_after": entry.get("not_after", "N/A"),
                            "serial": entry.get("serial_number", "N/A"),
                        }
                        cert_details.append(cert_info)
                break  # Success → exit retry loop
            else:
                print(f"[!] crt.sh returned {req.status_code} - retrying...")
        except Exception as e:
            if attempt < retries:
                wait = 2 ** attempt
                print(f"[!] Error on attempt {attempt+1}/{retries+1}: {e} - retrying in {wait}s...")
                time.sleep(wait)
            else:
                print(f"[!] All retries failed for crt.sh: {e}")
                return [], []

    return subdomains, cert_details

def resolve_ip(subdomain):
    try:
        return socket.gethostbyname(subdomain)
    except:
        return None

def resolve_ips_batch(subdomains, threads):
    ip_map = {}
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_sub = {executor.submit(resolve_ip, sub): sub for sub in subdomains}
        for future in as_completed(future_to_sub):
            sub = future_to_sub[future]
            try:
                ip = future.result()
                if ip:
                    ip_map[sub] = ip
            except:
                pass
    return ip_map

def process_domain(target):
    print(f"\n{'='*60}")
    print(f"TARGET: {target}")
    print(f"{'='*60}")

    subdomains, cert_details = fetch_crtsh(
        target, args.proxy, args.user_agent, args.timeout, args.retries, args.alive
    )

    if not subdomains:
        print("[!] No subdomains found.")
        return 0

    cleaned_subs = clean_subdomains(subdomains, target)
    print(f"[*] Found {len(cleaned_subs)} unique subdomains after cleaning.")

    results = []
    if args.resolve_ip or args.output:
        print(f"[*] Resolving {len(cleaned_subs)} subdomains to IPs (threads: {args.threads})...")
        ip_map = resolve_ips_batch(cleaned_subs, args.threads)
        for sub in cleaned_subs:
            ip = ip_map.get(sub, "No IP")
            line = f"{sub} → {ip}"
            results.append(line)
            print(line)
            if args.output:
                save_output(line, args.output)
    else:
        for sub in cleaned_subs:
            print(sub)
            if args.output:
                save_output(sub, args.output)

    if args.cert_details and cert_details:
        print("\n" + "="*60)
        print("CERTIFICATE DETAILS (first 15)")
        print("="*60)
        for cert in cert_details[:15]:
            print(f"Subdomain: {cert['subdomain']}")
            print(f"  Issuer:   {cert['issuer']}")
            print(f"  Valid:    {cert['not_before']} → {cert['not_after']}")
            if args.output:
                save_output(
                    f"[CERT] {cert['subdomain']} | {cert['issuer']} | {cert['not_before']} → {cert['not_after']}",
                    args.output
                )

    return len(cleaned_subs)

def main():
    global args
    args = parse_args()

    if not args.quiet and not args.silent:
        banner()

    domains = []
    if args.domain:
        domains.append(args.domain)
    if args.domain_list:
        try:
            with open(args.domain_list, encoding="utf-8") as f:
                domains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] File not found: {args.domain_list}")
            sys.exit(1)

    if not domains:
        print("[!] No domain provided. Use -d or -dL")
        sys.exit(1)

    total_found = 0
    for target in domains:
        target = clear_url(target)
        count = process_domain(target)
        total_found += count

    if not args.silent:
        print(f"\n[!] Total unique subdomains found: {total_found}")
        print("[!] Done.")

if __name__ == "__main__":
    main()
