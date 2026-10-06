#!/usr/bin/env python3
"""
Automated DNS Blocklist Aggregator (oktamagenerator)
Features:
- Cumulative retention: preserves previously blocked domains so no entries are lost
- Multi-source parallel scraping with custom User-Agent to bypass bot/scraper blocking
- Robust parsing for domains, hosts format, adblock rules, and comments
- Automatic deduplication and alphabetical sorting
- Aggregates category lists (ads, adult, gambling, malware, phishing, scam, drugs, violence)
  and produces a consolidated master-blocklist.txt (> 1.5 million domains)
"""

import os
import re
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

# Ensure UTF-8 output on Windows consoles
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
DOMAIN_REGEX = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-_]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]$')

# High-yield, verified, enterprise-grade sources
SOURCES = {
    "ads.txt": [
        # HaGeZi Multi PRO+ (Active & updated daily)
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.plus-onlydomains.txt",
        # OISD Big
        "https://big.oisd.nl/",
        # StevenBlack Unified hosts
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        # Firebog Lists
        "https://v.firebog.net/hosts/AdguardDNS.txt",
        "https://v.firebog.net/hosts/Easylist.txt",
        "https://v.firebog.net/hosts/Admiral.txt",
        # Peter Lowe
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
        # Anudeep Adservers
        "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
        # AdGuard DNS Filter
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    ],
    "adult.txt": [
        # StevenBlack Adult / Porn
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
    ],
    "gambling.txt": [
        # StevenBlack Gambling
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts",
        # BlocklistProject Gambling
        "https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt",
    ],
    "malware.txt": [
        # HaGeZi Threat Intelligence Feeds Medium (~694,000 domains)
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt",
        # URLhaus
        "https://urlhaus.abuse.ch/downloads/hostfile/",
        # ThreatFox
        "https://threatfox.abuse.ch/downloads/hostfile/",
    ],
    "phishing.txt": [
        # Phishing Army
        "https://phishing.army/download/phishing_army_blocklist.txt",
        # OpenPhish
        "https://openphish.com/feed.txt",
    ],
    "scam.txt": [
        # DurableNapkin Scam Blocklist
        "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt",
        # BlocklistProject Scam
        "https://raw.githubusercontent.com/blocklistproject/Lists/master/scam.txt",
    ],
    "drugs.txt": [
        # BlocklistProject Drugs
        "https://raw.githubusercontent.com/blocklistproject/Lists/master/drugs.txt",
    ],
    "violence.txt": [
        # StevenBlack Fakenews
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts",
    ],
}


def clean_domain(line: str) -> str | None:
    """Parse and clean a line into a valid, lowercased domain name."""
    line = re.sub(r'[#!;].*$', '', line).strip()
    if not line:
        return None

    if line.startswith('||'):
        line = line[2:]
    if '^' in line:
        line = line.split('^')[0]

    parts = line.split()
    if not parts:
        return None

    candidate = None
    if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1', '::1', '::'):
        candidate = parts[1]
    elif len(parts) == 1:
        candidate = parts[0]
    else:
        for p in parts:
            if p not in ('0.0.0.0', '127.0.0.1', '::1', '::', 'localhost', 'broadcasthost'):
                candidate = p
                break

    if not candidate:
        return None

    candidate = candidate.lower().rstrip('.')
    if candidate.startswith(('http://', 'https://')):
        candidate = candidate.split('://', 1)[1].split('/')[0]
    candidate = candidate.split(':')[0]

    if candidate in ('localhost', 'localhost.localdomain', 'local', 'broadcasthost', '0.0.0.0', '127.0.0.1'):
        return None

    if DOMAIN_REGEX.match(candidate):
        return candidate
    return None


def fetch_url(url: str, timeout: int = 40, retries: int = 3) -> set[str]:
    """Fetch URL with custom User-Agent and retries, extracting unique domains."""
    domains = set()
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/plain, text/html, */*",
        "Accept-Encoding": "identity",
    }

    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status != 200:
                    print(f"  ⚠️  HTTP {response.status} for {url}", flush=True)
                    return domains

                for line in response:
                    try:
                        text = line.decode('utf-8', errors='ignore')
                        dom = clean_domain(text)
                        if dom:
                            domains.add(dom)
                    except Exception:
                        continue
            return domains
        except urllib.error.HTTPError as e:
            print(f"  ❌ HTTP {e.code} ({e.reason}) on {url} (Attempt {attempt}/{retries})", flush=True)
            if e.code in (404, 410):
                break
            time.sleep(2)
        except Exception as e:
            print(f"  ⚠️  Error fetching {url}: {e} (Attempt {attempt}/{retries})", flush=True)
            time.sleep(2)

    return domains


def load_existing_domains(filepath: str) -> set[str]:
    """Load existing domains from a file so they are never lost (RETENTION)."""
    domains = set()
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    dom = clean_domain(line)
                    if dom:
                        domains.add(dom)
        except Exception as e:
            print(f"  ⚠️  Error reading existing file {filepath}: {e}", flush=True)
    return domains


def save_domains(filepath: str, domains: set[str]):
    """Save domains sorted alphabetically."""
    sorted_domains = sorted(domains)
    with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
        for dom in sorted_domains:
            f.write(dom + '\n')


def main():
    start_time = time.time()
    print("=" * 60, flush=True)
    print("🛡️  Starting DNS Blocklist Aggregator (Incremental / Cumulative)", flush=True)
    print("=" * 60, flush=True)

    category_results = {}

    for target_file, urls in SOURCES.items():
        print(f"\n📂 Processing category: {target_file}", flush=True)
        
        # 1. Load previously saved domains (RETENTION)
        prev_domains = load_existing_domains(target_file)
        print(f"  📌 Existing domains loaded: {len(prev_domains):,}", flush=True)

        combined_domains = set(prev_domains)

        # 2. Fetch new domains from all category sources in parallel
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_url = {executor.submit(fetch_url, url): url for url in urls}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    fetched = future.result()
                    new_count = len(fetched - combined_domains)
                    print(f"  ✅ {url} -> {len(fetched):,} domains (+{new_count:,} new)", flush=True)
                    combined_domains.update(fetched)
                except Exception as e:
                    print(f"  ❌ Failed to process {url}: {e}", flush=True)

        # 3. Save accumulated domains
        save_domains(target_file, combined_domains)
        added_count = len(combined_domains) - len(prev_domains)
        category_results[target_file] = combined_domains
        print(f"  💾 Saved {target_file}: {len(combined_domains):,} total domains (+{added_count:,} added)", flush=True)

    # 4. Generate / Update MASTER BLOCKLIST (master-blocklist.txt)
    print("\n" + "=" * 60, flush=True)
    print("👑 Generating / Updating master-blocklist.txt ...", flush=True)
    master_file = "master-blocklist.txt"
    prev_master = load_existing_domains(master_file)
    print(f"  📌 Existing master-blocklist domains: {len(prev_master):,}", flush=True)

    master_domains = set(prev_master)
    # Combine with core protection categories
    core_categories = ["ads.txt", "malware.txt", "phishing.txt", "scam.txt", "drugs.txt", "violence.txt"]
    for cat in core_categories:
        if cat in category_results:
            master_domains.update(category_results[cat])

    save_domains(master_file, master_domains)
    master_added = len(master_domains) - len(prev_master)
    print(f"  💾 Saved master-blocklist.txt: {len(master_domains):,} total domains (+{master_added:,} added)", flush=True)

    elapsed = time.time() - start_time
    print("\n" + "=" * 60, flush=True)
    print(f"🎉 All blocklists successfully updated in {elapsed:.1f}s!", flush=True)
    print(f"📊 Summary:", flush=True)
    for fn in list(SOURCES.keys()) + [master_file]:
        cnt = len(category_results.get(fn, master_domains if fn == master_file else set()))
        size_mb = os.path.getsize(fn) / (1024 * 1024) if os.path.exists(fn) else 0
        print(f"  - {fn:20s}: {cnt:>10,} domains ({size_mb:>6.2f} MB)", flush=True)
    print("=" * 60, flush=True)


if __name__ == "__main__":
    main()
