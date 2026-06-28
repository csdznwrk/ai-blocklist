#!/usr/bin/env python3
"""
sync_nextdns_local.py — run on your Mac to sync the blocklist to NextDNS denylist.
Scheduled via launchd. Requires NEXTDNS_API_KEY in environment (~/.zshenv).
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

PROFILE_ID  = "2a7d5a"
DOMAINS_URL = "https://csdznwrk.github.io/ai-blocklist/domains.txt"
BASE_URL    = f"https://api.nextdns.io/profiles/{PROFILE_ID}/denylist"

API_KEY = os.environ.get("NEXTDNS_API_KEY", "")
if not API_KEY:
    print("Error: NEXTDNS_API_KEY not set. Add it to ~/.zshenv", file=sys.stderr)
    sys.exit(1)

HEADERS = {"X-Api-Key": API_KEY, "Content-Type": "application/json"}


def fetch_domains():
    req = urllib.request.Request(DOMAINS_URL, headers={"User-Agent": "anti-ai-blocklist/1.0"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return [
            d.strip()
            for d in r.read().decode().splitlines()
            if d.strip() and not d.startswith("#")
        ]


def fetch_existing():
    req = urllib.request.Request(BASE_URL, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=15) as r:
        return {item["id"] for item in json.loads(r.read()).get("data", [])}


def add_domain(domain):
    payload = json.dumps({"id": domain, "active": True}).encode()
    req = urllib.request.Request(BASE_URL, data=payload, headers=HEADERS, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10):
            return "added"
    except urllib.error.HTTPError as e:
        if e.code == 409:
            return "skip"   # already exists
        return f"error:{e.code}"


def main():
    print("Fetching latest domain list...")
    domains = fetch_domains()
    print(f"  {len(domains)} domains in list")

    print("Fetching existing NextDNS denylist...")
    existing = fetch_existing()
    print(f"  {len(existing)} already in NextDNS denylist")

    new_domains = [d for d in domains if d not in existing]
    print(f"  Adding {len(new_domains)} new domains...")

    added = errors = 0
    for domain in new_domains:
        result = add_domain(domain)
        if result == "added":
            added += 1
        elif result.startswith("error"):
            errors += 1
            print(f"  ! {domain} → {result}")
        time.sleep(0.05)   # ~20 req/s — well within NextDNS rate limits

    print(f"\nDone: {added} added, {errors} errors")


if __name__ == "__main__":
    main()
