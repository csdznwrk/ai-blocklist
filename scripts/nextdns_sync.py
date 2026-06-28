#!/usr/bin/env python3
"""
Syncs docs/domains.txt to the NextDNS denylist via API.
Requires env vars: NEXTDNS_API_KEY, NEXTDNS_PROFILE_ID
"""
import json
import os
import time
import urllib.request
import urllib.error
from pathlib import Path

API_KEY    = os.environ["NEXTDNS_API_KEY"]
PROFILE_ID = os.environ["NEXTDNS_PROFILE_ID"]
BASE_URL   = f"https://api.nextdns.io/profiles/{PROFILE_ID}/denylist"
HEADERS    = {"X-Api-Key": API_KEY, "Content-Type": "application/json"}

# Load domains
domains = [
    d.strip() for d in Path("docs/domains.txt").read_text().splitlines()
    if d.strip() and not d.startswith("#")
]
print(f"Syncing {len(domains)} domains to NextDNS denylist...")

# Fetch existing entries to avoid duplicates
req = urllib.request.Request(BASE_URL, headers=HEADERS)
try:
    with urllib.request.urlopen(req, timeout=15) as r:
        existing = {item["id"] for item in json.loads(r.read()).get("data", [])}
    print(f"  {len(existing)} already in denylist")
except Exception as e:
    print(f"  Could not fetch existing denylist: {e}")
    existing = set()

new_domains = [d for d in domains if d not in existing]
print(f"  Adding {len(new_domains)} new domains...")

added  = 0
errors = 0
for domain in new_domains:
    payload = json.dumps({"id": domain, "active": True}).encode()
    req = urllib.request.Request(BASE_URL, data=payload, headers=HEADERS, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            added += 1
    except urllib.error.HTTPError as e:
        if e.code == 409:
            pass  # already exists
        else:
            errors += 1
            print(f"  [WARN] Failed {domain}: HTTP {e.code}")
    except Exception as e:
        errors += 1
        print(f"  [WARN] Failed {domain}: {e}")
    time.sleep(0.05)  # ~20 req/sec

print(f"Done: {added} added, {errors} errors, {len(existing)} already present")
