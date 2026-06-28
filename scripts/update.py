#!/usr/bin/env python3
"""
Anti-AI + Anti-ISP-Snooping Blocklist Updater
Pulls from:
  1. Certificate Transparency logs (crt.sh) — near real-time new subdomains
  2. Community domain lists (Hagezi, v2fly, MoralCode antitelemetry)
  3. Static seed list — hand-curated baseline domains

Outputs:
  docs/domains.txt         — plain domain-per-line (Little Snitch / Pi-hole / AdGuard format)
  docs/blocklist.lsrules   — Little Snitch JSON rule group (domains + port-53 ISP block rules)
  docs/metadata.json       — last updated, domain count, source stats
"""

import json
import re
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent
SEED_FILE = REPO_ROOT / "seeds.txt"
DIST_DIR  = REPO_ROOT / "docs"

# AI company apex domains to watch on crt.sh
CRT_WATCH_DOMAINS = [
    "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
    "anthropic.com", "claude.ai", "deepseek.com", "x.ai", "mistral.ai",
    "perplexity.ai", "cohere.com", "cohere.ai", "character.ai",
    "cursor.sh", "cursor.com", "codeium.com", "windsurf.com",
    "stability.ai", "runwayml.com", "elevenlabs.io", "suno.ai",
    "udio.com", "midjourney.com", "meta.ai", "grok.com", "huggingface.co",
]

# ISP apex domains to watch on crt.sh — filtered to tracking subdomains only
CRT_WATCH_ISP_DOMAINS = [
    "comcast.net", "xfinity.com", "spectrum.net", "att.net",
    "verizon.net", "cox.net", "charter.com", "rr.com",
    "rogers.com", "talktalk.net", "bt.com", "virginmedia.com",
    "barefruit.com", "phorm.com",
]

# Subdomain keywords that indicate ISP tracking/injection (applied to crt.sh ISP results)
ISP_TRACKING_KEYWORDS = [
    "analytic", "metric", "tracking", "tracker", "telemetry", "stat",
    "usage", "collect", "collector", "searchassist", "dnserror",
    "redirect", "adinfuse", "adhelper", "beacon", "insight",
]

# Community domain lists — plain domain-per-line or hosts format
COMMUNITY_SOURCES = [
    # Hagezi — Pro tier (ads + tracking + telemetry)
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt",
    # v2fly AI-specific lists
    "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/openai",
    "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/anthropic",
    # Telemetry-focused
    "https://raw.githubusercontent.com/MoralCode/pihole-antitelemetry/main/telemetry-domains.txt",
]

# Trusted DNS resolvers — outbound port 53/853 to these is ALLOWED.
# All other port-53 outbound is blocked to prevent ISP DNS interception.
TRUSTED_DNS_RESOLVERS = [
    # Cloudflare
    "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",
    # Quad9
    "9.9.9.9", "149.112.112.112",
    # Google
    "8.8.8.8", "8.8.4.4",
    # NextDNS
    "45.90.28.0", "45.90.30.0",
]

# Domains too broad to block (would break non-AI/non-ISP services)
SAFELIST = {
    "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "microsoft.com", "azure.com", "windows.com", "office.com",
    "cloudflare.com", "cloudflare.net", "stripe.com",
    "github.com", "githubusercontent.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazonaws.com",
    "discord.com", "discordapp.com",
    "auth0.com",
    "sentry.io",
    "twitter.com", "x.com",
    "localhost", "local",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fetch(url: str, timeout: int = 15, retries: int = 2) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "anti-ai-blocklist/1.0"})
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", errors="replace")
        except Exception as e:
            if attempt < retries:
                time.sleep(2 ** attempt)  # exponential backoff
            else:
                print(f"  [WARN] Failed to fetch {url}: {e}")
    return ""


def is_valid_domain(d: str) -> bool:
    d = d.strip().lower()
    if not d or d.startswith("#") or len(d) > 253:
        return False
    if not re.match(r"^[a-z0-9*._-]+$", d):
        return False
    if "." not in d:
        return False
    return True


def strip_broad(domain: str) -> bool:
    apex = ".".join(domain.split(".")[-2:])
    return apex in SAFELIST or domain in SAFELIST


def parse_domains_from_text(text: str) -> set:
    domains = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("@"):
            continue
        if re.match(r"^(0\.0\.0\.0|127\.0\.0\.1)\s+", line):
            parts = line.split()
            if len(parts) >= 2:
                line = parts[1]
        if line.startswith("full:"):
            line = line[5:]
        if ":" in line:
            continue
        line = line.split("#")[0].strip()
        if is_valid_domain(line):
            domains.add(line.lower())
    return domains

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

def fetch_crt_subdomains(apex: str) -> set:
    url = f"https://crt.sh/?q=%.{apex}&output=json"
    text = fetch(url, timeout=20)
    if not text:
        return set()
    try:
        records = json.loads(text)
    except json.JSONDecodeError:
        return set()
    domains = set()
    for rec in records:
        for field in ("name_value", "common_name"):
            val = rec.get(field) or ""
            for line in val.splitlines():
                line = line.strip().lstrip("*.")
                if is_valid_domain(line) and line.endswith(apex):
                    domains.add(line.lower())
    print(f"  crt.sh [{apex}]: {len(domains)} domains")
    return domains


def fetch_community_sources() -> set:
    domains = set()
    ai_apexes = set(".".join(d.split(".")[-2:]) for d in CRT_WATCH_DOMAINS)
    isp_apexes = set(".".join(d.split(".")[-2:]) for d in CRT_WATCH_ISP_DOMAINS)
    all_apexes = ai_apexes | isp_apexes
    for url in COMMUNITY_SOURCES:
        print(f"  Community: {url.split('/')[-1]}")
        text = fetch(url)
        found = parse_domains_from_text(text)
        filtered = {d for d in found if ".".join(d.split(".")[-2:]) in all_apexes}
        print(f"    -> {len(filtered)} relevant domains (of {len(found)} total)")
        domains.update(filtered)
        time.sleep(0.5)
    return domains


def load_seed_domains() -> set:
    if not SEED_FILE.exists():
        return set()
    text = SEED_FILE.read_text()
    domains = parse_domains_from_text(text)
    print(f"  Seed file: {len(domains)} domains")
    return domains

# ---------------------------------------------------------------------------
# Output generators
# ---------------------------------------------------------------------------

def write_domains_txt(domains: list, path: Path):
    path.write_text("\n".join(domains) + "\n")


def write_lsrules(domains: list, path: Path):
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ISP DNS interception block rules.
    # Little Snitch evaluates rules in order — the allow rules for trusted resolvers
    # fire first; any other process trying to reach port 53/853 on an unknown host is denied.
    isp_dns_rules = [
        {
            "action": "allow",
            "process": "any",
            "remote-addresses": ", ".join(TRUSTED_DNS_RESOLVERS),
            "ports": "53, 853",
            "protocol": "udp,tcp",
            "direction": "outgoing",
            "notes": "Allow DNS/DoT to trusted resolvers only (Cloudflare, Quad9, Google, NextDNS)",
        },
        {
            "action": "deny",
            "process": "any",
            "remote": "any",
            "ports": "53, 853",
            "protocol": "udp,tcp",
            "direction": "outgoing",
            "notes": (
                "Block DNS to all other hosts — prevents ISP resolver interception, "
                "query logging, NXDOMAIN hijacking, and ad injection via DNS"
            ),
        },
    ]

    payload = {
        "name": "Anti-AI + Anti-ISP-Snooping Blocklist",
        "description": (
            f"Auto-updated every 15 min. Blocks AI platform endpoints, ISP tracking/ad-injection "
            f"domains, telemetry collectors, and training data harvesters. "
            f"Includes firewall rules that force all DNS through trusted resolvers "
            f"(Cloudflare/Quad9/Google/NextDNS), blocking ISP DNS interception, "
            f"NXDOMAIN hijacking, and query logging. "
            f"Sources: crt.sh CT logs, Hagezi Pro, v2fly, MoralCode antitelemetry, seed list. "
            f"Updated: {now_str} | Domains: {len(domains)}"
        ),
        "rules": isp_dns_rules,
        "denied-remote-domains": domains,
        "denied-remote-notes": "Blocked by Anti-AI + Anti-ISP Blocklist — %REMOTE%",
    }
    path.write_text(json.dumps(payload, indent=2))


def write_metadata(domains: list, source_stats: dict, path: Path):
    meta = {
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "domain_count": len(domains),
        "sources": source_stats,
    }
    path.write_text(json.dumps(meta, indent=2))

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    DIST_DIR.mkdir(exist_ok=True)
    all_domains: set = set()
    source_stats: dict = {}

    print("[1/3] Loading seed domains...")
    seeds = load_seed_domains()
    all_domains.update(seeds)
    source_stats["seed"] = len(seeds)

    print("[2/3] Fetching Certificate Transparency logs (AI + ISP)...")
    crt_domains: set = set()

    for apex in CRT_WATCH_DOMAINS:
        found = fetch_crt_subdomains(apex)
        crt_domains.update(found)
        time.sleep(0.3)

    for apex in CRT_WATCH_ISP_DOMAINS:
        found = fetch_crt_subdomains(apex)
        # Filter ISP results to tracking-relevant subdomains only
        filtered = {
            d for d in found
            if any(kw in d for kw in ISP_TRACKING_KEYWORDS)
        }
        crt_domains.update(filtered)
        time.sleep(0.3)

    all_domains.update(crt_domains)
    source_stats["crt_sh"] = len(crt_domains)
    print(f"  Total from crt.sh: {len(crt_domains)}")

    print("[3/3] Fetching community sources...")
    community = fetch_community_sources()
    all_domains.update(community)
    source_stats["community"] = len(community)

    print("\n[Filtering]")
    before = len(all_domains)
    all_domains = {d for d in all_domains if not strip_broad(d)}
    print(f"  Removed {before - len(all_domains)} overly-broad domains")
    print(f"  Final count: {len(all_domains)} domains")

    sorted_domains = sorted(all_domains)

    print("\n[Writing output]")
    write_domains_txt(sorted_domains, DIST_DIR / "domains.txt")
    write_lsrules(sorted_domains, DIST_DIR / "blocklist.lsrules")
    write_metadata(sorted_domains, source_stats, DIST_DIR / "metadata.json")
    print("  docs/domains.txt")
    print("  docs/blocklist.lsrules")
    print("  docs/metadata.json")
    print("\nDone.")


if __name__ == "__main__":
    main()
