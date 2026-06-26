#!/usr/bin/env python3
"""
Anti-AI Blocklist Updater
Pulls from:
  1. Certificate Transparency logs (crt.sh) — near real-time new subdomains
  2. GitHub commit feeds — community domain list updates (Hagezi, v2fly, etc.)
  3. Static seed list — hand-curated baseline domains

Outputs:
  docs/domains.txt         — plain domain-per-line (Little Snitch hosts format)
  docs/blocklist.lsrules   — Little Snitch JSON rule group
  docs/metadata.json       — last updated, domain count, source stats
"""

import json
import re
import time
import urllib.request
import urllib.error
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
    "openai.com",
    "chatgpt.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "anthropic.com",
    "claude.ai",
    "deepseek.com",
    "x.ai",
    "mistral.ai",
    "perplexity.ai",
    "cohere.com",
    "cohere.ai",
    "character.ai",
    "cursor.sh",
    "cursor.com",
    "codeium.com",
    "windsurf.com",
    "stability.ai",
    "runwayml.com",
    "elevenlabs.io",
    "suno.ai",
    "udio.com",
    "midjourney.com",
    "meta.ai",
    "grok.com",
    "huggingface.co",
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

# Domains that are too broad to block (would break non-AI services)
SAFELIST = {
    "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "microsoft.com", "azure.com", "windows.com", "office.com",
    "cloudflare.com", "cloudflare.net", "stripe.com",
    "github.com", "githubusercontent.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazonaws.com", "aws.amazon.com",
    "discord.com", "discordapp.com",
    "auth0.com",  # broad — only specific openai auth0 subdomain is useful
    "sentry.io",  # broad — we only want specific OpenAI sentry ingestion subdomains
    "twitter.com", "x.com",
    "localhost", "local",
}

# Regex patterns that flag a domain as too broad / infrastructure-level
BROAD_PATTERNS = [
    re.compile(r"^(cdn|static|assets|img|fonts|api)\.[a-z]+\.(com|net|org)$"),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fetch(url: str, timeout: int = 15) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "anti-ai-blocklist/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"  [WARN] Failed to fetch {url}: {e}")
        return ""


def is_valid_domain(d: str) -> bool:
    d = d.strip().lower()
    if not d or d.startswith("#") or len(d) > 253:
        return False
    # Must look like a domain
    if not re.match(r"^[a-z0-9*._-]+$", d):
        return False
    # Must have at least one dot
    if "." not in d:
        return False
    return True


def strip_broad(domain: str) -> bool:
    """Return True if domain should be excluded (too broad)."""
    apex = ".".join(domain.split(".")[-2:])
    if apex in SAFELIST or domain in SAFELIST:
        return True
    for pat in BROAD_PATTERNS:
        if pat.match(domain):
            return True
    return False


def parse_domains_from_text(text: str) -> set:
    """Extract domain names from hosts file, plain list, or v2fly format."""
    domains = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("@"):
            continue
        # hosts format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
        if re.match(r"^(0\.0\.0\.0|127\.0\.0\.1)\s+", line):
            parts = line.split()
            if len(parts) >= 2:
                line = parts[1]
        # v2fly format: "full:domain.com" or "domain:keyword"
        if line.startswith("full:"):
            line = line[5:]
        if ":" in line:
            continue  # skip directives like "include:", "domain:", etc.
        # Strip trailing comments
        line = line.split("#")[0].strip()
        if is_valid_domain(line):
            domains.add(line.lower())
    return domains


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

def fetch_crt_subdomains(apex: str) -> set:
    """Query crt.sh certificate transparency logs for subdomains of apex."""
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
            val = rec.get(field, "")
            for line in val.splitlines():
                line = line.strip().lstrip("*.")
                if is_valid_domain(line) and line.endswith(apex):
                    domains.add(line.lower())
    print(f"  crt.sh [{apex}]: {len(domains)} domains")
    return domains


def fetch_community_sources() -> set:
    domains = set()
    for url in COMMUNITY_SOURCES:
        print(f"  Community: {url.split('/')[-1]}")
        text = fetch(url)
        found = parse_domains_from_text(text)
        # Community lists are huge — only keep domains whose apex matches AI companies
        ai_apexes = set(".".join(d.split(".")[-2:]) for d in CRT_WATCH_DOMAINS)
        filtered = {d for d in found if ".".join(d.split(".")[-2:]) in ai_apexes}
        print(f"    → {len(filtered)} AI-relevant domains (of {len(found)} total)")
        domains.update(filtered)
        time.sleep(0.5)  # be polite
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
    payload = {
        "name": "Anti-AI Network Exploit Blocklist",
        "description": (
            f"Auto-updated blocklist covering AI platform endpoints, telemetry collectors, "
            f"and training data harvesters. Sources: crt.sh CT logs, Hagezi, v2fly, MoralCode antitelemetry, "
            f"hand-curated seed list. Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}. "
            f"Total domains: {len(domains)}."
        ),
        "denied-remote-domains": domains,
        "denied-remote-notes": "Blocked by Anti-AI Blocklist — %REMOTE%",
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

    print("[2/3] Fetching Certificate Transparency logs...")
    crt_domains: set = set()
    for apex in CRT_WATCH_DOMAINS:
        found = fetch_crt_subdomains(apex)
        crt_domains.update(found)
        time.sleep(0.3)  # rate limit crt.sh
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
