# Anti-AI Network Exploit Blocklist

Auto-updating Little Snitch blocklist covering AI platform endpoints, telemetry collectors, and training data harvesters.

## Subscription URLs

| Format | URL |
|---|---|
| Little Snitch `.lsrules` | `https://csdznwrk.github.io/ai-blocklist/blocklist.lsrules` |
| Plain domains (Pi-hole, AdGuard) | `https://csdznwrk.github.io/ai-blocklist/domains.txt` |
| Status page | `https://csdznwrk.github.io/ai-blocklist/` |

## How to subscribe in Little Snitch

1. Open Little Snitch → Rules window
2. Click **+** → **New Rule Group Subscription…**
3. Paste the `.lsrules` URL above
4. Set update interval to **Every Hour** (list refreshes every 15 min on the server side)

## Update mechanism

GitHub Actions runs every **15 minutes** and:

1. **Queries crt.sh** Certificate Transparency logs for new subdomains of every watched AI company domain — catches new infrastructure within minutes of TLS cert issuance
2. **Fetches community lists** (Hagezi Pro, v2fly AI domain lists, MoralCode antitelemetry) and filters to AI-relevant apex domains only
3. **Merges with the hand-curated seed list** (`seeds.txt`)
4. **Regenerates** `dist/domains.txt`, `dist/blocklist.lsrules`, and `dist/metadata.json`
5. **Commits** only if the domain list changed, then **deploys to GitHub Pages**

## Covered platforms

- OpenAI / ChatGPT / Sora
- Anthropic / Claude
- Google Gemini / DeepMind
- DeepSeek
- xAI / Grok
- Mistral
- Meta AI
- Perplexity
- Cohere
- Hugging Face
- Character.ai
- Cursor / Windsurf / Codeium (AI code editors)
- Runway ML / Stability AI / Midjourney / Suno / Udio / ElevenLabs
- Microsoft Copilot
- Meeting AI bots (Fireflies, Read.ai, Otter, Fathom, Granola, Tactiq)
- Shared telemetry backends (Statsig, specific Sentry/Datadog ingestion endpoints, LaunchDarkly, Segment, Arkose Labs)

## Adding domains manually

Edit `seeds.txt` and push — the next 15-minute run will pick it up and republish.

## Notes

- `sentry.io` and `datadoghq.com` are **not** blanket-blocked — only specific OpenAI/AI ingestion subdomains. Blanket blocking would break error reporting for many legitimate apps.
- Google AI domains are scoped carefully — blocking all of `googleapis.com` would break vast swaths of the web.
- Little Snitch's minimum subscription poll interval is 1 hour, so your rules will be at most ~1 hour behind the server.
