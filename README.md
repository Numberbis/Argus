<div align="center">

# ◉ Argus — The hundred-eyed AI guardian for your websites

**Continuous security audits across all your sites — triaged, deduplicated, and explained by AI.**

[![CI](https://github.com/Numberbis/Argus/actions/workflows/ci.yml/badge.svg)](https://github.com/Numberbis/Argus/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docker.com)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-CronJobs-326CE5?logo=kubernetes&logoColor=white)](https://kubernetes.io)
[![Anthropic](https://img.shields.io/badge/AI-Claude%20%7C%20GPT%20%7C%20Gemini%20%7C%20Ollama-4fc3f7)](#ai-native--bring-your-own-key)

</div>

> 🤖 **AI-native security platform** — Argus orchestrates 7 industry-standard scanners, then triages every finding: kills false positives, fuses duplicates, re-prioritizes by real-world context, and writes the fix.
>
> 🔑 **Bring your own LLM key** — Works with Claude, GPT-4, Gemini, or 100% local Ollama. ~$2/month in API costs for typical usage.
>
> 🏠 **Self-hosted, no SaaS, no telemetry** — Your scan data never leaves your server. Docker Compose for hobbyists, Kubernetes for production.

---

## 60-second demo

```bash
git clone https://github.com/Numberbis/Argus && cd Argus
cp .env.example .env && echo "POSTGRES_PASSWORD=demo" >> .env
make demo        # full stack + ~200 realistic findings, AI-triaged
```

→ Open **http://localhost:5000/real-issues** to see ~200 raw findings collapsed into ~30 actionable issues.

<!-- SCREENSHOT: demo-real-issues.gif — required before launch -->
![Argus — Real Issues view](docs/screenshots/demo-real-issues.gif)

---

## Why another scanner aggregator?

Existing scanners are noisy. A single ZAP + Nikto + Nuclei run on a small site easily produces **800+ findings**. Of those, ~60% are false positives, ~20% are duplicates, and ~10% are mis-prioritized. **You spend more time triaging than fixing.**

Argus closes that gap with an AI agent that understands the context:

| | Without Argus | With Argus |
|---|---|---|
| Findings shown | 847 raw | **23 real issues** |
| False positives surfaced | ~30% | **filtered automatically** |
| Same CVE counted N times | yes | **deduplicated** |
| Fix suggestion | generic, scanner default | **specific to your stack** |
| Time to first fix | 2–4 hours | **15 minutes** |

---

## What it does

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  config/websites.yml                                                        │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐          │
│  │   7 Scanners    │───►│    Collector    │───►│   PostgreSQL    │          │
│  │  (Docker, k8s)  │    │     FastAPI     │    │   raw findings  │          │
│  └─────────────────┘    └────────┬────────┘    └────────┬────────┘          │
│                                  │                       │                   │
│                                  │ POST /triage          │                   │
│                                  ▼                       │                   │
│                         ┌─────────────────┐              │                   │
│                         │   AI Agent      │──────────────┘                   │
│                         │  ─ /triage      │   enrich findings:               │
│                         │  ─ /remediate   │   ├─ ai_severity                 │
│                         │  ─ /chat        │   ├─ ai_is_false_positive        │
│                         │  ─ /budget      │   ├─ ai_dedup_of                 │
│                         │  BYOK LLM       │   ├─ ai_remediation              │
│                         └─────────────────┘   └─ ai_root_cause_id            │
│                                  │                                            │
│                  ┌───────────────┴───────────────┐                            │
│                  ▼                               ▼                            │
│           Dashboard (Flask)               Reports + Alerts                    │
│           ─ Real Issues view              HTML/PDF · Slack · Email            │
│           ─ AI fix suggestions                                                │
│           ─ Chat with your data                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

Drop your URL list in `config/websites.yml`. Argus runs 7 scanners on a schedule, the AI agent triages every result, the dashboard shows what's actually broken.

---

## AI-native — Bring Your Own Key

Argus works with any major LLM provider. Pick one, drop the key in `.env`, you're done.

```bash
# .env
LLM_PROVIDER=anthropic              # or openai | google | ollama
ANTHROPIC_API_KEY=sk-ant-...
LLM_DAILY_BUDGET_USD=2.00           # circuit breaker
```

| Provider | Default model | API cost (typical) | Local? |
|---|---|---|---|
| **Anthropic Claude** | `claude-sonnet-4-6` | ~$0.04 / triage | ☁️ |
| **OpenAI** | `gpt-4o-mini` | ~$0.01 / triage | ☁️ |
| **Google Gemini** | `gemini-1.5-flash` | ~$0.005 / triage | ☁️ |
| **Ollama (local)** | `llama3.1:8b` | $0 | ✅ 100% local |

**Three things the agent does:**

1. **Triage** — for each scan, decides what's real, fuses duplicates, re-prioritizes by context. Runs automatically after every scan.
2. **Remediate** — on demand, generates a concrete fix (nginx block, header, dependency bump, diff) tailored to the finding.
3. **Chat** — ask questions in natural language: *"Which sites have open critical CVEs older than 7 days?"*. The agent translates to read-only SQL, runs it, summarizes.

**Without an LLM key**, Argus keeps working — you get the scans, the dashboard, the alerts, the reports. You just lose the AI layer.

---

## Scanners

| Tool | Catches | Schedule | Notes |
|---|---|---|---|
| **OWASP ZAP** | XSS, SQLi, CSRF, IDOR — active web scanning | Mon 02:00 | profile `full` |
| **Nikto** | Dangerous files, bad HTTP config, exposed admin paths | Tue 03:00 | high FP rate (AI cleans up) |
| **Nmap** | Open ports, exposed services, NSE vuln scripts | Wed 04:00 | |
| **testssl.sh** | Weak ciphers, expired certs, TLS misconfiguration | Daily 02:00 | |
| **Nuclei** | CVE templates, misconfigurations, exposed panels | Thu 05:00 | auto-updates |
| **WPScan** | WordPress core, plugins, themes CVEs | Fri 03:00 | profile `wordpress` |
| **Trivy** | OS/library CVEs, secrets, deps misconfigs | Sat 04:00 | free DB |

All scanners run in isolated containers. Findings are normalized (severity, CVSS, CVE) and stored in PostgreSQL.

---

## Get started

### Local — Docker Compose

```bash
# 1. Clone & configure
git clone https://github.com/Numberbis/Argus && cd Argus
cp .env.example .env
# Edit .env: set POSTGRES_PASSWORD; set LLM_PROVIDER + key for AI features

# 2. Pre-loaded demo (no API key needed — uses simulated triage)
make demo
# → http://localhost:5000

# 3. Real audit on your sites — edit config/websites.yml then:
make scan
```

**Common commands**

```bash
make scan                          # all scanners, all sites in websites.yml
make scan-site  SITE=my-site       # one site, all tools
make scan-tool  TOOL=nuclei        # one tool, all sites

make agent-up                      # start AI agent service alone
make triage SCAN_ID=42             # triage a specific scan
make chat Q="Critical issues by site?"
make agent-budget                  # check today's LLM spend

make report                        # generate HTML/PDF reports
make notify                        # send pending Slack/email alerts
make monitoring                    # Prometheus + Grafana on :3000
```

### Production — Kubernetes + Ansible

```bash
make bootstrap \
  EXTRA_VARS="registry_org=Numberbis \
    dashboard_domain=argus.example.com \
    db_password=$(openssl rand -hex 16) \
    anthropic_api_key=sk-ant-..."
```

The Ansible playbook deploys Postgres, Collector, AI Agent, Dashboard, scanner CronJobs, plus optional Notifier and Report Generator.

---

## Configuration

**`config/websites.yml`** — your targets:

```yaml
websites:
  - name: my-site
    url: https://my-site.com
    scan_profile: full        # full | light | ssl-only | wordpress
    notify_email: security@my-site.com
    slack_channel: "#security-alerts"
```

**`config/schedules.yml`** — when each scanner runs (k8s CronJob format).
**`config/thresholds.yml`** — alert thresholds (CVSS, severities).

---

## Status & roadmap

**v0.1 (current)** — triage agent, remediation agent, chat, BYOK, demo seed.
**v0.2 (planned)** — orchestrator agent (smart scanner selection from recon), MCP server interface, Linear/Jira ticket integration.
**v0.3 (planned)** — agent-as-MCP-tool so external clients (Claude Code, Cursor) can query Argus directly.

Issues and PRs welcome — especially additional Nuclei templates, scanner integrations, and prompt improvements.

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

Built for web agencies, freelancers, and security teams responsible for more than 10 websites.
**If Argus saved you a breach, give it a ⭐.**

</div>
