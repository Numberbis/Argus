# Contributing to Argus

Thank you for considering a contribution. Argus is an open project and improvements of any kind are welcome.

---

## Ways to contribute

- **Bug reports** — open an issue with reproduction steps and your environment (OS, Docker version, K8s version if applicable)
- **New scanner integrations** — add a new tool under `docker/<tool>/` with its Dockerfile and scan script
- **Nuclei template packs** — curated template sets for specific targets (WordPress, Drupal, APIs…)
- **Dashboard improvements** — Flask/HTML/CSS in `docker/dashboard/`
- **Documentation** — clarifications, examples, translations

---

## Before you open a PR

1. **Open an issue first** for anything beyond a trivial fix — it avoids duplicated work
2. One PR = one concern. Don't bundle unrelated changes
3. Tests must pass (`make test-unit`)
4. New scanner integrations must include at least one unit test

---

## Development setup

```bash
git clone https://github.com/Numberbis/Argus
cd argus
cp .env.example .env          # set POSTGRES_PASSWORD

# Install test dependencies
make test-setup

# Start the local stack
make up

# Run unit tests (no database required)
make test-unit

# Run integration tests (requires running stack)
make test-integration
```

---

## Adding a new scanner

A scanner is a standalone container that:
1. Accepts `TARGET_URL`, `TARGET_NAME`, `SCAN_PROFILE`, and `COLLECTOR_URL` as environment variables
2. Runs its tool against `TARGET_URL`
3. POSTs results to `$COLLECTOR_URL/results/<tool>/<target>` in the standard payload format

**Directory structure:**

```
docker/<tool>/
├── Dockerfile
├── <tool>-scan.sh   (or .py)
└── requirements.txt (if Python)
```

**Payload format** (POST to collector):

```json
{
  "started_at": "2024-01-15T02:00:00Z",
  "target_url": "https://example.com",
  "raw_output": {},
  "findings": [
    {
      "severity": "HIGH",
      "title": "Missing security header: X-Frame-Options",
      "description": "...",
      "url": "https://example.com",
      "cvss_score": 6.1,
      "cve_ids": [],
      "remediation": "Add 'X-Frame-Options: DENY' to HTTP response headers"
    }
  ]
}
```

Severity levels: `CRITICAL` · `HIGH` · `MEDIUM` · `LOW` · `INFO`

Once the scanner works, add it to:
- `docker-compose.yml` — as a new service under the `scanners` profile
- `config/schedules.yml` — default cron schedule
- `scripts/scan-all.sh` — include in `ALL_TOOLS`
- `README.md` — scanners table

---

## Commit style

```
feat: add RetireJS scanner for JavaScript CVEs
fix: collector fails on empty findings array
docs: add screenshot to README
chore: bump nuclei to v3.2.0
```

Use lowercase, imperative mood, no period at the end.

---

## Code style

- Python: [ruff](https://github.com/astral-sh/ruff) for linting, no formatter enforced
- Shell: `set -euo pipefail` at the top of every script
- YAML: 2-space indent, explicit strings for cron expressions

---

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
