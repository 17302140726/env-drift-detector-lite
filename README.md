# Env Drift Detector Lite — Find Out Why Prod Is Broken Before Your Users Do

Your `.env` drifted from `.env.example` three deploys ago. `MAIL_TOKEN` exists only in the
example. `API_KEY` still says `changeme`. And a live `sk_live_...` key is sitting in a file
that just got zipped into your repo backup.

**Env Drift Detector Lite** catches all of that in one pass — locally, zero dependencies,
one Python file.

> This is the free lite edition. The **full [Env Drift Detector](https://qiliang.gumroad.com/l/pgsxer) ($19)**
> adds secret-key entropy scoring with shape-aware false-positive suppression, `--allow-extra`
> team-style policies, `--json` on every subcommand for pipelines, machine-readable CI
> annotations, project-wide sweep exclusions, and baseline ratcheting.

## What It Checks

```
$ python env_drift_detector.py drift --env .env --example .env.example
[MISSING_IN_ENV] .env missing 1 key defined in .env.example: MAIL_TOKEN
[PLACEHOLDER_SECRET] .env secret-shaped key still holding a placeholder: API_KEY

$ python env_drift_detector.py leak --env weak.env
[LIVE_CREDENTIAL_SHAPE] STRIPE_SECRET_KEY: live Stripe key shape detected
[LOW_ENTROPY] SECRET: entropy -0.00 < 3.5 (looks hand-typed)
```

### `drift` — compare `.env` against `.env.example`
- **MISSING_IN_ENV** — keys your example promises but prod lacks (the classic "undefined index" outage)
- **EXTRA_IN_ENV** — keys living only in `.env` (undocumented config nobody remembers adding)
- **EMPTY_VALUE** — keys set to nothing
- **PLACEHOLDER_SECRET** — secret-shaped keys still holding `changeme` / `your-password-here`

### `leak` — scan any env file for credential hazards
- **KNOWN_DEFAULT** — Django `django-insecure-`, AWS example keys, default DB URLs
- **LOW_ENTROPY** — "secret" keys whose value looks hand-typed (`aaaaaaaaaaaa`)
- **LIVE_CREDENTIAL_SHAPE** — real-looking `sk_live_`, `AKIA...`, `ghp_`, `xoxb-`, PEM blocks

### `report` — sweep a whole project
Walks the tree (skips `.git`, `node_modules`, `venv`), finds every env file, runs drift + leak
on each, prints a table.

## CI / Cron Ready — Exit Code Contract

| Exit code | Meaning |
|-----------|---------|
| `0` | Clean |
| `1` | Issues found (drift or leak) |
| `2` | Bad arguments / missing file |

```yaml
# GitHub Actions
- name: Env drift check
  run: python env_drift_detector.py report --root . || exit 1
```

## Why Local-Only Matters

Every "check your .env security" SaaS wants you to upload the very file that contains all your
secrets. This tool never opens a network connection. Your keys stay on your machine. Audit the
source — it's one readable Python file.

## Try It In 10 Seconds

```bash
git clone https://github.com/17302140726/env-drift-detector-lite.git
cd env-drift-detector-lite
python env_drift_detector.py report --root .
```

## More Tools

- **[Env Drift Detector (full)](https://qiliang.gumroad.com/l/pgsxer)** — entropy scoring, baseline ratchet, `--json` everywhere ($19)
- **[More single-purpose dev tools](https://qiliang.gumroad.com)** — cron auditors, log auditors, cert sentinels
- **[agentechip.com](https://agentechip.com)** — the studio behind these tools

## License

MIT — use it anywhere, including commercial projects.
