# Exposed API Key Auditor

Async Python CLI to scan GitHub code or commit messages for exposed API keys (OpenAI, Anthropic, Google AI), with resumable checkpoints, optional validation, and safer storage defaults.

## Features

- Scans GitHub `code` search or `commits` search.
- Provider support:
  - OpenAI (`sk-...`, `sk-proj-...`, `sk-live-...`, `sk-test-...`)
  - Anthropic (`sk-ant-...`)
  - Google AI (`AIza...`)
- Async + bounded concurrency for faster scans.
- Checkpoint/resume support (`progress.json`).
- Optional key validation:
  - OpenAI: yes
  - Anthropic: yes
  - Google AI: no reliable lightweight validation endpoint
- Context/noise filtering to reduce false positives.
- Optional allow/deny regex filters.
- Export to JSON/CSV/TXT.
- Optional encrypted output using Fernet.

## Security model (important)

By default, raw keys are **not** stored.

Stored fields are:
- `key_hash` (SHA-256)
- `key_masked` (partial view only)

Where stored:
- Checkpoint: `progress.json`
- Export output: file from `--output-file` (default `audit_results.json`)

Raw keys are stored only if you explicitly pass:
- `--store-raw-keys` (unsafe)

## Requirements

- Python 3.11+ recommended
- GitHub Personal Access Token in `GITHUB_TOKEN`

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Setup

1. Copy `.env.example` to `.env`.
2. Set:
   - `GITHUB_TOKEN=your_token`
3. Optional:
   - `OUTPUT_ENCRYPTION_KEY=...` for encrypted exports.
   - `GITHUB_AUDITOR_DISABLE_FILE_LOG=1` to disable `audit.log`.

## Quick start

Basic run:

```bash
python auditor.py
```

Dry run (search only, no findings export):

```bash
python auditor.py --dry-run --providers openai,anthropic,google
```

Target a single repository:

```bash
python auditor.py --repo owner/repo --providers openai,anthropic,google
```

Validate discovered keys:

```bash
python auditor.py --validate
```

High-throughput scan:

```bash
python auditor.py --max-concurrency 20 --checkpoint-interval 50
```

## Common commands

Code mode with filters:

```bash
python auditor.py --mode code --extensions py,js,env --language python --min-stars 50
```

Commit-message scan:

```bash
python auditor.py --mode commits --repo owner/repo
```

Incremental scan from last checkpoint time:

```bash
python auditor.py --resume --since-checkpoint
```

Encrypted JSON export:

```bash
python auditor.py --encrypt-output --output-file results.enc
```

Allow/deny filtering:

```bash
python auditor.py --allow-patterns OPENAI_API_KEY,ANTHROPIC_API_KEY --deny-patterns example,dummy,mock
```

## CLI options

Core:

- `--repo`: target repository (`owner/repo`), default global search.
- `--mode`: `code` or `commits` (default `code`).
- `--providers`: comma-separated providers (`openai,anthropic,google`).
- `--extensions`: comma-separated file extensions (code mode only).
- `--validate`: validate found keys where supported.
- `--output-format`: `json`, `csv`, `txt`.
- `--output-file`: export path.
- `--resume`: continue from checkpoint.
- `--checkpoint-file`: checkpoint path (default `progress.json`).
- `--max-pages`: max GitHub result pages.
- `--min-stars`: minimum repo stars.
- `--language`: repo language filter.
- `--updated-after`: repo updated after date (`YYYY-MM-DD`).
- `--sort`: search sort mode (`indexed` or empty best-match mode).
- `--timeout`: validation request timeout seconds.

Performance/UX:

- `--max-concurrency`: concurrent item workers.
- `--checkpoint-interval`: save progress every N processed items.
- `--dry-run`: search only, no content processing/export.
- `--since-checkpoint`: only process results newer than checkpoint timestamp.

Security/filtering:

- `--allow-patterns`: comma-separated regex list; if provided, matching context is prioritized.
- `--deny-patterns`: comma-separated regex list; matched context is rejected.
- `--store-raw-keys`: include raw keys in checkpoint/export (unsafe).
- `--encrypt-output`: encrypt exported file with Fernet.
- `--encryption-key`: Fernet key string (or use `OUTPUT_ENCRYPTION_KEY` env var).

## Output files

- `progress.json`:
  - processed identifiers
  - findings
  - dedupe hashes
  - checkpoint timestamp
- `audit.log`:
  - runtime logs (unless disabled)
- Export file:
  - JSON/CSV/TXT or encrypted bytes if `--encrypt-output`

## Testing

Run tests:

```bash
python -m pytest -q
```

CI:
- GitHub Actions workflow in `.github/workflows/ci.yml` runs tests on Python 3.11 and 3.12.

## Troubleshooting

- `ModuleNotFoundError: dotenv` or `No module named pytest`:
  - `python -m pip install -r requirements.txt`
- GitHub rate limits:
  - use a valid PAT with appropriate scope
  - reduce `--max-concurrency`
  - set `--max-pages`
- Empty results:
  - broaden providers
  - remove strict filters (`--language`, `--min-stars`, `--updated-after`)

## Responsible use

This tool is for authorized security auditing and responsible disclosure only.
Do not use discovered credentials. Report exposures to repository owners/providers for revocation.
