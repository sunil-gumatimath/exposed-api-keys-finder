# Exposed API Key Auditor

A powerful, asynchronous Python tool designed to scan GitHub repositories and commit messages for exposed API keys. It supports resumption of scans, detailed filtering, and automatic validation for supported providers.

## Features

- **Multi-Provider Support**: specialized patterns for OpenAI, Anthropic, and Google AI (Gemini) keys.
- **Dual Search Modes**: Scan both code (`--mode code`) and commit messages (`--mode commits`).
- **Smart Validation**: Automatically validates found keys against their respective APIs (OpenAI & Anthropic supported) to determine if they are active.
- **Resumable Scans**: Tracks progress in `progress.json` so you can stop and resume long-running audits without losing work.
- **Advanced Filtering**:
  - specific repositories (`--repo`)
  - file extensions (`--extensions`)
  - minimum stars (`--min-stars`)
  - language (`--language`)
  - last updated date (`--updated-after`)
- **Flexible Logging**: Outputs to console and `audit.log`. Can export results to JSON, CSV, or TXT.

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/sunil-gumatimath/exposed-api-keys-finder.git
    cd exposed-api-keys-finder
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3.  Configure your environment:
    Copy `.env.example` to `.env` and add your GitHub Personal Access Token (PAT).
    ```bash
    cp .env.example .env
    # Edit .env and set GITHUB_TOKEN=your_token_here
    ```

## Usage

Basic usage to scan for OpenAI and Anthropic keys (default):
```bash
python auditor.py
```

### Examples

**Scan a specific repository:**
```bash
python auditor.py --repo sunil-gumatimath/exposed-api-keys-finder
```

**Include Google AI keys in the scan:**
```bash
python auditor.py --providers openai,anthropic,google
```

**Scan commit messages instead of code:**
```bash
python auditor.py --mode commits --repo some-org/some-repo
```

**Enable key validation (check if keys are active):**
```bash
python auditor.py --validate
```

**Filter by language and file extension:**
```bash
python auditor.py --language python --extensions py,ipynb
```

**Output results to CSV:**
```bash
python auditor.py --output-format csv --output-file results.csv
```

## Supported Providers & Validation

| Provider | Key Patterns | Validation Supported | Notes |
|----------|--------------|----------------------|-------|
| **OpenAI** | `sk-...` (classic, proj, live, test) | ✅ Yes | Tests against `/v1/models` |
| **Anthropic** | `sk-ant-...` | ✅ Yes | Tests against `/v1/models` |
| **Google AI** | `AIza...` | ❌ No | No public validation endpoint available |

## CLI Options

| Argument | Description | Default |
|----------|-------------|---------|
| `--repo` | Specific repository to search (e.g., `owner/repo`) | Global search |
| `--mode` | Search mode: `code` or `commits` | `code` |
| `--providers` | Comma-separated list of providers to scan | `openai,anthropic` |
| `--extensions` | Filter by file extensions (comma-separated) | All |
| `--validate` | distinctively check if found keys are active | `False` |
| `--output-format` | Format for output file (`json`, `csv`, `txt`) | `json` |
| `--output-file` | Path to save results | `audit_results.json` |
| `--resume` | Resume from the last checkpoint | `False` |
| `--checkpoint-file` | File to store progress | `progress.json` |
| `--timeout` | Timeout (seconds) for validation requests | `10` |
| `--min-stars` | Filter repos by minimum star count | None |
| `--language` | Filter repos by programming language | None |
| `--updated-after` | Filter repos updated after date (`YYYY-MM-DD`) | None |
| `--sort` | Sort order for GitHub search (`indexed` or best match) | `indexed` |

## Security & Ethics

**This tool is for security research and responsible disclosure purposes only.**

If you discover exposed API keys:
1.  **Do not use them.**
2.  Report them to the repository owner immediately.
3.  Report them to the respective provider for revocation:

*   **OpenAI**: [https://platform.openai.com/api-keys](https://platform.openai.com/api-keys)
*   **Anthropic**: [https://console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys)
*   **Google Cloud/AI**: [https://console.cloud.google.com/apis/credentials](https://console.cloud.google.com/apis/credentials)

## License

This project is open source. Feel free to use, modify, and distribute it as you see fit.
