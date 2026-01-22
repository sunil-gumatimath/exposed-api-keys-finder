# Exposed API Keys Finder

A Python tool to audit GitHub for exposed API keys from multiple providers including OpenAI, Anthropic, and Google AI.

## Features

- Scans for API keys from multiple providers:
  - **OpenAI** - sk-* keys (classic, proj, live, test variants)
  - **Anthropic** - sk-ant-* keys
  - **Google AI** - AIza* keys (Gemini API)
- Searches in code files or commit messages
- Filters by repo, file extensions, language, stars, updated date
- Resumes interrupted scans via checkpoint file
- Optional validation of found keys (where supported)
- Configurable timeout for API validation requests
- Exports results to JSON, CSV, or TXT

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/sunil-gumatimath/exposed-api-keys-finder.git
   cd exposed-api-keys-finder
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up your GitHub Token:**
   Copy the example environment file and add your token:
   ```bash
   cp .env.example .env
   ```
   Then edit `.env` and add your GitHub personal access token:
   ```
   GITHUB_TOKEN=your_github_personal_access_token
   ```

## Usage

Run the auditor with the following command. You will be prompted for your GitHub token if it's not in the `.env` file.

```bash
python github_api_key_auditor.py [options]
```

### Examples

- Scan a specific repo for OpenAI and Anthropic keys (default):
  ```bash
  python github_api_key_auditor.py --repo owner/repo --validate
  ```

- Scan for all supported providers:
  ```bash
  python github_api_key_auditor.py --providers openai,anthropic,google --max-pages 1
  ```

- Global scan with file type filter:
  ```bash
  python github_api_key_auditor.py --extensions py,js,env --max-pages 1
  ```

- Commit messages mode:
  ```bash
  python github_api_key_auditor.py --mode commits --repo owner/repo
  ```

- Resume an interrupted scan and write CSV:
  ```bash
  python github_api_key_auditor.py --resume --checkpoint-file progress.json \
    --output-format csv --output-file audit.csv
  ```

- Scan only for Google AI keys:
  ```bash
  python github_api_key_auditor.py --providers google --extensions py,env
  ```

### Options

| Option | Description |
|--------|-------------|
| `--repo owner/repo` | Search a specific repository |
| `--extensions ext1,ext2` | File extensions filter (e.g., `py,js,env`) |
| `--mode {code,commits}` | Search code or commit messages (default: code) |
| `--providers list` | Comma-separated providers: `openai,anthropic,google` (default: `openai,anthropic`) |
| `--validate` | Validate found keys against provider APIs |
| `--timeout N` | Timeout for validation requests in seconds (default: 10) |
| `--output-format {json,csv,txt}` | Output format (default: json) |
| `--output-file PATH` | Output file path (default: audit_results.json) |
| `--max-pages N` | Limit GitHub search pages fetched |
| `--min-stars N` | Minimum repo stars |
| `--language LANG` | Filter by programming language |
| `--updated-after YYYY-MM-DD` | Filter repos updated after date |
| `--resume` | Resume from checkpoint |
| `--checkpoint-file PATH` | Progress checkpoint file (default: progress.json) |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | Your GitHub personal access token |
| `GITHUB_AUDITOR_DISABLE_FILE_LOG` | Set to `1` to disable file logging (console only) |

## Key Validation Support

| Provider | Validation Supported | Notes |
|----------|---------------------|-------|
| OpenAI | Yes | Tests against /v1/models endpoint |
| Anthropic | Yes | Tests against /v1/models endpoint |
| Google AI | No | No public validation endpoint |

## Project Structure

```
exposed-api-keys-finder/
├── github_api_key_auditor.py  # Main auditor script
├── requirements.txt           # Python dependencies
├── .env.example              # Environment template
├── .env                      # Your local config (git-ignored)
├── .gitignore                # Git exclusions
├── tests/                    # Unit tests
└── README.md                 # This file
```

## Security Note

This tool is for security research and responsible disclosure. Please use it ethically and report any found keys to the respective providers for revocation:

- **OpenAI**: Revoke at https://platform.openai.com/api-keys
- **Anthropic**: Revoke at https://console.anthropic.com/settings/keys
- **Google AI**: Revoke at https://console.cloud.google.com/apis/credentials

## License

MIT License
