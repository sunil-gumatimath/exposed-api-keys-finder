# Exposed API Keys Finder

A Python tool to audit GitHub for exposed API keys from OpenAI and Anthropic.

## Features

- Scans for OpenAI and Anthropic API keys (broadened patterns for newer formats).
- Searches in code files or commit messages.
- Filters by repo, file extensions, language, stars, updated date.
- Resumes interrupted scans via checkpoint file.
- Optional validation of found keys.
- Exports results to JSON, CSV, or TXT.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/sunil-gumatimath/exposed-api-keys-finder.git
    cd exposed-api-keys-finder
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Set up your GitHub Token:**
    Create a `.env` file and add your token:
    ```
    GITHUB_TOKEN=your_github_personal_access_token
    ```

## Usage

Run the auditor with the following command. You will be prompted for your GitHub token if it's not in the `.env` file.

```bash
python github_api_key_auditor.py [options]
```

### Examples

- Specific repo and validate:
  ```bash
  python github_api_key_auditor.py --repo owner/repo --validate
  ```
- Global scan, limit pages and file types:
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

### Options

- `--repo owner/repo`         Search a specific repository.
- `--extensions ext1,ext2`    File extensions filter (e.g., `py,js,env`).
- `--mode {code,commits}`     Search code or commit messages.
- `--validate`                Validate found keys against providers.
- `--output-format {json,csv,txt}`  Output format (default: json).
- `--output-file PATH`        Output file path (default: audit_results.json).
- `--max-pages N`             Limit GitHub search pages fetched.
- `--min-stars N`             Minimum repo stars.
- `--language LANG`           Filter by language.
- `--updated-after YYYY-MM-DD` Filter repos updated after date.
- `--resume`                  Resume from checkpoint.
- `--checkpoint-file PATH`    Progress checkpoint file (default: progress.json).

### Environment

- `.env` should contain: `GITHUB_TOKEN=your_github_personal_access_token`
- Disable file logging (only console logs): set `GITHUB_AUDITOR_DISABLE_FILE_LOG=1` when running.

## Security Note

This tool is for security research and responsible disclosure. Please use it ethically and report any found keys to the respective providers.
