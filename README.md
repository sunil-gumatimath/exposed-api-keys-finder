# Exposed API Keys Finder

A Python tool to audit GitHub for exposed API keys from OpenAI and Anthropic.

## Features

- Scans for OpenAI and Anthropic API keys.
- Searches in code files or commit messages.
- Filters by repository, language, stars, and more.
- Resumes interrupted scans.
- Validates found keys.
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

**Example:** Search for keys in a specific repository and validate them.
```bash
python github_api_key_auditor.py --repo owner/repo --validate
```

### Key Options

-   `--repo REPO`: Specify a repository to search.
-   `--mode {code,commits}`: Set search mode.
-   `--validate`: Validate found keys.
-   `--resume`: Resume a previous scan.
-   `--output-format {json,csv,txt}`: Set the output format.

## Security Note

This tool is for security research and responsible disclosure. Please use it ethically and report any found keys to the respective providers.
