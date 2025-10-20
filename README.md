# Exposed API Keys Finder

A Python tool to audit GitHub repositories for exposed API keys from popular providers like OpenAI and Anthropic.

## Features

- **Dual Scripts**: Simple (`app.py`) and enhanced (`app_enhanced.py`) versions
- **Multi-Provider Support**: Scans for OpenAI and Anthropic API keys
- **Flexible Search**: Search code files or commit messages
- **Advanced Filtering**: Filter by repository stars, language, update date
- **Progress Tracking**: Resume interrupted scans with checkpointing
- **Key Validation**: Optional validation of found keys
- **Multiple Output Formats**: JSON, CSV, or TXT export
- **Rate Limiting**: Built-in handling of GitHub API rate limits

## Installation

1. Clone the repository:

```bash
git clone https://github.com/sunil-gumatimath/exposed-api-keys-finder.git
cd exposed-api-keys-finder
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Set up environment variables:
Create a `.env` file in the project root:

```
GITHUB_TOKEN=your_github_personal_access_token_here
```

## Usage

### Simple Version (app.py)

Basic auditing with minimal features. Found keys are saved to `keys.txt`.

```bash
python app.py
```

### Enhanced Version (app_enhanced.py)

Full-featured auditing with advanced options:

```bash
python app_enhanced.py [options]
```

#### Command Line Options

- `--repo REPO`: Specific repository (format: owner/repo)
- `--extensions EXTENSIONS`: File extensions (comma-separated, e.g., py,js,env)
- `--mode {code,commits}`: Search mode (default: code)
- `--validate`: Validate found API keys
- `--output-format {json,csv,txt}`: Output format (default: json)
- `--output-file FILE`: Output file path (default: audit_results.json)
- `--max-pages NUM`: Maximum pages to fetch
- `--min-stars NUM`: Minimum repository stars
- `--language LANG`: Filter by programming language
- `--updated-after DATE`: Filter repos updated after date (ISO format)
- `--resume`: Resume from previous scan
- `--checkpoint-file FILE`: Checkpoint file path

#### Examples

Audit all repositories for API keys:

```bash
python app_enhanced.py
```

Search specific repository:

```bash
python app_enhanced.py --repo octocat/Hello-World
```

Search with validation:

```bash
python app_enhanced.py --validate --max-pages 5
```

Resume interrupted scan:

```bash
python app_enhanced.py --resume
```

## Output

### Output Files

The scripts generate the following output files:

- **keys.txt** (Simple version only): Plain text file with discovered API keys, one per line
- **audit_results.json** (Enhanced version): Structured JSON containing detailed scan results (default output file)
- **audit.log** (Enhanced version): Detailed scan log with timestamps, API calls, and processing information
- **progress.json** (Enhanced version with --resume): Checkpoint file for resuming interrupted scans

### Result Format

Results from the enhanced script contain the following information:

- **Provider**: OpenAI or Anthropic
- **Key**: The discovered API key value
- **Repository**: Repository name and owner
- **Path**: File path where the key was found
- **URL**: Direct GitHub link to the file
- **Timestamp**: When the key was discovered
- **Validation Status**: Whether the key is valid (if --validate was used)

## Security Considerations

- **Never commit API keys** to version control
- Use environment variables for sensitive tokens
- The `.env` file is ignored by Git for security
- Report found keys to respective providers for revocation
- This tool is for security research and responsible disclosure

## API Keys Detected

The tool searches for:

- **OpenAI**: Keys matching `sk-[A-Za-z0-9_-]{48}`
- **Anthropic**: Keys matching `sk-ant-api03-[A-Za-z0-9_-]{95}`

## Requirements

- Python 3.8+
- GitHub Personal Access Token with `repo` scope
- Internet connection for API calls

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see LICENSE file for details

## Disclaimer

This tool is provided for educational and security research purposes. Users are responsible for complying with GitHub's Terms of Service and applicable laws. Use responsibly and ethically.
