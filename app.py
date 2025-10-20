import requests
import re
import base64
import time
from typing import Dict, Any, List
import importlib.util
import os

try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except ImportError:
    pass  # dotenv not installed, rely on manual env var setting

if importlib.util.find_spec("tqdm") is not None:
    from tqdm import tqdm  # type: ignore
else:
    tqdm = None

# Regex patterns for API keys
ANTHROPIC_KEY_PATTERN = r'sk-ant-api03-[A-Za-z0-9_-]{95}'
OPENAI_KEY_PATTERN = r'sk-[A-Za-z0-9_-]{48}'

def get_github_token() -> str:
    token = os.getenv('GITHUB_TOKEN')
    if token:
        return token
    return input("Enter your GitHub token: ").strip()

def search_github_code(query: str, token: str, max_results: int = 10) -> Dict[str, Any]:
    url = f"https://api.github.com/search/code?q={query}&type=code&per_page={max_results}"
    headers = {"Authorization": f"token {token}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 403:
        raise Exception("Rate limit exceeded or authentication failed")
    response.raise_for_status()
    return response.json()

def get_file_content(repo_full_name: str, path: str, token: str) -> str | None:
    url = f"https://api.github.com/repos/{repo_full_name}/contents/{path}"
    headers = {"Authorization": f"token {token}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 403:
        return None  # Skip if rate limited
    response.raise_for_status()
    data = response.json()
    if 'content' in data:
        return base64.b64decode(data['content']).decode('utf-8', errors='ignore')
    return None

def extract_keys(content: str, pattern: str) -> List[str]:
    return re.findall(pattern, content)

def validate_openai_key(key: str) -> bool:
    try:
        response = requests.get("https://api.openai.com/v1/models", headers={"Authorization": f"Bearer {key}"}, timeout=10)
        return response.status_code == 200
    except Exception:
        return False

def validate_anthropic_key(key: str) -> bool:
    try:
        headers = {"x-api-key": key, "anthropic-version": "2023-06-01"}
        response = requests.get("https://api.anthropic.com/v1/models", headers=headers, timeout=10)
        return response.status_code == 200
    except Exception:
        return False

def audit_api_keys(provider: str, query: str, pattern: str, token: str, validate: bool = False) -> None:
    print(f"\nAuditing {provider} API keys...")
    try:
        results = search_github_code(query, token, max_results=100)
        items = results.get('items', [])
        if not items:
            print(f"No results found for {provider}.")
            return
        files_scanned = 0
        keys_total = 0
        iterator = tqdm(items, desc=f"Auditing {provider}") if tqdm else items
        for item in iterator:
            repo = item['repository']['full_name']
            path = item['path']
            print(f"Checking {repo}/{path}...")
            content = get_file_content(repo, path, token)
            if content:
                keys = extract_keys(content, pattern)
                if keys:
                    print(f"Found potential {provider} keys in {repo}/{path}:")
                    for key in keys:
                        print(f"  {key}")
                        if validate:
                            valid = False
                            if provider == "OpenAI":
                                valid = validate_openai_key(key)
                            elif provider == "Anthropic":
                                valid = validate_anthropic_key(key)
                            print(f"    Valid: {valid}")
                    keys_total += len(keys)
                    # Append to keys.txt
                    with open('keys.txt', 'a') as f:
                        f.write(f"{provider}: {repo}/{path}\n")
                        for key in keys:
                            f.write(f"  {key}\n")
                        f.write("\n")
                else:
                    print(f"No keys found in {repo}/{path}.")
            else:
                print(f"Could not fetch content for {repo}/{path}.")
            files_scanned += 1
            time.sleep(1)  # Rate limit precaution
        print(f"Summary for {provider}: {files_scanned} files scanned, {keys_total} keys found.")
    except Exception as e:
        print(f"Error auditing {provider}: {e}")

def search_github_commits(query: str, token: str, max_results: int = 10) -> Dict[str, Any]:
    url = f"https://api.github.com/search/commits?q={query}&per_page={max_results}"
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    response = requests.get(url, headers=headers)
    if response.status_code == 403:
        raise Exception("Rate limit exceeded or authentication failed")
    response.raise_for_status()
    return response.json()

def audit_commit_messages(provider: str, query: str, pattern: str, token: str, validate: bool = False) -> None:
    print(f"\nAuditing {provider} API keys in commit messages...")
    try:
        results = search_github_commits(query, token, max_results=100)
        items = results.get('items', [])
        if not items:
            print(f"No results found for {provider}.")
            return
        files_scanned = 0
        keys_total = 0
        iterator = tqdm(items, desc=f"Auditing {provider} commits") if tqdm else items
        for item in iterator:
            repo = item['repository']['full_name']
            commit_sha = item['sha']
            message = item['commit']['message']
            print(f"Checking commit {commit_sha[:7]} in {repo}: {message[:50]}...")
            keys = extract_keys(message, pattern)
            if keys:
                print(f"Found potential {provider} keys in commit {commit_sha} message:")
                for key in keys:
                    print(f"  {key}")
                    if validate:
                        valid = False
                        if provider == "OpenAI":
                            valid = validate_openai_key(key)
                        elif provider == "Anthropic":
                            valid = validate_anthropic_key(key)
                        print(f"    Valid: {valid}")
                keys_total += len(keys)
                # Append to keys.txt
                with open('keys.txt', 'a') as f:
                    f.write(f"{provider}: {repo}/commit/{commit_sha}\n")
                    for key in keys:
                        f.write(f"  {key}\n")
                    f.write("\n")
            else:
                print(f"No keys found in commit message.")
            files_scanned += 1
            time.sleep(1)  # Rate limit precaution
        print(f"Summary for {provider} commits: {files_scanned} commits scanned, {keys_total} keys found.")
    except Exception as e:
        print(f"Error auditing {provider} commits: {e}")

if __name__ == "__main__":
    try:
        token = get_github_token()
        # Defaults for testing
        repo = ""  # Global search
        extensions = ""  # All extensions
        mode = "code"  # Code mode
        validate = False  # No validation
        print(f"Using defaults: repo='{repo}', extensions='{extensions}', mode='{mode}', validate={validate}")
        query_suffix = f" repo:{repo}" if repo else ""
        if mode == "code":
            if extensions:
                for ext in extensions.split(','):  # type: ignore
                    ext = ext.strip().lstrip('.')  # type: ignore
                    query_suffix += f" extension:{ext}"
        if mode == "commits":  # type: ignore
            # Search for Anthropic keys in commits
            audit_commit_messages("Anthropic", f"sk-ant-{query_suffix}", ANTHROPIC_KEY_PATTERN, token, validate)
            # Search for OpenAI keys in commits
            audit_commit_messages("OpenAI", f"sk-{query_suffix}", OPENAI_KEY_PATTERN, token, validate)
        else:
            # Search for Anthropic keys in code
            audit_api_keys("Anthropic", f"sk-ant-{query_suffix}", ANTHROPIC_KEY_PATTERN, token, validate)
            # Search for OpenAI keys in code
            audit_api_keys("OpenAI", f"sk-{query_suffix}", OPENAI_KEY_PATTERN, token, validate)
        print("\nAudit complete. Remember to report any found keys to the respective providers for revocation.")
    except ValueError as e:
        print(f"Configuration error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
