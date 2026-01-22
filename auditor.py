import asyncio
import aiohttp
import argparse
import json
import csv
import re
import base64
import time
import logging
from typing import Dict, Any, List, Set, Optional
from pathlib import Path
from datetime import datetime
import importlib.util
import os
from dotenv import load_dotenv
from urllib.parse import quote_plus

load_dotenv()

if importlib.util.find_spec("tqdm") is not None:
    from tqdm import tqdm
else:
    tqdm = None

# API Key Patterns - Broadened to capture newer key formats
# Anthropic keys generally start with sk-ant- and are long
ANTHROPIC_KEY_PATTERN = r"\bsk-ant-[A-Za-z0-9_-]{50,}\b"
# OpenAI keys include classic sk-<48>, and newer variants like sk-proj-*, sk-live-*, sk-test-*
OPENAI_KEY_PATTERN = r"\b(?:sk-[A-Za-z0-9]{48}|sk-(?:live|test)-[A-Za-z0-9]{24,}|sk-proj-[A-Za-z0-9_-]{20,})\b"
# Google AI (Gemini) API keys - typically start with AIza
GOOGLE_AI_KEY_PATTERN = r"\bAIza[A-Za-z0-9_-]{35}\b"

# Default timeout for API validation requests (seconds)
DEFAULT_VALIDATION_TIMEOUT = 10

handlers = [logging.StreamHandler()]
if os.getenv('GITHUB_AUDITOR_DISABLE_FILE_LOG', '0').lower() not in {'1', 'true', 'yes'}:
    handlers.insert(0, logging.FileHandler('audit.log'))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=handlers
)
logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self, max_retries: int = 5):
        self.max_retries = max_retries
        self.reset_time = None
        self.remaining = None
    
    async def wait_if_needed(self, response_headers: Dict[str, str]) -> None:
        self.remaining = int(response_headers.get('X-RateLimit-Remaining', 1))
        reset_timestamp = int(response_headers.get('X-RateLimit-Reset', 0))
        
        if self.remaining == 0 and reset_timestamp:
            wait_time = reset_timestamp - time.time() + 5
            if wait_time > 0:
                logger.warning(f"Rate limit reached. Waiting {wait_time:.0f} seconds...")
                await asyncio.sleep(wait_time)
    
    async def exponential_backoff(self, attempt: int) -> None:
        wait_time = min(2 ** attempt, 300)
        logger.warning(f"Backing off for {wait_time} seconds (attempt {attempt + 1}/{self.max_retries})")
        await asyncio.sleep(wait_time)

class ProgressTracker:
    def __init__(self, checkpoint_file: str = 'progress.json'):
        self.checkpoint_file = checkpoint_file
        self.processed: Set[str] = set()
        self.found_keys: List[Dict[str, Any]] = []
        self.seen_keys: Set[str] = set()
        self.load_progress()
    
    def load_progress(self) -> None:
        if Path(self.checkpoint_file).exists():
            try:
                with open(self.checkpoint_file, 'r') as f:
                    data = json.load(f)
                    self.processed = set(data.get('processed', []))
                    self.found_keys = data.get('found_keys', [])
                    # seen_keys in JSON can be list of strings (old) or list of dicts (new)
                    seen_data = data.get('seen_keys', [])
                    if seen_data and isinstance(seen_data[0], dict):
                         self.seen_keys = {item['key'] for item in seen_data}
                    else:
                        self.seen_keys = set(seen_data)
                logger.info(f"Resumed: {len(self.processed)} items processed, {len(self.found_keys)} keys found")
            except Exception as e:
                logger.error(f"Failed to load progress: {e}")
    
    def save_progress(self) -> None:
        try:
            # Create a map of key -> provider from found_keys
            key_provider_map = {item['key']: item['provider'] for item in self.found_keys}
            
            # Create structured seen_keys list
            structured_seen_keys = []
            for key in self.seen_keys:
                provider = key_provider_map.get(key, "Unknown")
                structured_seen_keys.append({"provider": provider, "key": key})
            
            with open(self.checkpoint_file, 'w') as f:
                json.dump({
                    'processed': list(self.processed),
                    'found_keys': self.found_keys,
                    'seen_keys': structured_seen_keys,
                    'timestamp': datetime.now().isoformat()
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save progress: {e}")
    
    def is_processed(self, identifier: str) -> bool:
        return identifier in self.processed
    
    def mark_processed(self, identifier: str) -> None:
        self.processed.add(identifier)
    
    def is_duplicate_key(self, key: str) -> bool:
        return key in self.seen_keys
    
    def add_key(self, key_data: Dict[str, Any]) -> None:
        key_value = key_data['key']
        if key_value not in self.seen_keys:
            self.seen_keys.add(key_value)
            self.found_keys.append(key_data)

class APIAuditor:
    def __init__(self, token: str, rate_limiter: RateLimiter, progress: ProgressTracker, args: argparse.Namespace):
        self.token = token
        self.rate_limiter = rate_limiter
        self.progress = progress
        self.args = args
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(headers={"Authorization": f"token {self.token}"})
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def request_with_retry(self, url: str, headers: Optional[Dict] = None) -> Optional[Dict[str, Any]]:
        for attempt in range(self.rate_limiter.max_retries):
            try:
                request_headers = {"Authorization": f"token {self.token}"}
                if headers:
                    request_headers.update(headers)
                
                async with self.session.get(url, headers=request_headers) as response:
                    await self.rate_limiter.wait_if_needed(response.headers)
                    
                    if response.status == 403:
                        logger.warning(f"Rate limit or auth failed for {url}")
                        await self.rate_limiter.exponential_backoff(attempt)
                        continue
                    elif response.status == 404:
                        logger.debug(f"Resource not found: {url}")
                        return None
                    
                    response.raise_for_status()
                    return await response.json()
            except aiohttp.ClientError as e:
                logger.error(f"Request error for {url}: {e}")
                if attempt < self.rate_limiter.max_retries - 1:
                    await self.rate_limiter.exponential_backoff(attempt)
                else:
                    return None
        return None
    
    async def search_github_code(self, query: str, page: int = 1) -> Optional[Dict[str, Any]]:
        encoded_q = quote_plus(query)
        sort_param = f"&sort={self.args.sort}&order=desc" if self.args.sort else ""
        url = f"https://api.github.com/search/code?q={encoded_q}&per_page=100&page={page}{sort_param}"
        return await self.request_with_retry(url)
    
    async def search_github_commits(self, query: str, page: int = 1) -> Optional[Dict[str, Any]]:
        encoded_q = quote_plus(query)
        sort_param = f"&sort={self.args.sort}&order=desc" if self.args.sort else ""
        url = f"https://api.github.com/search/commits?q={encoded_q}&per_page=100&page={page}{sort_param}"
        # Commit search historically requires preview header
        return await self.request_with_retry(url, headers={"Accept": "application/vnd.github.cloak-preview+json"})
    
    async def get_file_content(self, repo_full_name: str, path: str) -> Optional[str]:
        url = f"https://api.github.com/repos/{repo_full_name}/contents/{path}"
        data = await self.request_with_retry(url)
        if data and 'content' in data:
            try:
                return base64.b64decode(data['content']).decode('utf-8', errors='ignore')
            except Exception as e:
                logger.error(f"Failed to decode content from {repo_full_name}/{path}: {e}")
        return None
    
    def extract_keys(self, content: str, pattern: str) -> List[str]:
        return re.findall(pattern, content)
    
    async def validate_openai_key(self, key: str) -> bool:
        """Validate an OpenAI API key by making a test request."""
        try:
            timeout = getattr(self.args, 'timeout', DEFAULT_VALIDATION_TIMEOUT)
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {key}"},
                    timeout=aiohttp.ClientTimeout(total=timeout)
                ) as response:
                    return response.status == 200
        except Exception as e:
            logger.debug(f"OpenAI validation failed: {e}")
            return False
    
    async def validate_anthropic_key(self, key: str) -> bool:
        """Validate an Anthropic API key by making a test request."""
        try:
            timeout = getattr(self.args, 'timeout', DEFAULT_VALIDATION_TIMEOUT)
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://api.anthropic.com/v1/models",
                    headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
                    timeout=aiohttp.ClientTimeout(total=timeout)
                ) as response:
                    return response.status == 200
        except Exception as e:
            logger.debug(f"Anthropic validation failed: {e}")
            return False
    
    async def validate_google_key(self, key: str) -> Optional[bool]:
        """Validate a Google AI API key (no validation endpoint, returns None)."""
        # Google doesn't have a simple validation endpoint, mark as unknown
        return None
    
    async def batch_validate_keys(self, keys_data: List[Dict[str, Any]], provider: str) -> None:
        """Validate multiple API keys in batch."""
        validation_map = {
            "OpenAI": self.validate_openai_key,
            "Anthropic": self.validate_anthropic_key,
            "Google": self.validate_google_key,
        }
        
        validator = validation_map.get(provider)
        if not validator:
            logger.warning(f"No validator available for provider: {provider}")
            return
        
        tasks = []
        for key_data in keys_data:
            tasks.append(validator(key_data['key']))
        
        results = await asyncio.gather(*tasks)
        for key_data, valid in zip(keys_data, results):
            key_data['valid'] = valid
    
    def filter_repo(self, item: Dict[str, Any]) -> bool:
        repo = item.get('repository', {})
        
        if self.args.min_stars and repo.get('stargazers_count', 0) < self.args.min_stars:
            return False
        
        if self.args.language:
            repo_lang = repo.get('language', '').lower()
            if repo_lang != self.args.language.lower():
                return False
        
        if self.args.updated_after:
            updated_at = repo.get('updated_at', '')
            if updated_at < self.args.updated_after:
                return False
        
        return True
    
    def mask_key(self, key: str) -> str:
        """Mask a key for safe logging (e.g. sk-abc...1234)"""
        if len(key) <= 12:
            return "***"
        return f"{key[:8]}...{key[-4:]}"
    
    async def audit_api_keys(self, provider: str, query: str, pattern: str) -> None:
        logger.info(f"Auditing {provider} API keys...")
        all_items = []
        
        page = 1
        while True:
            results = await self.search_github_code(query, page)
            if not results or 'items' not in results:
                break
            
            items = results['items']
            if not items:
                break
            
            filtered_items = [item for item in items if self.filter_repo(item)]
            all_items.extend(filtered_items)
            
            logger.info(f"Fetched page {page}, got {len(filtered_items)} filtered items")
            
            if len(items) < 100:
                break
            
            page += 1
            
            if self.args.max_pages and page > self.args.max_pages:
                logger.info(f"Reached max pages limit: {self.args.max_pages}")
                break
        
        if not all_items:
            logger.info(f"No results found for {provider}.")
            return
        
        logger.info(f"Processing {len(all_items)} repositories for {provider}")
        
        keys_to_validate = []
        iterator = tqdm(all_items, desc=f"Auditing {provider}") if tqdm else all_items
        
        for item in iterator:
            repo = item['repository']['full_name']
            path = item['path']
            identifier = f"{repo}/{path}"
            
            if self.progress.is_processed(identifier):
                logger.debug(f"Skipping already processed: {identifier}")
                continue
            
            logger.info(f"Checking {identifier}...")
            content = await self.get_file_content(repo, path)
            
            if content:
                keys = self.extract_keys(content, pattern)
                for key in keys:
                    if not self.progress.is_duplicate_key(key):
                        key_data = {
                            'provider': provider,
                            'key': key,
                            'repo': repo,
                            'path': path,
                            'url': item.get('html_url') or f"https://github.com/{repo}/blob/{path}",
                            'timestamp': datetime.now().isoformat(),
                            'valid': None
                        }
                        self.progress.add_key(key_data)
                        keys_to_validate.append(key_data)
                        masked = self.mask_key(key)
                        logger.info(f"Found new {provider} key in {identifier}: {masked}")
                    else:
                        logger.debug(f"Skipping duplicate key in {identifier}")
            
            self.progress.mark_processed(identifier)
            
            if len(self.progress.processed) % 10 == 0:
                self.progress.save_progress()
        
        if self.args.validate and keys_to_validate:
            logger.info(f"Validating {len(keys_to_validate)} {provider} keys...")
            await self.batch_validate_keys(keys_to_validate, provider)
        
        self.progress.save_progress()
        logger.info(f"Completed {provider} audit: {len(self.progress.found_keys)} total unique keys found")
    
    async def audit_commit_messages(self, provider: str, query: str, pattern: str) -> None:
        logger.info(f"Auditing {provider} API keys in commit messages...")
        all_items = []
        
        page = 1
        while True:
            results = await self.search_github_commits(query, page)
            if not results or 'items' not in results:
                break
            
            items = results['items']
            if not items:
                break
            
            filtered_items = [item for item in items if self.filter_repo(item)]
            all_items.extend(filtered_items)
            
            logger.info(f"Fetched page {page}, got {len(filtered_items)} filtered commits")
            
            if len(items) < 100:
                break
            
            page += 1
            
            if self.args.max_pages and page > self.args.max_pages:
                logger.info(f"Reached max pages limit: {self.args.max_pages}")
                break
        
        if not all_items:
            logger.info(f"No results found for {provider}.")
            return
        
        logger.info(f"Processing {len(all_items)} commits for {provider}")
        
        keys_to_validate = []
        iterator = tqdm(all_items, desc=f"Auditing {provider} commits") if tqdm else all_items
        
        for item in iterator:
            repo = item['repository']['full_name']
            commit_sha = item['sha']
            message = item['commit']['message']
            identifier = f"{repo}/commit/{commit_sha}"
            
            if self.progress.is_processed(identifier):
                logger.debug(f"Skipping already processed: {identifier}")
                continue
            
            logger.info(f"Checking {identifier}...")
            keys = self.extract_keys(message, pattern)
            
            for key in keys:
                if not self.progress.is_duplicate_key(key):
                    key_data = {
                        'provider': provider,
                        'key': key,
                        'repo': repo,
                        'commit': commit_sha,
                        'url': item.get('html_url') or f"https://github.com/{repo}/commit/{commit_sha}",
                        'message': message[:100],
                        'timestamp': datetime.now().isoformat(),
                        'valid': None
                    }
                    self.progress.add_key(key_data)
                    keys_to_validate.append(key_data)
                    masked = self.mask_key(key)
                    logger.info(f"Found new {provider} key in {identifier}: {masked}")
                else:
                    logger.debug(f"Skipping duplicate key in {identifier}")
            
            self.progress.mark_processed(identifier)
            
            if len(self.progress.processed) % 10 == 0:
                self.progress.save_progress()
        
        if self.args.validate and keys_to_validate:
            logger.info(f"Validating {len(keys_to_validate)} {provider} keys...")
            await self.batch_validate_keys(keys_to_validate, provider)
        
        self.progress.save_progress()
        logger.info(f"Completed {provider} commits audit: {len(self.progress.found_keys)} total unique keys found")

def export_results(progress: ProgressTracker, output_format: str, output_file: str) -> None:
    if not progress.found_keys:
        logger.info("No keys found to export")
        return
    
    if output_format == 'json':
        with open(output_file, 'w') as f:
            json.dump({
                'total_keys': len(progress.found_keys),
                'scan_date': datetime.now().isoformat(),
                'keys': progress.found_keys
            }, f, indent=2)
        logger.info(f"Results exported to {output_file}")
    
    elif output_format == 'csv':
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            if progress.found_keys:
                fieldnames = progress.found_keys[0].keys()
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(progress.found_keys)
        logger.info(f"Results exported to {output_file}")
    
    elif output_format == 'txt':
        with open(output_file, 'w') as f:
            for key_data in progress.found_keys:
                f.write(f"{key_data['provider']}: {key_data.get('repo', 'N/A')}\n")
                f.write(f"  Key: {key_data['key']}\n")
                if key_data.get('valid') is not None:
                    f.write(f"  Valid: {key_data['valid']}\n")
                f.write(f"  URL: {key_data.get('url', 'N/A')}\n")
                f.write(f"  Timestamp: {key_data['timestamp']}\n\n")
        logger.info(f"Results exported to {output_file}")

def get_github_token() -> str:
    """Retrieve GitHub token from environment or prompt user."""
    token = os.getenv('GITHUB_TOKEN')
    if token:
        return token
    return input("Enter your GitHub token: ").strip()

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='GitHub API Key Auditor with advanced features')
    
    parser.add_argument('--repo', type=str, default='', help='Specific repository to search (format: owner/repo)')
    parser.add_argument('--extensions', type=str, default='', help='File extensions to search (comma-separated, e.g., py,js,env)')
    parser.add_argument('--mode', type=str, choices=['code', 'commits'], default='code', help='Search mode: code or commits')
    parser.add_argument('--validate', action='store_true', help='Validate found API keys')
    parser.add_argument('--output-format', type=str, choices=['json', 'csv', 'txt'], default='json', help='Output format for results')
    parser.add_argument('--output-file', type=str, default='audit_results.json', help='Output file path')
    parser.add_argument('--max-pages', type=int, help='Maximum number of pages to fetch from GitHub API')
    parser.add_argument('--min-stars', type=int, help='Minimum number of stars for repositories')
    parser.add_argument('--language', type=str, help='Filter by programming language')
    parser.add_argument('--updated-after', type=str, help='Filter repositories updated after date (ISO format: YYYY-MM-DD)')
    parser.add_argument('--sort', type=str, choices=['indexed', ''], default='indexed', help='Sort by ("indexed" for recent, "" for best match)')
    parser.add_argument('--resume', action='store_true', help='Resume from previous progress')
    parser.add_argument('--checkpoint-file', type=str, default='progress.json', help='Checkpoint file for resume functionality')
    parser.add_argument('--timeout', type=int, default=DEFAULT_VALIDATION_TIMEOUT, help='Timeout for API validation requests in seconds')
    parser.add_argument('--providers', type=str, default='openai,anthropic', 
                        help='Comma-separated list of providers to scan (openai,anthropic,google)')
    
    return parser.parse_args()

async def main():
    args = parse_args()
    
    logger.info("="*60)
    logger.info("GitHub API Key Auditor - Enhanced Version")
    logger.info("="*60)
    logger.info(f"Configuration:")
    logger.info(f"  Mode: {args.mode}")
    logger.info(f"  Repository: {args.repo or 'All (global search)'}")
    logger.info(f"  Extensions: {args.extensions or 'All'}")
    logger.info(f"  Validate: {args.validate}")
    logger.info(f"  Output format: {args.output_format}")
    logger.info(f"  Output file: {args.output_file}")
    logger.info(f"  Resume: {args.resume}")
    if args.min_stars:
        logger.info(f"  Min stars: {args.min_stars}")
    if args.language:
        logger.info(f"  Language: {args.language}")
    if args.updated_after:
        logger.info(f"  Updated after: {args.updated_after}")
    logger.info("="*60)
    
    try:
        token = get_github_token()
        rate_limiter = RateLimiter()
        
        if not args.resume:
            if Path(args.checkpoint_file).exists():
                logger.warning(f"Removing existing checkpoint file: {args.checkpoint_file}")
                Path(args.checkpoint_file).unlink()
        
        progress = ProgressTracker(args.checkpoint_file)
        
        query_suffix = f" repo:{args.repo}" if args.repo else ""
        
        if args.mode == "code" and args.extensions:
            for ext in args.extensions.split(','):
                ext = ext.strip().lstrip('.')
                query_suffix += f" extension:{ext}"
        
        # Provider configuration: (name, search_query, pattern)
        provider_configs = {
            'anthropic': ("Anthropic", "sk-ant-", ANTHROPIC_KEY_PATTERN),
            'openai': ("OpenAI", "sk-", OPENAI_KEY_PATTERN),
            'google': ("Google", "AIza", GOOGLE_AI_KEY_PATTERN),
        }
        
        # Parse selected providers
        selected_providers = [p.strip().lower() for p in args.providers.split(',')]
        
        async with APIAuditor(token, rate_limiter, progress, args) as auditor:
            for provider_key in selected_providers:
                if provider_key not in provider_configs:
                    logger.warning(f"Unknown provider: {provider_key}, skipping...")
                    continue
                
                name, search_term, pattern = provider_configs[provider_key]
                query = f"{search_term}{query_suffix}"
                
                if args.mode == "commits":
                    await auditor.audit_commit_messages(name, query, pattern)
                else:
                    await auditor.audit_api_keys(name, query, pattern)
        
        export_results(progress, args.output_format, args.output_file)
        
        logger.info("="*60)
        logger.info(f"Audit complete!")
        logger.info(f"Total unique keys found: {len(progress.found_keys)}")
        logger.info(f"Results saved to: {args.output_file}")
        logger.info(f"Progress saved to: {args.checkpoint_file}")
        logger.info("Remember to report any found keys to the respective providers for revocation.")
        logger.info("="*60)
        
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)

if __name__ == "__main__":
    asyncio.run(main())
