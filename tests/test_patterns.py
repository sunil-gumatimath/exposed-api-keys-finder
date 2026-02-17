import argparse
import re

from auditor import (
    ANTHROPIC_KEY_PATTERN,
    APIAuditor,
    GOOGLE_AI_KEY_PATTERN,
    OPENAI_KEY_PATTERN,
    ProgressTracker,
    RateLimiter,
    fingerprint_key,
    mask_key,
)


def _build_args(**overrides):
    base = {
        "max_concurrency": 2,
        "allow_patterns": [],
        "deny_patterns": [],
        "since_checkpoint": False,
        "sort": "indexed",
        "min_stars": None,
        "language": None,
        "updated_after": None,
        "max_pages": 1,
        "dry_run": True,
        "validate": False,
        "store_raw_keys": False,
        "checkpoint_interval": 5,
        "timeout": 5,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def test_valid_anthropic_key():
    key = "sk-ant-api03-" + "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNO"
    matches = re.findall(ANTHROPIC_KEY_PATTERN, key)
    assert len(matches) == 1


def test_invalid_anthropic_key():
    invalid_keys = [
        "sk-ant-short",
        "sk-ant",
        "random-string",
    ]
    for key in invalid_keys:
        matches = re.findall(ANTHROPIC_KEY_PATTERN, key)
        assert len(matches) == 0


def test_valid_openai_formats():
    classic = "sk-" + "a" * 48
    proj = "sk-proj-abcdefghijklmnopqrstuvwxyz"
    live = "sk-live-abcdefghijklmnopqrstuvwxyz"
    assert len(re.findall(OPENAI_KEY_PATTERN, classic)) == 1
    assert len(re.findall(OPENAI_KEY_PATTERN, proj)) == 1
    assert len(re.findall(OPENAI_KEY_PATTERN, live)) == 1


def test_invalid_openai_key():
    invalid_keys = ["sk-short", "not-a-key"]
    for key in invalid_keys:
        assert len(re.findall(OPENAI_KEY_PATTERN, key)) == 0


def test_valid_google_key():
    key = "AIza" + "a" * 35
    assert len(re.findall(GOOGLE_AI_KEY_PATTERN, key)) == 1


def test_mask_and_fingerprint():
    key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
    masked = mask_key(key)
    assert masked.startswith("sk-proj-")
    assert masked.endswith("3456")
    fp = fingerprint_key(key)
    assert len(fp) == 64


def test_noise_filter_rejects_placeholder_context(tmp_path):
    args = _build_args()
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)
    key = "sk-" + "a" * 48
    context = f"OPENAI_API_KEY={key} # example placeholder"
    assert auditor.is_probable_secret(key, context) is False


def test_allow_pattern_overrides_noise(tmp_path):
    args = _build_args(allow_patterns=[r"OPENAI_API_KEY"], deny_patterns=[])
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)
    key = "sk-" + "a" * 48
    context = f"OPENAI_API_KEY={key} # example placeholder"
    assert auditor.is_probable_secret(key, context) is True


def test_deny_pattern_blocks(tmp_path):
    args = _build_args(deny_patterns=[r"DO_NOT_USE"])
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)
    key = "sk-" + "A1" * 24
    context = f"DO_NOT_USE={key}"
    assert auditor.is_probable_secret(key, context) is False
