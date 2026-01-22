"""
Unit tests for API key pattern matching in github_api_key_auditor.py
"""
import re
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auditor import (
    ANTHROPIC_KEY_PATTERN,
    OPENAI_KEY_PATTERN,
    GOOGLE_AI_KEY_PATTERN,
)


class TestAnthropicKeyPattern:
    """Tests for Anthropic API key pattern."""
    
    def test_valid_anthropic_key(self):
        """Should match valid Anthropic keys."""
        valid_keys = [
            "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNO",
        ]
        for key in valid_keys:
            matches = re.findall(ANTHROPIC_KEY_PATTERN, key)
            assert len(matches) == 1, f"Failed to match: {key}"
    
    def test_invalid_anthropic_key(self):
        """Should not match invalid keys."""
        invalid_keys = [
            "sk-ant-short",  # Too short
            "sk-ant",        # Way too short
            "random-string",
        ]
        for key in invalid_keys:
            matches = re.findall(ANTHROPIC_KEY_PATTERN, key)
            assert len(matches) == 0, f"Should not match: {key}"


class TestOpenAIKeyPattern:
    """Tests for OpenAI API key pattern."""
    
    def test_valid_openai_classic_key(self):
        """Should match classic sk-<48 chars> format."""
        key = "sk-" + "a" * 48
        matches = re.findall(OPENAI_KEY_PATTERN, key)
        assert len(matches) == 1
    
    def test_valid_openai_proj_key(self):
        """Should match sk-proj-* format."""
        key = "sk-proj-abcdefghijklmnopqrstuvwxyz"
        matches = re.findall(OPENAI_KEY_PATTERN, key)
        assert len(matches) == 1
    
    def test_valid_openai_live_key(self):
        """Should match sk-live-* format."""
        key = "sk-live-abcdefghijklmnopqrstuvwxyz"
        matches = re.findall(OPENAI_KEY_PATTERN, key)
        assert len(matches) == 1
    
    def test_invalid_openai_key(self):
        """Should not match invalid keys."""
        invalid_keys = [
            "sk-short",      # Too short
            "not-a-key",
        ]
        for key in invalid_keys:
            matches = re.findall(OPENAI_KEY_PATTERN, key)
            assert len(matches) == 0, f"Should not match: {key}"


class TestGoogleAIKeyPattern:
    """Tests for Google AI API key pattern."""
    
    def test_valid_google_key(self):
        """Should match AIza* format."""
        key = "AIza" + "a" * 35
        matches = re.findall(GOOGLE_AI_KEY_PATTERN, key)
        assert len(matches) == 1
    
    def test_invalid_google_key(self):
        """Should not match invalid keys."""
        invalid_keys = [
            "AIza-short",    # Too short
            "AIZA" + "a" * 35,  # Wrong case for prefix
        ]
        for key in invalid_keys:
            matches = re.findall(GOOGLE_AI_KEY_PATTERN, key)
            assert len(matches) == 0, f"Should not match: {key}"


def run_tests():
    """Simple test runner."""
    test_classes = [
        TestAnthropicKeyPattern,
        TestOpenAIKeyPattern,
        TestGoogleAIKeyPattern,
    ]
    
    passed = 0
    failed = 0
    
    for test_class in test_classes:
        print(f"\n{test_class.__name__}")
        print("-" * 40)
        
        instance = test_class()
        for method_name in dir(instance):
            if method_name.startswith("test_"):
                try:
                    getattr(instance, method_name)()
                    print(f"  PASS: {method_name}")
                    passed += 1
                except AssertionError as e:
                    print(f"  FAIL: {method_name} - {e}")
                    failed += 1
                except Exception as e:
                    print(f"  ERROR: {method_name} - {e}")
                    failed += 1
    
    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
