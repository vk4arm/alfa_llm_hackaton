"""
Zero-PII Vault Configuration Loader.

Loads masking rules, regex patterns, verb stopwords, and famous personality
lexicons from external YAML configuration files, eliminating hardcoded constants
from the codebase and allowing dynamic runtime reconfiguration.
"""

import os
import re
from dataclasses import dataclass, field
from typing import Dict, Set, Pattern, Optional, Any
import yaml

@dataclass
class VaultConfig:
    """
    Immutable runtime configuration container for the Zero-PII Vault.
    Holds pre-compiled regular expressions, entity dictionaries, and operational parameters.
    """
    # Raw string patterns from YAML
    patterns: Dict[str, str]
    
    # Pre-compiled regex patterns for high-speed sub-millisecond matching
    compiled_patterns: Dict[str, Pattern] = field(default_factory=dict)
    
    # Context classification patterns
    metaphor_pattern: Optional[Pattern] = None
    banking_intent_pattern: Optional[Pattern] = None
    
    # Filtering dictionaries
    verb_stopwords: Set[str] = field(default_factory=set)
    famous_person_bases: Set[str] = field(default_factory=set)
    famous_persons: Set[str] = field(default_factory=set)
    
    # General vault settings
    granular_address: bool = False
    context_window_chars: int = 80

    def get_pattern(self, name: str) -> Pattern:
        """Retrieves a pre-compiled regular expression by its configuration name."""
        if name not in self.compiled_patterns:
            raise KeyError(f"Pattern '{name}' is not configured in rules.yaml")
        return self.compiled_patterns[name]

_CACHED_CONFIG: Optional[VaultConfig] = None

def get_default_config_dir() -> str:
    """
    Resolves the configuration directory location using hierarchical lookup:
    1. ZERO_PII_CONFIG_DIR environment variable.
    2. Relative path to sibling 'config' folder (services/zero-pii-vault/config).
    3. Current working directory fallback paths.
    """
    env_path = os.getenv("ZERO_PII_CONFIG_DIR")
    if env_path and os.path.isdir(env_path):
        return env_path
    
    # Standard package structure: ../config from src/
    candidate1 = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config"))
    if os.path.isdir(candidate1):
        return candidate1
        
    candidate2 = os.path.abspath("services/zero-pii-vault/config")
    if os.path.isdir(candidate2):
        return candidate2
        
    candidate3 = os.path.abspath("config")
    if os.path.isdir(candidate3):
        return candidate3
        
    return candidate1

def load_vault_config(config_dir: Optional[str] = None, force_reload: bool = False) -> VaultConfig:
    """
    Loads and compiles Zero-PII Vault configuration from rules.yaml and famous_persons.yaml.
    Results are cached in memory for zero-overhead re-use across masking instances and threads.
    
    :param config_dir: Optional custom path to configuration folder.
    :param force_reload: If True, bypasses in-memory cache and reloads from disk.
    :return: Fully initialized VaultConfig instance with pre-compiled regexes.
    """
    global _CACHED_CONFIG
    if _CACHED_CONFIG is not None and not force_reload and config_dir is None:
        return _CACHED_CONFIG

    target_dir = config_dir or get_default_config_dir()
    rules_path = os.path.join(target_dir, "rules.yaml")
    famous_path = os.path.join(target_dir, "famous_persons.yaml")

    if not os.path.isfile(rules_path):
        raise FileNotFoundError(f"Configuration file not found: {rules_path}")
    if not os.path.isfile(famous_path):
        raise FileNotFoundError(f"Configuration file not found: {famous_path}")

    # Load YAML definitions
    with open(rules_path, "r", encoding="utf-8") as f:
        rules_data = yaml.safe_load(f) or {}

    with open(famous_path, "r", encoding="utf-8") as f:
        famous_data = yaml.safe_load(f) or {}

    # Extract raw patterns and settings
    raw_patterns: Dict[str, str] = rules_data.get("patterns", {})
    settings: Dict[str, Any] = rules_data.get("settings", {})
    raw_metaphor = rules_data.get("metaphor", "")
    raw_banking = rules_data.get("banking_intent", "")
    
    verb_stopwords = set(s.lower().strip() for s in rules_data.get("verb_stopwords", []))
    famous_bases = set(b.lower().strip() for b in famous_data.get("bases", []))
    famous_exact = set(e.lower().strip() for e in famous_data.get("exact_names", []))

    # Pre-compile all regexes for performance
    compiled_patterns: Dict[str, Pattern] = {}
    for name, pat_str in raw_patterns.items():
        try:
            compiled_patterns[name] = re.compile(pat_str)
        except re.error as err:
            raise ValueError(f"Failed to compile pattern '{name}': {err}")

    metaphor_pattern = re.compile(raw_metaphor) if raw_metaphor else None
    banking_intent_pattern = re.compile(raw_banking) if raw_banking else None

    config = VaultConfig(
        patterns=raw_patterns,
        compiled_patterns=compiled_patterns,
        metaphor_pattern=metaphor_pattern,
        banking_intent_pattern=banking_intent_pattern,
        verb_stopwords=verb_stopwords,
        famous_person_bases=famous_bases,
        famous_persons=famous_exact,
        granular_address=settings.get("granular_address", False),
        context_window_chars=settings.get("context_window_chars", 80)
    )

    if config_dir is None:
        _CACHED_CONFIG = config

    return config
