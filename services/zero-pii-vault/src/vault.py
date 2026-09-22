"""
ZERO-PII VAULT: Reversible Anonymizer & Tokenizer Service
Compliant with Russian Federal Laws: 152-FZ & 395-1 (Banking Secrecy).

Integrates high-speed algorithmic validators and Natasha NER for complete
Russian personal identifiable information (PII) detection and redaction.
"""

import os
import uuid
from typing import Dict, Tuple, List, Optional
try:
    from .masker import NatashaPIIMasker, luhn_checksum_valid, validate_inn
except ImportError:
    from masker import NatashaPIIMasker, luhn_checksum_valid, validate_inn

class ZeroPiiVault:
    def __init__(self, redis_client=None, session_ttl_sec: int = 300, granular_address: bool = False):
        self.redis = redis_client
        self.session_ttl_sec = session_ttl_sec
        self.memory_store: Dict[str, Dict[str, str]] = {}
        self.masker = NatashaPIIMasker(granular_address=granular_address)

    def mask_text(self, text: str, session_id: Optional[str] = None) -> Tuple[str, str, Dict[str, str]]:
        """
        Masks all sensitive banking & personal data across 16 categories.
        Replaces detected spans with reversible synthetic tokens.
        Returns: (sanitized_text, session_id, mapping)
        """
        masked_text, session_id, mapping = self.masker.mask(text, session_id=session_id)
        
        # Store in Redis or in-memory store
        if self.redis:
            try:
                import json
                self.redis.setex(f"pii_session:{session_id}", self.session_ttl_sec, json.dumps(mapping))
            except Exception:
                self.memory_store[session_id] = mapping
        else:
            self.memory_store[session_id] = mapping

        return masked_text, session_id, mapping

    def unmask_text(self, text: str, session_id: str) -> str:
        """
        Reverses tokenization using the ephemeral session mapping.
        """
        mapping = {}
        if self.redis:
            try:
                import json
                raw = self.redis.get(f"pii_session:{session_id}")
                if raw:
                    mapping = json.loads(raw)
            except Exception:
                mapping = self.memory_store.get(session_id, {})
        else:
            mapping = self.memory_store.get(session_id, {})

        return self.masker.unmask(text, mapping)

    def purge_session(self, session_id: str):
        """Immediately destroy ephemeral session keys."""
        if self.redis:
            try:
                self.redis.delete(f"pii_session:{session_id}")
            except Exception:
                pass
        if session_id in self.memory_store:
            del self.memory_store[session_id]
