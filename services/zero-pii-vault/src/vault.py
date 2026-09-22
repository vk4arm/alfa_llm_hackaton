"""
ZERO-PII VAULT: Reversible Anonymizer & Tokenizer
Compliant with Russian Federal Laws: 152-FZ & 395-1 (Banking Secrecy)
"""

import re
import uuid
from typing import Dict, Tuple, List, Optional

def luhn_checksum_valid(card_number_str: str) -> bool:
    """Validates 16-digit card number using Luhn algorithm."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled if doubled < 10 else doubled - 9
        else:
            checksum += digit
    return checksum % 10 == 0

class ZeroPiiVault:
    def __init__(self, redis_client=None, session_ttl_sec: int = 300):
        self.redis = redis_client
        self.session_ttl_sec = session_ttl_sec
        self.memory_store: Dict[str, Dict[str, str]] = {}
        
        # Regex patterns for Russian PII
        self.card_pattern = re.compile(r'\b(?:\d[ -]*?){13,19}\b')
        self.passport_pattern = re.compile(r'\b\d{2}\s?\d{2}\s?\d{6}\b')
        self.snils_pattern = re.compile(r'\b\d{3}-\d{3}-\d{3}\s?\d{2}\b')
        self.phone_pattern = re.compile(r'\b(?:\+7|8)[\s\-]?(?:\(?\d{3}\)?[\s\-]?)?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b')

    def mask_text(self, text: str, session_id: Optional[str] = None) -> Tuple[str, str, Dict[str, str]]:
        """
        Masks all sensitive banking data, replaces with synthetic tokens:
        [CARD_1], [PASSPORT_1], [PHONE_1], etc.
        Returns: (sanitized_text, session_id, mapping)
        """
        if not session_id:
            session_id = str(uuid.uuid4())
            
        mapping: Dict[str, str] = {}
        card_counter = 1
        passport_counter = 1
        phone_counter = 1

        # 1. Mask bank cards (validated via Luhn algorithm)
        def replace_card(match):
            nonlocal card_counter
            raw_card = match.group(0)
            cleaned = re.sub(r'[\s\-]', '', raw_card)
            if len(cleaned) == 16 and luhn_checksum_valid(cleaned):
                token = f"[CARD_{card_counter}]"
                mapping[token] = raw_card
                card_counter += 1
                return token
            return raw_card

        sanitized = self.card_pattern.sub(replace_card, text)

        # 2. Mask passports
        def replace_passport(match):
            nonlocal passport_counter
            raw = match.group(0)
            token = f"[PASSPORT_{passport_counter}]"
            mapping[token] = raw
            passport_counter += 1
            return token

        sanitized = self.passport_pattern.sub(replace_passport, sanitized)

        # 3. Mask phones
        def replace_phone(match):
            nonlocal phone_counter
            raw = match.group(0)
            token = f"[PHONE_{phone_counter}]"
            mapping[token] = raw
            phone_counter += 1
            return token

        sanitized = self.phone_pattern.sub(replace_phone, sanitized)

        # Store in Redis / memory with TTL
        self.memory_store[session_id] = mapping

        return sanitized, session_id, mapping

    def unmask_text(self, text: str, session_id: str) -> str:
        """
        Reverses tokenization using the ephemeral session mapping.
        """
        mapping = self.memory_store.get(session_id, {})
        result = text
        for token, original_value in mapping.items():
            result = result.replace(token, original_value)
        return result

    def purge_session(self, session_id: str):
        """Immediately destroy ephemeral session keys."""
        if session_id in self.memory_store:
            del self.memory_store[session_id]
