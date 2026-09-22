"""
Zero-PII Vault: Natasha-powered Neural & Algorithmic Masker
Compliant with Russian Federal Laws: 152-FZ (Personal Data) & 395-1 (Banking Secrecy).

Supported entities:
1.  ФИО (Full Name, declension & inflections handled via Slovnet/Natasha PER NER)
2.  Дата рождения (Birth Date)
3.  Место рождения (Place of Birth)
4.  Серия и номер паспорта РФ (Passport Series & Number)
5.  Гражданство (Citizenship)
6.  Орган, выдавший паспорт (Issuing Authority)
7.  Код подразделения (Department Code)
8.  Дата выдачи паспорта (Passport Issue Date)
9.  Серия и номер водительского удостоверения (Driver's License)
10. Адрес (Country, postal code, city, street, house, apartment)
11. Email
12. Номер телефона (Russian mobile & landline phones)
13. ИНН (10-digit legal & 12-digit individual with FNS checksum validation)
14. Номер банковской карты (16 digits with Luhn algorithm validation)
15. CVV / CVC код карты (Security code)
16. Пин-код карты (PIN code)
17. Имя держателя карты (Cardholder name)
"""

import re
import uuid
from typing import Dict, Tuple, List, Optional, Any
from natasha import (
    Segmenter,
    MorphVocab,
    NewsEmbedding,
    NewsNERTagger,
    AddrExtractor,
    Doc
)

def luhn_checksum_valid(card_number_str: str) -> bool:
    """Validates 13-19 digit card number using Luhn algorithm."""
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

def validate_inn(inn: str) -> bool:
    """Validates Russian Tax Identification Number (ИНН) with official check digits."""
    digits = [int(c) for c in inn if c.isdigit()]
    if len(digits) == 10:
        weights = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum = sum(w * d for w, d in zip(weights, digits[:9])) % 11 % 10
        return checksum == digits[9]
    elif len(digits) == 12:
        weights1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum1 = sum(w * d for w, d in zip(weights1, digits[:10])) % 11 % 10
        weights2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum2 = sum(w * d for w, d in zip(weights2, digits[:11])) % 11 % 10
        return checksum1 == digits[10] and checksum2 == digits[11]
    return False

class NatashaPIIMasker:
    """
    High-speed, lightweight PII anonymizer and reversible tokenizer.
    Combines rule-based validators (Luhn, FNS checksums, RFC regexes) with
    Natasha (Slovnet compact embeddings + Yargy grammars) for morphological NER.
    """
    def __init__(self, granular_address: bool = False):
        self.granular_address = granular_address
        
        # Initialize lightweight NLP engines
        self.segmenter = Segmenter()
        self.morph_vocab = MorphVocab()
        self.emb = NewsEmbedding()
        self.ner_tagger = NewsNERTagger(self.emb)
        self.addr_extractor = AddrExtractor(self.morph_vocab)
        
        # 1. Financial & Account Identifiers
        self.card_pattern = re.compile(r'\b(?:\d[ -]*?){13,19}\b')
        self.inn_pattern = re.compile(r'\b\d{10}\b|\b\d{12}\b')
        self.cvv_pattern = re.compile(
            r'(?i)(?:\b(?:cvv2?|cvc2?|cid|код\s+безопасности|код\s+на\s+обороте)\b[^\d\n]{1,6})(\d{3,4})\b'
        )
        self.pin_pattern = re.compile(
            r'(?i)(?:\b(?:пин(?:-?код)?|pin(?:-?code)?)\b[^\d\n]{0,10}?[(\[\s]*?)(\d{4})(?=[)\]\s,.;\n]|$)'
        )
        self.cardholder_pattern = re.compile(
            r'(?i)(?:\b(?:держатель(?:\s+карты)?|cardholder(?:\s+name)?|card\s*holder|на\s+карте\s+указано\s+имя)\b\s*[:\-–—]?\s*)([A-Z\s]{3,35}|[А-ЯЁ\s]{3,35})(?=[,\n\.;\)]|$)'
        )
        
        # 2. Government IDs & Documents
        self.vu_pattern = re.compile(
            r'(?i)(?:\b(?:водительск(?:ое|их)?\s+(?:удостоверени[ея]|прав[ао]?)|в/?у)\b[^\d\n]{0,10}?)([0-9]{2}\s?[0-9А-ЯA-Z]{2}\s?[0-9]{6})\b'
        )
        self.pass_code_pattern = re.compile(
            r'(?i)(?:\b(?:код(?:\s+подразделения)?|подразделение|к/п)\b\s*[:\-–—]?\s*)(\b\d{3}[-\s]\d{3}\b)'
        )
        self.pass_pattern = re.compile(
            r'(?i)(?:(?:\b(?:паспорт(?:ные\s+данные|а|\s+РФ)?|реквизиты\s+паспорта)\b\s*[:\-–—]?\s*)?(?:серия\s*)?(\b\d{2}\s?\d{2}\b)\s*(?:№|номер)?\s*(\b\d{6}\b))'
        )
        self.issuer_pattern = re.compile(
            r'(?i)(?:\b(?:кем\s+выдан|орган[,\s]+выдавший\s+(?:документ|паспорт)|орган\s+выдачи|выдан(?:\s+паспорт)?)\b\s*[:\-–—]?\s*)([^\n,;]+?(?:отделом|уфмс|мвд|овд|ровд|гу\s+мвд|тп\s+№|отделением|паспортным|умвд)[^\n,;]+)'
        )
        self.pass_date_pattern = re.compile(
            r'(?i)(?:\b(?:дата\s+выдачи(?:\s+паспорта)?|выдан(?:\s+паспорт)?(?:\s+от)?)\b\s*[:\-–—]?\s*)(\d{2}[./]\d{2}[./]\d{4})'
        )
        self.citizen_pattern = re.compile(
            r'(?i)(?:\b(?:гражданство|гражданин|гражданка|подданство)\b\s*[:\-–—]?\s*)(РФ|Российская Федерация|Россия|Республика\s+[А-Яа-яЁё]+|[А-Яа-яЁё\-]{3,20})\b'
        )
        
        # 3. Biographic & Personal Data
        self.birth_date_pattern = re.compile(
            r'(?i)(?:\b(?:дата(?:\s+и\s+место)?\s+рождения|д\.?р\.?|родил(?:ся|ась)|г\.?р\.?)\b\s*(?:заявителя)?\s*[:\-–—]?\s*)(\d{2}[./]\d{2}[./]\d{4})'
        )
        self.birth_place_pattern = re.compile(
            r'(?i)(?:\b(?:место\s+рождения|уроженец|уроженка)\s*[:\-–—]?\s*|(?:дата\s+и\s+место\s+рождения[^\n,]+,\s*))([^\n,;\.]+(?:г\.|гор\.|город|село|с\.|пос\.|деревня|д\.)?[^\n,;\.\)]+)'
        )
        
        # 4. Contacts & Location
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
        self.phone_pattern = re.compile(r'(?:\+7|8)[\s\-]?(?:\(?\d{3}\)?[\s\-]?)?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b')
        self.address_line_pattern = re.compile(
            r'(?i)(?:\b(?:адрес(?:\s+постоянной|\s+фактической|\s+временной)?\s+(?:регистрации|проживания)|зарегистрирован\s+по\s+адресу|проживает\s+по\s+адресу)\b\s*[:\-–—]?\s*)(Россия[^\n]+|г\.[^\n]+|[0-9]{6},[^\n]+)'
        )

    def mask(self, text: str, session_id: Optional[str] = None) -> Tuple[str, str, Dict[str, str]]:
        """
        Masks all identified PII entities, returning:
        (sanitized_text, session_id, mapping_dict)
        """
        if not session_id:
            session_id = str(uuid.uuid4())
            
        spans: List[Tuple[int, int, str, str]] = [] # (start, end, label, raw_text)
        
        def is_overlapping(start: int, end: int) -> bool:
            return any(not (end <= s or start >= e) for s, e, _, _ in spans)
            
        def add_span(start: int, end: int, label: str, val: str):
            if not is_overlapping(start, end):
                spans.append((start, end, label, val))

        # 1. Driver's License
        for m in self.vu_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'DRIVER_LICENSE', m.group(1))

        # 2. Bank Cards (Luhn validated)
        for m in self.card_pattern.finditer(text):
            raw = m.group(0)
            cleaned = re.sub(r'[\s\-]', '', raw)
            if len(cleaned) == 16 and luhn_checksum_valid(cleaned):
                add_span(m.start(), m.end(), 'CARD', raw)

        # 3. Passport code
        for m in self.pass_code_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'PASSPORT_CODE', m.group(1))

        # 4. Passport series & number
        for m in self.pass_pattern.finditer(text):
            add_span(m.start(), m.end(), 'PASSPORT', m.group(0))

        # 5. INN (Checksum validated)
        for m in self.inn_pattern.finditer(text):
            val = m.group(0)
            if validate_inn(val):
                add_span(m.start(), m.end(), 'INN', val)

        # 6. Email
        for m in self.email_pattern.finditer(text):
            add_span(m.start(), m.end(), 'EMAIL', m.group(0))

        # 7. Phone
        for m in self.phone_pattern.finditer(text):
            add_span(m.start(), m.end(), 'PHONE', m.group(0))

        # 8. CVV
        for m in self.cvv_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'CVV', m.group(1))

        # 9. PIN
        for m in self.pin_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'PIN', m.group(1))

        # 10. Cardholder
        for m in self.cardholder_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'CARDHOLDER', m.group(1).strip())

        # 11. Birth date
        for m in self.birth_date_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'BIRTHDATE', m.group(1))

        # 12. Passport issue date
        for m in self.pass_date_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'PASSPORT_DATE', m.group(1))

        # 13. Birth place
        for m in self.birth_place_pattern.finditer(text):
            val = m.group(1).strip()
            add_span(m.start(1), m.end(1), 'BIRTHPLACE', val)

        # 14. Citizenship
        for m in self.citizen_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'CITIZENSHIP', m.group(1).strip())

        # 15. Passport issuer
        for m in self.issuer_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'PASSPORT_ISSUER', m.group(1).strip())

        # 16. Address (Full line or granular breakdown)
        if not self.granular_address:
            for m in self.address_line_pattern.finditer(text):
                add_span(m.start(1), m.end(1), 'ADDRESS', m.group(1).strip())
        else:
            for m in self.addr_extractor(text):
                t_label = m.fact.type or 'addr_part'
                tag = {
                    'страна': 'COUNTRY',
                    'индекс': 'POSTCODE',
                    'город': 'CITY',
                    'улица': 'STREET',
                    'дом': 'HOUSE',
                    'квартира': 'FLAT'
                }.get(t_label, 'ADDRESS_PART')
                add_span(m.start, m.stop, tag, text[m.start:m.stop])

        # 17. Natasha NER for ФИО (PER)
        doc = Doc(text)
        doc.segment(self.segmenter)
        doc.tag_ner(self.ner_tagger)
        for s in doc.spans:
            if s.type == 'PER':
                raw_name = s.text.strip()
                st = s.start
                en = s.stop
                # Strip leading prefix if bound to intro particle
                if raw_name.startswith('Я, '):
                    raw_name = raw_name[3:].strip()
                    st += 3
                # Multi-word person name (e.g. Иванов Иван, Петров А. В.)
                if len(raw_name.split()) >= 2:
                    add_span(st, en, 'FIO', raw_name)

        # Sort spans by start position ascending
        spans.sort(key=lambda x: x[0])
        
        # Build substitution and mapping
        mapping: Dict[str, str] = {}
        counters: Dict[str, int] = {}
        
        # Replace from end to start to preserve index offsets
        result_chars = list(text)
        for start, end, label, _ in reversed(spans):
            counters[label] = counters.get(label, 0) + 1
            token = f"[{label}_{counters[label]}]"
            mapping[token] = text[start:end]
            result_chars[start:end] = list(token)
            
        masked_text = "".join(result_chars)
        return masked_text, session_id, mapping

    def unmask(self, masked_text: str, mapping: Dict[str, str]) -> str:
        """
        Reverses tokenization using the ephemeral session mapping.
        """
        result = masked_text
        for token, original_value in mapping.items():
            result = result.replace(token, original_value)
        return result
