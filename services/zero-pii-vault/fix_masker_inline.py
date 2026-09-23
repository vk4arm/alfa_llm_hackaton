import re

with open('src/masker.py', 'r') as f:
    content = f.read()

# Add to __init__
content = content.replace('self.context_window_chars: int = self.config.context_window_chars', 'self.context_window_chars: int = self.config.context_window_chars\n        self.enabled_masks = self.config.enabled_masks or {}')

replacements = [
    (r'for m in self\.vu_pattern\.finditer\(text\):', r'for m in (self.vu_pattern.finditer(text) if self.enabled_masks.get("driver_license", True) else []):'),
    (r'for m in self\.card_pattern\.finditer\(text\):', r'for m in (self.card_pattern.finditer(text) if self.enabled_masks.get("card", True) else []):'),
    (r'for m in self\.inn_pattern\.finditer\(text\):', r'for m in (self.inn_pattern.finditer(text) if self.enabled_masks.get("inn", True) else []):'),
    (r'for m in self\.pass_code_pattern\.finditer\(text\):', r'for m in (self.pass_code_pattern.finditer(text) if self.enabled_masks.get("passport_code", True) else []):'),
    (r'for m in self\.pass_pattern\.finditer\(text\):', r'for m in (self.pass_pattern.finditer(text) if self.enabled_masks.get("passport", True) else []):'),
    (r'for m in self\.email_pattern\.finditer\(text\):', r'for m in (self.email_pattern.finditer(text) if self.enabled_masks.get("email", True) else []):'),
    (r'for m in self\.phone_pattern\.finditer\(text\):', r'for m in (self.phone_pattern.finditer(text) if self.enabled_masks.get("phone", True) else []):'),
    (r'for m in self\.cvv_pattern\.finditer\(text\):', r'for m in (self.cvv_pattern.finditer(text) if self.enabled_masks.get("cvv", True) else []):'),
    (r'for m in self\.pin_pattern\.finditer\(text\):', r'for m in (self.pin_pattern.finditer(text) if self.enabled_masks.get("pin", True) else []):'),
    (r'for m in self\.cardholder_pattern\.finditer\(text\):', r'for m in (self.cardholder_pattern.finditer(text) if self.enabled_masks.get("cardholder", True) else []):'),
    (r'for m in self\.birth_date_pattern\.finditer\(text\):', r'for m in (self.birth_date_pattern.finditer(text) if self.enabled_masks.get("birth_date", True) else []):'),
    (r'for m in self\.pass_date_pattern\.finditer\(text\):', r'for m in (self.pass_date_pattern.finditer(text) if self.enabled_masks.get("passport_date", True) else []):'),
    (r'for m in self\.birth_place_pattern\.finditer\(text\):', r'for m in (self.birth_place_pattern.finditer(text) if self.enabled_masks.get("birth_place", True) else []):'),
    (r'for m in self\.citizen_pattern\.finditer\(text\):', r'for m in (self.citizen_pattern.finditer(text) if self.enabled_masks.get("citizenship", True) else []):'),
    (r'for m in self\.issuer_pattern\.finditer\(text\):', r'for m in (self.issuer_pattern.finditer(text) if self.enabled_masks.get("passport_issuer", True) else []):'),
    (r'for m in self\.identity_person_pattern\.finditer\(text\):', r'for m in (self.identity_person_pattern.finditer(text) if self.enabled_masks.get("identity_person", True) else []):'),
    (r'for m in self\.address_line_pattern\.finditer\(text\):', r'for m in (self.address_line_pattern.finditer(text) if self.enabled_masks.get("address", True) else []):'),
    (r'for m in self\.addr_extractor\(text\):', r'for m in (self.addr_extractor(text) if self.enabled_masks.get("address", True) else []):'),
]

for pat, rep in replacements:
    content = re.sub(pat, rep, content)

# For person NER
ner_code = """        # --------------------------------------------------------------------------
        # ЭТАП 2: Нейросетевое извлечение ФИО (PER) через Natasha + слияние спанов
        # --------------------------------------------------------------------------
        doc = Doc(text)
        doc.segment(self.segmenter)
        doc.tag_ner(self.ner_tagger)
        per_spans = [s for s in doc.spans if s.type == 'PER']"""

new_ner_code = """        # --------------------------------------------------------------------------
        # ЭТАП 2: Нейросетевое извлечение ФИО (PER) через Natasha + слияние спанов
        # --------------------------------------------------------------------------
        per_spans = []
        if self.enabled_masks.get("person", True):
            doc = Doc(text)
            doc.segment(self.segmenter)
            doc.tag_ner(self.ner_tagger)
            per_spans = [s for s in doc.spans if s.type == 'PER']"""

content = content.replace(ner_code, new_ner_code)

with open('src/masker.py', 'w') as f:
    f.write(content)
