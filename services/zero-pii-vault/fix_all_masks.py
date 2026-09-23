import re

with open('src/masker.py', 'r') as f:
    content = f.read()

replacements = [
    (r'(for m in self\.vu_pattern\.finditer\(text\):)', r'if self.enabled_masks.get("driver_license", True):\n            \1'),
    (r'(for m in self\.card_pattern\.finditer\(text\):)', r'if self.enabled_masks.get("card", True):\n            \1'),
    (r'(for m in self\.inn_pattern\.finditer\(text\):)', r'if self.enabled_masks.get("inn", True):\n            \1'),
    (r'(for m in self\.pass_code_pattern\.finditer\(text\):)', r'if self.enabled_masks.get("passport_code", True):\n            \1'),
    (r'(for m in self\.pass_pattern\.finditer\(text\):)', r'if self.enabled_masks.get("passport", True):\n            \1'),
    (r'(for m in self\.email_pattern\.finditer\(text\):)', r'if self.enabled_masks.get("email", True):\n            \1'),
    (r'(for m in self\.phone_pattern\.finditer\(text\):)', r'if self.enabled_masks.get("phone", True):\n            \1'),
    (r'(for m in self\.cvv_pattern\.finditer\(text\):)', r'if self.enabled_masks.get("cvv", True):\n            \1'),
    (r'(for m in self\.pin_pattern\.finditer\(text\):)', r'if self.enabled_masks.get("pin", True):\n            \1'),
    (r'(for m in self\.cardholder_pattern\.finditer\(text\):)', r'if self.enabled_masks.get("cardholder", True):\n            \1'),
    (r'(for m in self\.birth_date_pattern\.finditer\(text\):)', r'if self.enabled_masks.get("birth_date", True):\n            \1'),
    (r'(for m in self\.pass_date_pattern\.finditer\(text\):)', r'if self.enabled_masks.get("passport_date", True):\n            \1'),
    (r'(for m in self\.birth_place_pattern\.finditer\(text\):)', r'if self.enabled_masks.get("birth_place", True):\n            \1'),
    (r'(for m in self\.citizen_pattern\.finditer\(text\):)', r'if self.enabled_masks.get("citizenship", True):\n            \1'),
    (r'(for m in self\.issuer_pattern\.finditer\(text\):)', r'if self.enabled_masks.get("passport_issuer", True):\n            \1'),
    (r'(for m in self\.identity_person_pattern\.finditer\(text\):)', r'if self.enabled_masks.get("identity_person", True):\n            \1')
]

for pat, rep in replacements:
    content = re.sub(pat, rep, content)

with open('src/masker.py', 'w') as f:
    f.write(content)

