with open('src/masker.py', 'r') as f:
    content = f.read()

# Add to __init__
content = content.replace('self.context_window_chars: int = self.config.context_window_chars', 'self.context_window_chars: int = self.config.context_window_chars\n        self.enabled_masks = self.config.enabled_masks or {}')

# Update extract_spans loops
replacements = [
    ('for m in self.vu_pattern.finditer(text):', 'if self.enabled_masks.get("driver_license", True):\n            for m in self.vu_pattern.finditer(text):'),
    ('for m in self.card_pattern.finditer(text):', 'if self.enabled_masks.get("card", True):\n            for m in self.card_pattern.finditer(text):'),
    ('for m in self.inn_pattern.finditer(text):', 'if self.enabled_masks.get("inn", True):\n            for m in self.inn_pattern.finditer(text):'),
    ('for m in self.pass_code_pattern.finditer(text):', 'if self.enabled_masks.get("passport_code", True):\n            for m in self.pass_code_pattern.finditer(text):'),
    ('for m in self.pass_pattern.finditer(text):', 'if self.enabled_masks.get("passport", True):\n            for m in self.pass_pattern.finditer(text):'),
    ('for m in self.email_pattern.finditer(text):', 'if self.enabled_masks.get("email", True):\n            for m in self.email_pattern.finditer(text):'),
    ('for m in self.phone_pattern.finditer(text):', 'if self.enabled_masks.get("phone", True):\n            for m in self.phone_pattern.finditer(text):'),
    ('for m in self.cvv_pattern.finditer(text):', 'if self.enabled_masks.get("cvv", True):\n            for m in self.cvv_pattern.finditer(text):'),
    ('for m in self.pin_pattern.finditer(text):', 'if self.enabled_masks.get("pin", True):\n            for m in self.pin_pattern.finditer(text):'),
    ('for m in self.cardholder_pattern.finditer(text):', 'if self.enabled_masks.get("cardholder", True):\n            for m in self.cardholder_pattern.finditer(text):'),
    ('for m in self.birth_date_pattern.finditer(text):', 'if self.enabled_masks.get("birth_date", True):\n            for m in self.birth_date_pattern.finditer(text):'),
    ('for m in self.pass_date_pattern.finditer(text):', 'if self.enabled_masks.get("passport_date", True):\n            for m in self.pass_date_pattern.finditer(text):'),
    ('for m in self.birth_place_pattern.finditer(text):', 'if self.enabled_masks.get("birth_place", True):\n            for m in self.birth_place_pattern.finditer(text):'),
    ('for m in self.citizen_pattern.finditer(text):', 'if self.enabled_masks.get("citizenship", True):\n            for m in self.citizen_pattern.finditer(text):'),
    ('for m in self.issuer_pattern.finditer(text):', 'if self.enabled_masks.get("passport_issuer", True):\n            for m in self.issuer_pattern.finditer(text):'),
    ('if not self.granular_address:\n            for m in self.address_line_pattern.finditer(text):', 'if self.enabled_masks.get("address", True):\n            if not self.granular_address:\n                for m in self.address_line_pattern.finditer(text):'),
    ('else:\n            for m in self.addr_extractor(text):', '            else:\n                for m in self.addr_extractor(text):'),
    ('for m in self.identity_person_pattern.finditer(text):', 'if self.enabled_masks.get("identity_person", True):\n            for m in self.identity_person_pattern.finditer(text):')
]

for old, new in replacements:
    content = content.replace(old, new)

# And for person NER
person_old = "if self.onnx_accelerated:"
person_new = 'if self.enabled_masks.get("person", True):\n            if self.onnx_accelerated:'

# Wait, `if self.onnx_accelerated:` has an `else:` block for NER tagging, so I need to wrap both or wrap the person iteration inside them.
# Let's wrap the iteration inside `extract_spans`.
