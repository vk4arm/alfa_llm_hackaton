with open('config/rules.yaml', 'r') as f:
    content = f.read()

enabled_masks_block = """
  # Включение/отключение маскирования конкретных типов ПДн
  enabled_masks:
    card: true
    inn: true
    email: true
    phone: true
    cvv: true
    pin: true
    cardholder: true
    driver_license: true
    passport_code: true
    passport: true
    passport_issuer: true
    passport_date: true
    citizenship: true
    birth_date: true
    birth_place: true
    address: true
    person: true
    identity_person: true
"""

content = content.replace('  context_window_chars: 80', '  context_window_chars: 80' + enabled_masks_block)

with open('config/rules.yaml', 'w') as f:
    f.write(content)
