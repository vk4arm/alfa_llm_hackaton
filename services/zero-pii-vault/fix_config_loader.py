import re
with open('src/config_loader.py', 'r') as f:
    content = f.read()

# Add to VaultConfig
content = content.replace('    granular_address: bool = False', '    granular_address: bool = False\n    enabled_masks: Dict[str, bool] = None')

# Add to load_vault_config
content = content.replace('        context_window_chars=settings.get("context_window_chars", 80),', '        context_window_chars=settings.get("context_window_chars", 80),\n        enabled_masks=settings.get("enabled_masks", {})')

with open('src/config_loader.py', 'w') as f:
    f.write(content)
