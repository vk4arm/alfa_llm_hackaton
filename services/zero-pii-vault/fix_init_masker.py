with open('src/masker.py', 'r') as f:
    content = f.read()

content = content.replace('self.context_window_chars: int = self.config.context_window_chars', 'self.context_window_chars: int = self.config.context_window_chars\n        self.enabled_masks = self.config.enabled_masks or {}')

with open('src/masker.py', 'w') as f:
    f.write(content)
