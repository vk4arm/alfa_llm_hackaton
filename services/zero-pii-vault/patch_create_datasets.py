import re
import os

filepath = "/Users/victor/work/СТРАННОЕ/alfa/data/create_datasets.py"
with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

# Add edge case chunks to UPPER_CHUNKS / LOWER_CHUNKS or just create a new list and inject it into create_record
edge_cases_code = """
EDGE_CHUNKS = [
    "доп документы: загран 51-1234567, паспорт беларуси мс-1234567, св-во о рожд. vi ав123456.",
    "клиент предоставил даркон 12345678 и узбекский паспорт ac12345678.",
    "в базе числится военник вг1234567 и теудат-зехут: 123456789.",
    "Свидетельство на ребенка: X-ЕР№123456. У брата казахский паспорт 123456789.",
    "загранпаспорт: 511234567, лессе пассе 12345678, паспорт снг 123456789.",
    "опечатки: белорусский паспорт МС1234567, военный билет ВГ-1234567, паспорт рб мс1234567."
]
"""

# Insert EDGE_CHUNKS definition after LOWER_CHUNKS
content = content.replace("]\n\ndef create_record", "]\n" + edge_cases_code + "\ndef create_record")

# Modify create_record to inject edge chunks
injection_logic = """
        elif chunk_r < 0.85:
            # Заключительная часть (текст просьбы/описания проблемы) полностью маленькими буквами
            lines = rec.split("\\n")
            if len(lines) > 4:
                lines[-1] = lines[-1].lower()
            rec = "\\n".join(lines)
        else:
            # Краевые случаи и опечатки новых документов
            rec += "\\n" + random.choice(EDGE_CHUNKS)
"""

# Find the end of the if-elif chain in create_record and replace it
content = re.sub(r'elif chunk_r < 0\.85:(.*?)rec = "\\n"\.join\(lines\)', injection_logic.strip(), content, flags=re.DOTALL)

with open(filepath, "w", encoding="utf-8") as f:
    f.write(content)
