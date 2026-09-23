import os

filepath = "/Users/victor/work/СТРАННОЕ/alfa/data/create_datasets.py"
with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

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
content = content.replace("]\n\ndef create_record", "]\n" + edge_cases_code + "\ndef create_record")

old_code = """        elif chunk_r < 0.85:
            # Заключительная часть (текст просьбы/описания проблемы) полностью маленькими буквами
            lines = rec.split("\\n")
            if len(lines) > 4:
                lines[-1] = lines[-1].lower()
            rec = "\\n".join(lines)"""

new_code = """        elif chunk_r < 0.85:
            # Заключительная часть (текст просьбы/описания проблемы) полностью маленькими буквами
            lines = rec.split("\\n")
            if len(lines) > 4:
                lines[-1] = lines[-1].lower()
            rec = "\\n".join(lines)
        else:
            rec += "\\n" + random.choice(EDGE_CHUNKS)"""

content = content.replace(old_code, new_code)

with open(filepath, "w", encoding="utf-8") as f:
    f.write(content)
