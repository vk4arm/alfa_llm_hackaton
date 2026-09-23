with open('src/masker.py', 'r') as f:
    content = f.read()

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
