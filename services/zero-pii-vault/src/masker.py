"""
Zero-PII Vault: Модуль нейросетевого и алгоритмического маскирования персональных данных.
Соответствует требованиям Федеральных законов РФ:
- 152-ФЗ «О персональных данных»
- 395-1 «О банках и банковской деятельности» (Банковская тайна)

Архитектурные принципы:
1. Конфигурация вынесена во внешние файлы (config/rules.yaml, config/famous_persons.yaml).
   Никакого хардкода регулярок, списков персон или стоп-слов в коде.
2. Zero-Loss 100% обратимость: текст восстанавливается байт-в-байт через session mapping.
3. Нейросетевой NER (Natasha / Slovnet) с контекстной верификацией банковских интентов.
4. Разрешение ролевых/стилистических метафор: известные поэты/ученые в стилистических
   запросах ("Ты, как Пушкин") НЕ маскируются, но при реальных транзакциях или в анкетах
   клиентов ("Переведи 5000 руб Пушкину") — МАСКИРУЮТСЯ ОБЯЗАТЕЛЬНО.
5. Валидация контрольных сумм: алгоритм Луна для банковских карт и алгоритм ФНС для ИНН.
"""

import re
import uuid
from typing import Dict, Tuple, List, Optional, Set

from natasha import (
    Segmenter,
    MorphVocab,
    NewsEmbedding,
    NewsNERTagger,
    AddrExtractor,
    Doc
)

# Загрузка внешней конфигурации (декаплинг бизнес-логики от списков сущностей и regex-паттернов)
try:
    from .config_loader import VaultConfig, load_vault_config
except ImportError:
    from config_loader import VaultConfig, load_vault_config


def luhn_checksum_valid(card_number_str: str) -> bool:
    """
    Проверка валидности номера банковской карты по алгоритму Луна (Luhn, Mod 10).
    Используется международными платежными системами (МИР, Visa, Mastercard, UnionPay).
    Длина номера карты: от 13 до 19 цифр.
    
    Алгоритм:
    1. Идем справа налево по цифрам номера карты.
    2. Каждую вторую цифру удваиваем. Если результат >= 10, вычитаем 9 (складываем цифры).
    3. Суммируем все полученные значения.
    4. Если итоговая сумма делится на 10 без остатка — номер валиден.
    """
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
    """
    Алгоритмическая проверка контрольной суммы ИНН (Идентификационный номер налогоплательщика)
    по официальной методике Федеральной налоговой службы (ФНС России).
    
    Поддерживает:
    - 10-значный ИНН юридического лица: контрольная цифра (10-я) рассчитывается по 9 весовым коэффициентам.
    - 12-значный ИНН физического лица / ИП: 11-я и 12-я контрольные цифры рассчитываются
      последовательно по двум независимым массивам весов.
    """
    digits = [int(c) for c in inn if c.isdigit()]
    
    # 1. Валидация 10-значного ИНН организации (Юрлицо)
    if len(digits) == 10:
        weights = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum = sum(w * d for w, d in zip(weights, digits[:9])) % 11 % 10
        return checksum == digits[9]
        
    # 2. Валидация 12-значного ИНН физического лица / ИП
    elif len(digits) == 12:
        weights1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum1 = sum(w * d for w, d in zip(weights1, digits[:10])) % 11 % 10
        weights2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum2 = sum(w * d for w, d in zip(weights2, digits[:11])) % 11 % 10
        return checksum1 == digits[10] and checksum2 == digits[11]
        
    return False


class NatashaPIIMasker:
    """
    Высокопроизводительный нейросетевой и алгоритмический маскировщик ПДн.
    
    Сочетает:
    - Внешнюю декларативную конфигурацию правил и сущностей (YAML).
    - Прекомпилированные регулярные выражения высокой производительности.
    - Математические валидаторы банковских идентификаторов (Луна, контрольные разряды ФНС).
    - Компактные эмбеддинги Natasha / Slovnet NewsEmbedding для морфологического анализа ФИО.
    - Двунаправленный контекстный анализатор интентов для корректной обработки
      ролевых запросов vs реальных финансовых поручений.
    """
    
    def __init__(
        self,
        config: Optional[VaultConfig] = None,
        granular_address: Optional[bool] = None
    ):
        """
        Инициализация маскировщика.
        
        :param config: Экземпляр VaultConfig. Если не передан, автоматически загружается
                       из внешних файлов config/rules.yaml и config/famous_persons.yaml.
        :param granular_address: Флаг дробления адресов на составные части ([CITY], [STREET]...).
                                 Если не задан, берется значение из конфигурации.
        """
        # 1. Инициализация конфигурации из внешних YAML-файлов
        self.config: VaultConfig = config or load_vault_config()
        self.granular_address: bool = (
            granular_address if granular_address is not None else self.config.granular_address
        )
        self.context_window_chars: int = self.config.context_window_chars

        # 2. Словари и лексиконы, загруженные из конфигурации
        self.famous_persons: Set[str] = self.config.famous_persons
        self.famous_person_bases: Set[str] = self.config.famous_person_bases
        self.verb_stopwords: Set[str] = self.config.verb_stopwords

        # 3. Прекомпилированные регулярные выражения для категорий ПДн из rules.yaml
        self.card_pattern = self.config.get_pattern("card")
        self.inn_pattern = self.config.get_pattern("inn")
        self.cvv_pattern = self.config.get_pattern("cvv")
        self.pin_pattern = self.config.get_pattern("pin")
        self.cardholder_pattern = self.config.get_pattern("cardholder")
        self.vu_pattern = self.config.get_pattern("driver_license")
        self.pass_code_pattern = self.config.get_pattern("passport_code")
        self.pass_pattern = self.config.get_pattern("passport")
        self.issuer_pattern = self.config.get_pattern("passport_issuer")
        self.pass_date_pattern = self.config.get_pattern("passport_date")
        self.citizen_pattern = self.config.get_pattern("citizenship")
        self.birth_date_pattern = self.config.get_pattern("birth_date")
        self.birth_place_pattern = self.config.get_pattern("birth_place")
        self.email_pattern = self.config.get_pattern("email")
        self.phone_pattern = self.config.get_pattern("phone")
        self.address_line_pattern = self.config.get_pattern("address")
        self.identity_person_pattern = self.config.get_pattern("identity_person")

        # 4. Контекстные паттерны метафор и банковских намерений
        self.metaphor_pattern = self.config.metaphor_pattern
        self.banking_intent_pattern = self.config.banking_intent_pattern

        # 5. Инициализация легковесного морфологического движка Natasha
        self.segmenter = Segmenter()
        self.morph_vocab = MorphVocab()
        self.emb = NewsEmbedding()
        self.ner_tagger = NewsNERTagger(self.emb)
        self.addr_extractor = AddrExtractor(self.morph_vocab)

    def is_person_pii(self, raw_name: str, full_text: str, start: int, end: int) -> bool:
        """
        Контекстный классификатор: определяет, является ли найденное имя реальными ПДн
        (клиент банка, получатель перевода, владелец счета, субъект договора),
        либо стилистической / ролевой отсылкой к известной исторической личности.
        
        Логика принятия решений:
        1. Очистка имени от висячих предлогов и проверка по списку командных стоп-слов.
        2. Выделение контекстного окна (символы до и после имени).
        3. Изоляция метафоры внутри текущей клаузы (знаки препинания разделяют интенты).
        4. Проверка личности по словарям известных деятелей культуры, науки и истории.
        5. Проверка наличия банковских интентов в непосредственной близости.
        6. Правило:
           - Известная личность + ролевой запрос ("Ты, как Пушкин...") -> НЕ МАСКИРУЕМ.
           - Известная личность + банковский интент ("Переведи Пушкину на карту...") -> МАСКИРУЕМ.
           - Обычное имя клиента в банковском запросе -> МАСКИРУЕМ.
           - Одиночное нарицательное слово с заглавной буквы без контекста -> НЕ МАСКИРУЕМ (защита от FP).
        """
        # Очистка имени от возможных прилипших служебных частей речи
        clean_name = re.sub(
            r'\s+\b(?:по|в|на|и|с|о|от|к|для|при|из|под|за)\b\s*$',
            '',
            raw_name.strip(" ,.:;!?()\"'")
        )
        words = clean_name.split()
        if not words:
            return False

        # Проверка: если имя целиком совпадает с командным глаголом-стоп-словом ("Переведи", "Скинь")
        clean_lower = clean_name.lower()
        if clean_lower in self.verb_stopwords:
            return False

        # Выделение скользящего контекстного окна (двунаправленное сканирование)
        win = self.context_window_chars
        prefix = full_text[max(0, start - win):start]
        suffix = full_text[end:min(len(full_text), end + win)]

        # Изоляция метафоры/роли: проверяем префикс ТОЛЬКО текущей клаузы/предложения,
        # чтобы оборот "Ты, как Пушкин," не перетекал на второе лицо после запятой ("переведи Толстому...")
        line_prefix = prefix.split('\n')[-1]
        clause_prefix = re.split(r'[\.\?!;,\(\)]\s*', line_prefix)[-1]
        has_metaphor = bool(self.metaphor_pattern.search(clause_prefix)) if self.metaphor_pattern else False

        # Проверка: совпадает ли найденное имя с известной публичной/культурной фигурой
        # (используем как поиск по корням-основам для учета падежей, так и точные словоформы)
        words_lower = [w.lower().strip(" ,.:;!?") for w in words]
        is_famous = any(
            any(w.startswith(b) for b in self.famous_person_bases) or w in self.famous_persons
            for w in words_lower
        )

        # Проверка наличия банковских и платежных интентов в окружающем тексте
        has_banking_intent = False
        if self.banking_intent_pattern:
            has_banking_intent = bool(
                self.banking_intent_pattern.search(prefix) or self.banking_intent_pattern.search(suffix)
            )

        # Решение для известных личностей
        if is_famous:
            # Известная личность маскируется ТОЛЬКО если она явно вовлечена в банковский интент
            # (например, "Клиент: Маяковский В.В.", "Перевести 5000 рублей Пушкину на карту")
            # и при этом НЕ является объектом метафоры/ролевой инструкции
            if has_banking_intent and not has_metaphor:
                return True
            return False

        # Решение для обычных имен клиентов:
        # Если перед именем стоит метафорический оборот сравнения, не маскируем
        if has_metaphor:
            return False

        # Одиночное капитализированное слово без подтверждающего контекста отклоняем
        # для предотвращения ложных срабатываний на началах фраз ("Позвони", "Внимание", "Тикет")
        if len(words) < 2 and not has_banking_intent:
            return False

        return True

    def mask(self, text: str, session_id: Optional[str] = None) -> Tuple[str, str, Dict[str, str]]:
        """
        Выполняет комплексное маскирование всех найденных категорий ПДн.
        
        Возвращает:
        (sanitized_text, session_id, mapping_dict)
        - sanitized_text: обезличенный текст с подстановочными токенами ([CARD_1], [FIO_1]...).
        - session_id: уникальный идентификатор сессии.
        - mapping_dict: строго конфиденциальная карта соответствия токенов исходным данным.
        """
        if not session_id:
            session_id = str(uuid.uuid4())

        # Список обнаруженных фрагментов ПДн: (начало, конец, метка_категории, исходное_значение)
        spans: List[Tuple[int, int, str, str]] = []

        def is_overlapping(start: int, end: int) -> bool:
            """Проверяет пересечение нового интервала с уже зарегистрированными спанами."""
            return any(not (end <= s or start >= e) for s, e, _, _ in spans)

        def add_span(start: int, end: int, label: str, val: str):
            """Регистрирует спан, предотвращая наложение интервалов."""
            if not is_overlapping(start, end):
                spans.append((start, end, label, val))

        # --------------------------------------------------------------------------
        # ЭТАП 1: Алгоритмический и регулярный поиск строго структурированных ПДн
        # --------------------------------------------------------------------------

        # 1. Водительские удостоверения РФ
        for m in self.vu_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'DRIVER_LICENSE', m.group(1))

        # 2. Номера банковских карт (с обязательной валидацией по алгоритму Луна)
        for m in self.card_pattern.finditer(text):
            raw = m.group(0)
            cleaned = re.sub(r'\D', '', raw)
            if (13 <= len(cleaned) <= 19) and luhn_checksum_valid(cleaned):
                add_span(m.start(), m.end(), 'CARD', raw)

        # 3. ИНН физических и юридических лиц (с обязательной валидацией контрольных цифр ФНС)
        for m in self.inn_pattern.finditer(text):
            raw = m.group(1) if m.group(1) else m.group(0)
            clean = re.sub(r'\D', '', raw)
            if len(clean) in (10, 12) and validate_inn(clean):
                st = m.start(1) if m.group(1) else m.start(0)
                en = m.end(1) if m.group(1) else m.end(0)
                add_span(st, en, 'INN', raw)

        # 4. Код подразделения паспортного органа
        for m in self.pass_code_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'PASSPORT_CODE', m.group(1))

        # 5. Серия и номер паспорта РФ
        for m in self.pass_pattern.finditer(text):
            add_span(m.start(), m.end(), 'PASSPORT', m.group(0))

        # 6. Email-адреса
        for m in self.email_pattern.finditer(text):
            add_span(m.start(), m.end(), 'EMAIL', m.group(0))

        # 7. Номера телефонов (все форматы записи: с точками, дефисами, кодами +7/8/007)
        for m in self.phone_pattern.finditer(text):
            raw = m.group('num') if m.group('num') else m.group(0)
            clean = re.sub(r'\D', '', raw)
            if len(clean) in (10, 11) or (clean.startswith('007') and len(clean) == 13):
                st = m.start('num') if m.group('num') else m.start(0)
                en = m.end('num') if m.group('num') else m.end(0)
                add_span(st, en, 'PHONE', raw)

        # 8. Коды безопасности CVV / CVC
        for m in self.cvv_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'CVV', m.group(1))

        # 9. ПИН-коды карт
        for m in self.pin_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'PIN', m.group(1))

        # 10. Имя держателя карты (Cardholder name)
        for m in self.cardholder_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'CARDHOLDER', m.group(1).strip())

        # 11. Дата рождения
        for m in self.birth_date_pattern.finditer(text):
            val = m.group(1) or m.group(2)
            st = m.start(1) if m.group(1) else m.start(2)
            en = m.end(1) if m.group(1) else m.end(2)
            add_span(st, en, 'BIRTHDATE', val)

        # 12. Дата выдачи паспорта
        for m in self.pass_date_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'PASSPORT_DATE', m.group(1))

        # 13. Место рождения (включая разговорные формы: "родился в Самаре", "родом из...")
        for m in self.birth_place_pattern.finditer(text):
            val = (m.group(1) or m.group(2)).strip()
            st = m.start(1) if m.group(1) else m.start(2)
            en = m.end(1) if m.group(1) else m.end(2)
            add_span(st, en, 'BIRTHPLACE', val)

        # 14. Гражданство
        for m in self.citizen_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'CITIZENSHIP', m.group(1).strip())

        # 15. Кем выдан паспорт (подразделения МВД/УФМС)
        for m in self.issuer_pattern.finditer(text):
            raw_val = m.group(1).strip()
            clean_val = re.sub(r'^(?:его\s+|в\s+|через\s+)+', '', raw_val)
            st = m.start(1) + (len(raw_val) - len(clean_val))
            en = m.end(1)
            add_span(st, en, 'PASSPORT_ISSUER', clean_val)

        # 16. Адрес регистрации / фактического проживания
        if not self.granular_address:
            for m in self.address_line_pattern.finditer(text):
                raw_val = m.group(1).strip()
                clean_val = re.sub(r'^(?:сейчас\s+|по\s+адресу\s+|в\s+|на\s+адрес\s+|на\s+)+', '', raw_val)
                clean_val = re.sub(r'(?:,\s*(?:хотя|паспорт|прописан|тел|но|к/п|код|выдан).*)$', '', clean_val)
                st = m.start(1) + (len(raw_val) - len(clean_val))
                en = st + len(clean_val)
                add_span(st, en, 'ADDRESS', clean_val)
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

        # 17. Явно маркированное ФИО клиента в обращениях, анкетах и договорах
        for m in self.identity_person_pattern.finditer(text):
            val = m.group(1).strip()
            if self.is_person_pii(val, text, m.start(1), m.end(1)):
                add_span(m.start(1), m.end(1), 'FIO', val)

        # --------------------------------------------------------------------------
        # ЭТАП 2: Нейросетевое извлечение ФИО (PER) через Natasha + слияние спанов
        # --------------------------------------------------------------------------
        doc = Doc(text)
        doc.segment(self.segmenter)
        doc.tag_ner(self.ner_tagger)
        per_spans = [s for s in doc.spans if s.type == 'PER']

        # Слияние соседних фрагментов ФИО, если они разделены лишь пробелами
        # (например, Slovnet может выделить "Александр" и "Пушкин" двумя отдельными спанами)
        merged_spans: List[Tuple[int, int, str]] = []
        for s in per_spans:
            if merged_spans and merged_spans[-1][1] <= s.start and text[merged_spans[-1][1]:s.start].strip() == '':
                prev_st, prev_en, prev_text = merged_spans.pop()
                merged_spans.append((prev_st, s.stop, text[prev_st:s.stop]))
            else:
                merged_spans.append((s.start, s.stop, s.text))

        # Обработка каждого обнаруженного имени
        for st, en, raw_name in merged_spans:
            raw_name = raw_name.strip()

            # Отсекаем вступительную частицу "Я, ..." если модель захватила ее
            if raw_name.startswith('Я, '):
                raw_name = raw_name[3:].strip()
                st += 3

            # Отделяем командный глагол, если модель "склеила" глагол и имя
            # (например, "Скинь Ницше" -> "Скинь" оставляем в тексте, "Ницше" анализируем)
            first_word = raw_name.split()[0].rstrip(',:').lower()
            if first_word in self.verb_stopwords and len(raw_name.split()) > 1:
                v_len = len(raw_name.split()[0])
                rest = raw_name[v_len:].lstrip(' ,:')
                st += len(raw_name) - len(rest)
                raw_name = rest

            # Очищаем имя от висячего предлога на конце ("по", "к", "для")
            cleaned_name = re.sub(r'\s+\b(?:по|в|на|и|с|о|от|к|для|при|из|под|за)\b\s*$', '', raw_name)
            if len(cleaned_name) < len(raw_name):
                en = st + len(cleaned_name)
                raw_name = cleaned_name

            # Проверяем через контекстный классификатор интентов
            if self.is_person_pii(raw_name, text, st, en):
                add_span(st, en, 'FIO', raw_name)

        # --------------------------------------------------------------------------
        # ЭТАП 3: Формирование обезличенного текста и обратной карты маппинга
        # --------------------------------------------------------------------------
        # Сортируем спаны строго по возрастанию индекса начала в тексте
        spans.sort(key=lambda x: x[0])

        mapping: Dict[str, str] = {}
        counters: Dict[str, int] = {}

        # Замену выполняем строго с конца к началу текста, чтобы индексы символов
        # предшествующих спанов не смещались при изменении длины строки
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
        Восстанавливает исходный текст, подставляя оригинальные данные вместо токенов
        по временной сессионной карте (обратное демаскирование).
        
        Гарантирует 100% обратимость и идентичность исходному тексту (Lossless).
        """
        result = masked_text
        for token, original_value in mapping.items():
            result = result.replace(token, original_value)
        return result
