"""
Комплексный набор тестов для Zero-PII Vault.
Проверяет:
1. Загрузку внешней конфигурации (rules.yaml, famous_persons.yaml) через config_loader.
2. Алгоритмическую валидацию (алгоритм Луна для карт, контрольные разряды ФНС для ИНН).
3. Маскирование всех 17 категорий ПДн.
4. Разрешение контекста для известных личностей:
   - Ролевые запросы и метафоры ("Ты, как Пушкин") -> НЕ маскируются.
   - Банковские интенты, переводы, клиенты ("Переведи Пушкину на карту...") -> МАСКИРУЮТСЯ.
   - Совместное использование ("Ты, как Пушкин, переведи Толстому 5000 руб") -> Пушкин сохранен, Толстой замаскирован.
5. Различные безумные форматы записи телефонов, карт и ИНН (точки, дефисы, слэши, пробелы, скобки).
6. 100% обратимость (Roundtrip Lossless Reversibility: unmask(masked) == original).
"""

import os
import sys
import unittest

# Добавляем путь к исходным кодам микросервиса
src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from config_loader import load_vault_config, VaultConfig
from masker import NatashaPIIMasker, luhn_checksum_valid, validate_inn
from vault import ZeroPiiVault


class TestConfigLoader(unittest.TestCase):
    """Тестирование модуля загрузки конфигураций без хардкода."""

    def test_config_loaded_successfully(self):
        config = load_vault_config()
        self.assertIsInstance(config, VaultConfig)
        self.assertGreater(len(config.compiled_patterns), 10)
        self.assertGreater(len(config.famous_person_bases), 100)
        self.assertGreater(len(config.famous_persons), 50)
        self.assertGreater(len(config.verb_stopwords), 30)
        self.assertIsNotNone(config.metaphor_pattern)
        self.assertIsNotNone(config.banking_intent_pattern)

    def test_required_patterns_present(self):
        config = load_vault_config()
        expected = [
            "card", "inn", "cvv", "pin", "cardholder", "driver_license",
            "passport_code", "passport", "passport_issuer", "passport_date",
            "citizenship", "birth_date", "birth_place", "email", "phone",
            "address", "identity_person"
        ]
        for name in expected:
            pattern = config.get_pattern(name)
            self.assertIsNotNone(pattern, f"Паттерн {name} должен быть скомпилирован")


class TestChecksumAlgorithms(unittest.TestCase):
    """Тестирование математических алгоритмов валидации карт и ИНН."""

    def test_luhn_algorithm(self):
        # Реальные валидные номера карт (тестовые генераторы банков)
        self.assertTrue(luhn_checksum_valid("2200 1234 5678 9019"))
        self.assertTrue(luhn_checksum_valid("4111111111111111"))
        self.assertTrue(luhn_checksum_valid("5555555555554444"))
        self.assertTrue(luhn_checksum_valid("2202201234567895"))

        # Невалидные номера карт (ошибочная контрольная сумма)
        self.assertFalse(luhn_checksum_valid("4111111111111112"))
        self.assertFalse(luhn_checksum_valid("2200123456789010"))
        self.assertFalse(luhn_checksum_valid("123"))

    def test_inn_algorithm(self):
        # Валидный 10-значный ИНН организации (ПАО Сбербанк)
        self.assertTrue(validate_inn("7707083893"))
        # Валидный 10-значный ИНН (Альфа-Банк)
        self.assertTrue(validate_inn("7728168971"))
        # Валидный 12-значный ИНН физлица
        self.assertTrue(validate_inn("500100732259"))
        self.assertTrue(validate_inn("781201456701"))

        # Невалидные ИНН (нарушена контрольная сумма)
        self.assertFalse(validate_inn("7707083890"))
        self.assertFalse(validate_inn("500100732250"))
        self.assertFalse(validate_inn("1234567890"))


class TestFamousPersonsRoleplayVsBanking(unittest.TestCase):
    """
    Тестирование контекстного маскирования известных личностей:
    - Не маскируем, если поэт/деятель упомянут в контексте роли, стиля или метафоры.
    - Маскируем, если деятель является клиентом, получателем или участником финансовой операции.
    """

    def setUp(self):
        self.masker = NatashaPIIMasker()

    def test_poet_in_roleplay_is_not_masked(self):
        samples = [
            "Ты, как Александр Пушкин, напиши стихотворение о золотой осени.",
            "Ответь в стиле Сергея Есенина на этот философский вопрос.",
            "Представь, что ты Михаил Лермонтов и рассуждай о Кавказе.",
            "Словно Леонардо да Винчи опиши чертеж летательного аппарата.",
            "Кто такой Иммануил Кант и в чем суть категорического императива?",
            "Рассуждай, как Сократ или Фридрих Ницше.",
            "Напиши эссе в духе Федора Достоевского.",
            "В манере Антона Чехова опиши ружье на стене."
        ]
        for s in samples:
            masked, _, mapping = self.masker.mask(s)
            self.assertEqual(len(mapping), 0, f"Известная личность в роли/стиле не должна маскироваться: {s} -> {masked}")
            self.assertEqual(masked, s)

    def test_poet_in_banking_intent_is_masked(self):
        samples = [
            ("Переведи 5000 рублей Пушкину на карту 2200 1234 5678 9019", "Пушкину"),
            ("Скинь Ницше 1500 руб по номеру +79991234567", "Ницше"),
            ("Клиент: Маяковский Владимир Владимирович, оформил заявку на кредит", "Маяковский Владимир Владимирович"),
            ("Заблокируй карту на имя Льва Толстого срочно!", "Льва Толстого"),
            ("Списать комиссию со счета Сергея Есенина", "Сергея Есенина"),
            ("Получатель платежа: Альберт Эйнштейн, счет закрыт", "Альберт Эйнштейн"),
        ]
        for text, person in samples:
            masked, _, mapping = self.masker.mask(text)
            self.assertIn(person, mapping.values(), f"Личность в банковском интенте ОБЯЗАНА быть замаскирована: {text}")
            self.assertNotIn(person, masked, f"Оригинальное имя {person} не должно присутствовать в открытом виде")
            unmasked = self.masker.unmask(masked, mapping)
            self.assertEqual(unmasked, text, "100% обратимость должна сохраняться")

    def test_dual_coexistence_roleplay_and_banking(self):
        text = "Ты, как Александр Пушкин, переведи 5000 рублей Льву Толстому на карту 2200 1234 5678 9019"
        masked, _, mapping = self.masker.mask(text)
        
        # Александр Пушкин (ролевая метафора) должен остаться открытым
        self.assertIn("Александр Пушкин", masked)
        # Лев Толстой (получатель денег) должен быть замаскирован
        self.assertIn("Льву Толстому", mapping.values())
        self.assertNotIn("Льву Толстому", masked)
        # Карта должна быть замаскирована
        self.assertIn("2200 1234 5678 9019", mapping.values())
        
        # Проверка обратимости
        self.assertEqual(self.masker.unmask(masked, mapping), text)


class TestDiverseFormattingAndUnconventionalFields(unittest.TestCase):
    """
    Тестирование устойчивости к безумным форматам записи (пробелы, точки, слэши,
    нестандартный синтаксис, разговорная речь).
    """

    def setUp(self):
        self.masker = NatashaPIIMasker()

    def test_unconventional_phones(self):
        cases = [
            ("Позвони мне на +7 (903) 123-45-67 завтра", "+7 (903) 123-45-67"),
            ("Связь по тел. 8.916.234.56.78 срочно", "8.916.234.56.78"),
            ("Номер для связи 007-925-345-67-89", "007-925-345-67-89"),
            ("Моб: 8_999_888_77_66 перезвони", "8_999_888_77_66"),
            ("Мой сотовый 8/902/555/44/33 записал?", "8/902/555/44/33"),
        ]
        for text, expected in cases:
            masked, _, mapping = self.masker.mask(text)
            self.assertIn(expected, mapping.values(), f"Телефон {expected} должен быть извлечен")
            self.assertEqual(self.masker.unmask(masked, mapping), text)

    def test_unconventional_cards_and_inns(self):
        # Карта с точками и дефисами
        text_card = "Оплата картой 2200.1234-5678_9019 на терминале"
        masked_c, _, mapping_c = self.masker.mask(text_card)
        self.assertIn("2200.1234-5678_9019", mapping_c.values())
        self.assertEqual(self.masker.unmask(masked_c, mapping_c), text_card)

        # ИНН с дефисами и разделителями
        text_inn = "Контрагент указал ИНН: 77-07-08389-3 в акте"
        masked_i, _, mapping_i = self.masker.mask(text_inn)
        self.assertIn("77-07-08389-3", mapping_i.values())
        self.assertEqual(self.masker.unmask(masked_i, mapping_i), text_inn)

    def test_conversational_freeform_ticket(self):
        ticket = (
            "Привет! Меня зовут Смирнов Алексей Павлович. Родился 15.04.1989 в Самаре. "
            "Живу в Москве на ул. Тверская 12, кв. 45. Паспорт получал в отделе УФМС по г. Москве 12.05.2015, "
            "серия 45 12 № 789456, код подразделения 770-001. "
            "Почта alex.smirnov@example.com, сотовый +7 926 777-88-99. "
            "Переведите 10000 руб с карты 2200 1234 5678 9019 на счет."
        )
        vault = ZeroPiiVault()
        masked, s_id, mapping = vault.mask_text(ticket)
        
        # Проверяем, что все ключевые типы ПДн были обнаружены
        keys_str = " ".join(mapping.keys())
        self.assertIn("[FIO_", keys_str)
        self.assertIn("[BIRTHDATE_", keys_str)
        self.assertIn("[BIRTHPLACE_", keys_str)
        self.assertIn("[ADDRESS_", keys_str)
        self.assertIn("[PASSPORT_", keys_str)
        self.assertIn("[PASSPORT_CODE_", keys_str)
        self.assertIn("[PASSPORT_ISSUER_", keys_str)
        self.assertIn("[EMAIL_", keys_str)
        self.assertIn("[PHONE_", keys_str)
        self.assertIn("[CARD_", keys_str)

        # Проверка 100% обратимости
        unmasked = vault.unmask_text(masked, s_id)
        self.assertEqual(unmasked, ticket, "Обратный текст должен быть 100% идентичен оригиналу")


if __name__ == "__main__":
    unittest.main(verbosity=2)
