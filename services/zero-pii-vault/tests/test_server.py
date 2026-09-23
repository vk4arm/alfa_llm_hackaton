"""
Интеграционные тесты для FastAPI сервера POST /process (Zero-PII Vault).
Проверяют строгое соответствие контракту OpenAPI (Приложение A и B в ds.pdf):
1. Двухфазная корреляция по payload_id:
   - Фаза 1 (Маскирование): {payload, payload_id} -> {result: <маска>}
   - Фаза 2 (Демаскирование): {payload: <маска>, payload_id} -> {result: <исходная строка>}
2. Идемпотентность и устойчивость к ретраям (повторные вызовы Фазы 1 возвращают тот же результат).
3. Обработка ролевых запросов (поэты не маскируются) vs реальных банковских поручений (маскируются).
4. Защита от пустых payload_id и валидация схемы JSON.
5. Проверка работоспособности эндпоинта /health.
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from server import app


class TestProcessApiContract(unittest.TestCase):
    """Тестирование соответствия контракту POST /process."""

    @classmethod
    def setUpClass(cls):
        # Используем TestClient в контексте lifespan (запуск воркеров и структур)
        cls.client_ctx = TestClient(app)
        cls.client = cls.client_ctx.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client_ctx.__exit__(None, None, None)

    def test_health_endpoint(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "UP")
        self.assertIn("workers", data)
        self.assertIn("active_sessions", data)

    def test_two_phase_mask_and_demask(self):
        pid = "test-session-contract-001"
        original = "Клиент Смирнов Алексей Павлович, паспорт 4512 789456, сотовый +7 926 777-88-99, карта 2200 1234 5678 9019"

        # --- ФАЗА 1: Маскирование (Прямой шаг) ---
        req1 = {"payload": original, "payload_id": pid}
        resp1 = self.client.post("/process", json=req1)
        self.assertEqual(resp1.status_code, 200, f"Ошибка Фазы 1: {resp1.text}")
        data1 = resp1.json()
        self.assertIn("result", data1)
        masked_result = data1["result"]

        # Проверяем, что ПДн скрыты токенами
        self.assertNotIn("Смирнов Алексей Павлович", masked_result)
        self.assertNotIn("4512 789456", masked_result)
        self.assertNotIn("+7 926 777-88-99", masked_result)
        self.assertNotIn("2200 1234 5678 9019", masked_result)
        self.assertIn("[FIO_", masked_result)
        self.assertIn("[PASSPORT_", masked_result)
        self.assertIn("[PHONE_", masked_result)
        self.assertIn("[CARD_", masked_result)

        # --- ИДЕМПОТЕНТНЫЙ РЕТРАЙ ФАЗЫ 1 ---
        # Если клиент из-за сбоя сети шлет запрос повторно — должен вернуться тот же результат
        resp_retry = self.client.post("/process", json=req1)
        self.assertEqual(resp_retry.status_code, 200)
        self.assertEqual(resp_retry.json()["result"], masked_result)

        # --- ФАЗА 2: Демаскирование (Обратный шаг) ---
        req2 = {"payload": masked_result, "payload_id": pid}
        resp2 = self.client.post("/process", json=req2)
        self.assertEqual(resp2.status_code, 200, f"Ошибка Фазы 2: {resp2.text}")
        data2 = resp2.json()
        self.assertIn("result", data2)
        unmasked_result = data2["result"]

        # Исходный текст должен восстановиться 1:1 побайтово
        self.assertEqual(unmasked_result, original, "Восстановленный текст обязан совпадать с оригиналом на 100%")

    def test_roleplay_poet_preservation(self):
        pid = "roleplay-pushkin-002"
        prompt = "Ты, как Александр Пушкин, напиши четверостишие о зимнем утре."

        # Фаза 1: имя Пушкина в роли НЕ должно маскироваться
        resp = self.client.post("/process", json={"payload": prompt, "payload_id": pid})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["result"], prompt)

    def test_poet_in_banking_transaction(self):
        pid = "banking-pushkin-003"
        prompt = "Переведи 5000 рублей Пушкину на карту 2200 1234 5678 9019"

        # Фаза 1: Пушкин как получатель перевода ОБЯЗАН быть замаскирован
        resp1 = self.client.post("/process", json={"payload": prompt, "payload_id": pid})
        self.assertEqual(resp1.status_code, 200)
        masked = resp1.json()["result"]
        self.assertNotIn("Пушкину", masked)
        self.assertIn("[FIO_", masked)
        self.assertIn("[CARD_", masked)

        # Фаза 2: Точное демаскирование
        resp2 = self.client.post("/process", json={"payload": masked, "payload_id": pid})
        self.assertEqual(resp2.status_code, 200)
        self.assertEqual(resp2.json()["result"], prompt)

    def test_empty_payload_id_validation(self):
        resp = self.client.post("/process", json={"payload": "Привет", "payload_id": ""})
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
