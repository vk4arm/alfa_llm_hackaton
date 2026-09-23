#!/usr/bin/env python3
"""
5-Minute Sustained 2000 RPS Load Test Runner for Zero-PII Vault with 10% Large Texts (450+ Chars).

Workload Breakdown:
- 90% Standard Requests: Russian banking tickets & fast operations (< 250 characters).
- 10% Large Requests: Full Russian banking dossiers & applications (450+ characters, 734-1056 chars)
  loaded from data/pii_samples/pii_dataset_2mb.txt.

Target:
- 2000 HTTP requests / second (1000 paired E2E sessions / second).
- Duration: 300 seconds (5.0 minutes).
- Total target requests: 600,000 HTTP requests (300,000 paired E2E sessions: 270,000 standard, 30,000 large).

Cluster Limits:
- 3.0 CPU Cores (zero-pii-vault)
- 1.0 CPU Core (zero-pii-redis)
"""

import asyncio
import aiohttp
import time
import os
import sys
import numpy as np
import subprocess
from collections import Counter
from typing import List, Tuple

SERVER_URL = os.getenv("TARGET_URL", "http://161.104.59.60/process")
HEALTH_URL = os.getenv("HEALTH_URL", "http://161.104.59.60/health")

STANDARD_TICKETS = [
    # 1. Запрос на перевод
    "Клиент Иванов Иван Иванович, паспорт 4509 123456, телефон +7 926 123-45-67, карта 2200 1234 5678 9019, сумма 15000 руб.",
    # 2. Идентификация и ИНН
    "Заявитель: Петрова Мария Сергеевна, 12.08.1994 г.р., родом из г. Казань. ИНН: 7707083893, сотовый 8-903-555-44-33.",
    # 3. Ролевой запрос (метафора vs интент)
    "Ты, как Александр Пушкин, переведи 5000 рублей Льву Толстому на карту 2200 1234 5678 9019 на номер 8.916.234.56.78",
    # 4. Претензия по транзакции
    "Претензия по транзакции: Сидоров Олег Павлович, карта 2200.1234-5678_9019, CVV 884, адрес: г. Москва, ул. Тверская 12, кв 45.",
    # 5. Срочный перевод со счета
    "Срочный перевод 25000 руб от клиента: Смирнов Алексей, счет 40817810000000000000, тел 007-925-345-67-89.",
    # 6. Строчное ФИО клиента
    "От клиента: кузнецов дмитрий николаевич, паспорт 4515 987654, карта 5469 1122 3344 5566, сумма 30000 руб.",
    # 7. Блокировка карты ALL CAPS
    "СРОЧНО ЗАБЛОКИРУЙТЕ КАРТУ 2200 9876 5432 1098 ВЛАДЕЛЕЦ: АНДРЕЕВ РОМАН ПАВЛОВИЧ, ТЕЛЕФОН +7 916 333-22-11.",
    # 8. Баланс по водительскому удостоверению
    "Водительское удостоверение: 77 12 654321, клиент Васильев Илья Сергеевич, телефон 8-926-777-88-99, баланс счета.",
    # 9. Обращение в саппорт строчными буквами
    "здравствуйте, я козлов михаил сергеевич, д.р. 14.05.1990, номер карты 4154 3322 1100 4455, cvv 492, разблокируйте.",
    # 10. Запрос справки по кредиту
    "Заемщик: Морозова Ольга Владимировна, паспорт 4508 654321, email: morozova.olga@mail.ru, выписка по счету."
]


def load_large_records() -> List[str]:
    """Loads all records >= 450 characters from the newly regenerated 2MB dataset."""
    file_path = "data/pii_samples/pii_dataset_2mb.txt"
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Missing {file_path}. Run data/create_datasets.py first!")
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    records = [r.strip() for r in content.split("=" * 80) if len(r.strip()) >= 450]
    print(f"[*] Loaded {len(records)} large banking records (450+ chars, range {min(len(r) for r in records)}-{max(len(r) for r in records)} chars).", flush=True)
    return records


def get_docker_stats() -> str:
    try:
        res = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{.Name}}: CPU {{.CPUPerc}}, MEM {{.MemUsage}}", "zero-pii-vault", "zero-pii-redis"],
            capture_output=True, text=True, timeout=3.0
        )
        lines = [line.strip() for line in res.stdout.strip().split("\n") if line.strip()]
        return " | ".join(lines)
    except Exception:
        return "stats unavailable"


class MetricsTracker:
    def __init__(self):
        self.lock = asyncio.Lock()
        self.total_completed_pairs = 0
        self.total_http_requests = 0
        self.status_counts = Counter()
        self.exact_matches = 0
        
        # Breakdown by category
        self.std_pairs = 0
        self.std_exact = 0
        self.large_pairs = 0
        self.large_exact = 0

        # Sampled latencies (1 in every 25 pairs)
        self.std_lat_p1 = []
        self.std_lat_p2 = []
        self.large_lat_p1 = []
        self.large_lat_p2 = []
        
        self.sample_interval = 25
        self.start_time = 0.0

    async def record_pair(self, s1: int, s2: int, lat1: float, lat2: float, is_exact: bool, is_large: bool):
        async with self.lock:
            self.total_completed_pairs += 1
            self.total_http_requests += (2 if s1 == 200 else 1)
            self.status_counts[s1] += 1
            if s1 == 200:
                self.status_counts[s2] += 1
                if is_exact:
                    self.exact_matches += 1

            if is_large:
                self.large_pairs += 1
                if is_exact:
                    self.large_exact += 1
            else:
                self.std_pairs += 1
                if is_exact:
                    self.std_exact += 1

            if self.total_completed_pairs % self.sample_interval == 0:
                if s1 == 200:
                    if is_large:
                        self.large_lat_p1.append(lat1)
                        if s2 == 200:
                            self.large_lat_p2.append(lat2)
                    else:
                        self.std_lat_p1.append(lat1)
                        if s2 == 200:
                            self.std_lat_p2.append(lat2)


async def send_req(session, pid, payload):
    t0 = time.perf_counter()
    try:
        async with session.post(
            SERVER_URL,
            json={"payload_id": pid, "payload": payload},
            timeout=aiohttp.ClientTimeout(total=8.0)
        ) as resp:
            lat = (time.perf_counter() - t0) * 1000
            if resp.status == 200:
                data = await resp.json()
                return resp.status, lat, data.get("result", "")
            else:
                return resp.status, lat, ""
    except asyncio.TimeoutError:
        return 408, (time.perf_counter() - t0) * 1000, "TIMEOUT"
    except Exception as e:
        return 599, (time.perf_counter() - t0) * 1000, str(e)


async def transaction_pair(session, idx, original_text, is_large, tracker, inflight_sem):
    async with inflight_sem:
        pid = f"load2k-10pct-{idx}-{time.time_ns()}"
        # Phase 1: Masking
        s1, lat1, masked = await send_req(session, pid, original_text)
        if s1 != 200:
            await tracker.record_pair(s1, 0, lat1, 0.0, False, is_large)
            return

        # Phase 2: Demasking
        s2, lat2, unmasked = await send_req(session, pid, masked)
        is_exact = (unmasked == original_text)
        await tracker.record_pair(s1, s2, lat1, lat2, is_exact, is_large)


async def main():
    target_duration_sec = int(os.getenv("TEST_DURATION_SEC", "300"))  # 300s = 5 minutes
    target_rps = int(os.getenv("TARGET_RPS", "2000"))
    target_pairs_per_sec = target_rps // 2  # 1000 pairs/sec = 2000 req/sec
    batch_interval = 0.05  # 50 ms
    pairs_per_batch = int(target_pairs_per_sec * batch_interval)  # 50 pairs per 50 ms
    total_target_requests = target_rps * target_duration_sec
    total_target_pairs = target_pairs_per_sec * target_duration_sec

    print("=" * 80, flush=True)
    print(f"🔥 LAUNCHING 5-MINUTE 2000 RPS LOAD TEST (10% LARGE TEXTS 450+ CHARS)", flush=True)
    print(f"   Target Request Rate:     {target_rps} requests/second", flush=True)
    print(f"   Target Pair Rate:        {target_pairs_per_sec} paired transactions/second", flush=True)
    print(f"   Target Duration:         {target_duration_sec} seconds (5.0 minutes)", flush=True)
    print(f"   Total Target Requests:   {total_target_requests:,} requests ({total_target_pairs:,} pairs)", flush=True)
    print(f"   Workload Distribution:   90% Standard (<250 chars) | 10% Large (450+ chars)", flush=True)
    print(f"   Hardware Limits:         3.0 CPU Cores (Vault) | 1.0 CPU Core (Redis)", flush=True)
    print("=" * 80, flush=True)

    large_records = load_large_records()

    connector = aiohttp.TCPConnector(
        limit=1000,
        limit_per_host=1000,
        ttl_dns_cache=300,
        keepalive_timeout=60
    )
    timeout = aiohttp.ClientTimeout(total=10.0)

    tracker = MetricsTracker()
    inflight_sem = asyncio.Semaphore(800)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        # Pre-warm
        print("[*] Pre-warming connection pool and server template caches...", flush=True)
        for idx in range(20):
            t = large_records[idx] if idx % 2 == 0 else STANDARD_TICKETS[idx % len(STANDARD_TICKETS)]
            pid = f"prewarm-10pct-{idx}"
            _, _, masked = await send_req(session, pid, t)
            await send_req(session, pid, masked)
        print("[*] Target service warm and healthy. Commencing 5-minute sustained traffic...\n", flush=True)

        tracker.start_time = time.perf_counter()
        start_time = tracker.start_time
        batches_total = int(target_duration_sec / batch_interval)
        last_report_time = start_time
        last_report_reqs = 0

        pair_global_idx = 0
        active_tasks = set()

        for b in range(batches_total):
            for _ in range(pairs_per_batch):
                # Exactly 10% of requests are large texts (450+ chars)
                is_large = (pair_global_idx % 10 == 0)
                if is_large:
                    txt = large_records[(pair_global_idx // 10) % len(large_records)]
                else:
                    txt = STANDARD_TICKETS[pair_global_idx % len(STANDARD_TICKETS)]

                task = asyncio.create_task(
                    transaction_pair(session, pair_global_idx, txt, is_large, tracker, inflight_sem)
                )
                active_tasks.add(task)
                task.add_done_callback(active_tasks.discard)
                pair_global_idx += 1

            now = time.perf_counter()
            elapsed_total = now - start_time
            sleep_time = (b + 1) * batch_interval - elapsed_total
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)

            # Periodic reporting every 20 seconds
            if now - last_report_time >= 20.0:
                period_sec = now - last_report_time
                async with tracker.lock:
                    curr_reqs = tracker.total_http_requests
                    curr_pairs = tracker.total_completed_pairs
                    curr_exact = tracker.exact_matches
                    c200 = tracker.status_counts[200]
                    p1_lat = tracker.std_lat_p1[-100:] if tracker.std_lat_p1 else [0]
                    p2_lat = tracker.std_lat_p2[-100:] if tracker.std_lat_p2 else [0]
                    large_p1 = tracker.large_lat_p1[-50:] if tracker.large_lat_p1 else [0]
                    large_p2 = tracker.large_lat_p2[-50:] if tracker.large_lat_p2 else [0]

                interval_rps = (curr_reqs - last_report_reqs) / period_sec
                cum_rps = curr_reqs / elapsed_total
                pct_200 = (c200 / curr_reqs * 100) if curr_reqs else 100.0
                pct_exact = (curr_exact / curr_pairs * 100) if curr_pairs else 100.0
                p1_med = np.median(p1_lat) if p1_lat else 0.0
                p2_med = np.median(p2_lat) if p2_lat else 0.0
                l_p1_med = np.median(large_p1) if large_p1 else 0.0
                l_p2_med = np.median(large_p2) if large_p2 else 0.0
                dock_stats = get_docker_stats()

                mins, secs = divmod(int(elapsed_total), 60)
                tot_mins = target_duration_sec // 60
                print(
                    f"[{mins:02d}:{secs:02d} / {tot_mins:02d}:00] "
                    f"Done: {curr_reqs:7d} reqs | "
                    f"Rate: {interval_rps:6.1f} RPS (avg {cum_rps:6.1f}) | "
                    f"200 OK: {pct_200:5.1f}% | "
                    f"Exact: {pct_exact:5.1f}% | "
                    f"Std P50: {p1_med:4.1f}ms/{p2_med:4.1f}ms | "
                    f"450+ P50: {l_p1_med:4.1f}ms/{l_p2_med:4.1f}ms | "
                    f"{dock_stats}",
                    flush=True
                )
                last_report_time = now
                last_report_reqs = curr_reqs

        if active_tasks:
            print(f"[*] Waiting for {len(active_tasks)} in-flight tasks to complete...", flush=True)
            await asyncio.gather(*active_tasks, return_exceptions=True)

        final_time = time.perf_counter() - start_time

    # Final summary calculations
    async with tracker.lock:
        total_reqs = tracker.total_http_requests
        total_pairs = tracker.total_completed_pairs
        exact_matches = tracker.exact_matches
        std_p = tracker.std_pairs
        std_ex = tracker.std_exact
        large_p = tracker.large_pairs
        large_ex = tracker.large_exact
        status_counts = dict(tracker.status_counts)
        s_lat_p1 = np.array(tracker.std_lat_p1)
        s_lat_p2 = np.array(tracker.std_lat_p2)
        l_lat_p1 = np.array(tracker.large_lat_p1)
        l_lat_p2 = np.array(tracker.large_lat_p2)

    throughput = total_reqs / final_time

    print("\n" + "=" * 80, flush=True)
    print("📊 5-MINUTE 2000 RPS LOAD TEST (10% 450+ CHARS): FINAL RESULTS", flush=True)
    print("=" * 80, flush=True)
    print(f"Total Test Duration:          {final_time:.2f} seconds ({final_time / 60:.2f} minutes)", flush=True)
    print(f"Total HTTP Requests:          {total_reqs:,}", flush=True)
    print(f"Total Paired E2E Sessions:    {total_pairs:,}", flush=True)
    print(f"Effective Throughput:         {throughput:.1f} RPS", flush=True)
    print(f"Overall Reversibility:        {exact_matches:,} / {total_pairs:,} ({exact_matches / total_pairs * 100:.2f}% exact matches)", flush=True)

    print("\nWorkload Distribution Breakdown:", flush=True)
    pct_std = (std_p / total_pairs * 100) if total_pairs else 0
    pct_lrg = (large_p / total_pairs * 100) if total_pairs else 0
    print(f"  • Standard Tickets (<250 chars): {std_p * 2:,} reqs ({std_p:,} pairs, {pct_std:.1f}%) | Exact: {std_ex:,}/{std_p:,} ({std_ex/std_p*100:.2f}%)", flush=True)
    print(f"  • Large Texts (450+ chars):     {large_p * 2:,} reqs ({large_p:,} pairs, {pct_lrg:.1f}%) | Exact: {large_ex:,}/{large_p:,} ({large_ex/large_p*100:.2f}%)", flush=True)

    print("\nHTTP Response Code Breakdown:", flush=True)
    for code, count in sorted(status_counts.items()):
        name = "OK" if code == 200 else ("Rate Limit (429)" if code == 429 else "Error")
        pct = (count / total_reqs) * 100 if total_reqs else 0
        print(f"  HTTP {code} ({name:20}): {count:7d}  ({pct:5.2f}%)", flush=True)

    print("\nLatency Breakdown — Standard Tickets (<250 Chars):", flush=True)
    if len(s_lat_p1) > 0:
        print(f"  Phase 1 (Masking):   P50: {np.percentile(s_lat_p1, 50):5.2f} ms | P90: {np.percentile(s_lat_p1, 90):5.2f} ms | P95: {np.percentile(s_lat_p1, 95):5.2f} ms | P99: {np.percentile(s_lat_p1, 99):5.2f} ms", flush=True)
    if len(s_lat_p2) > 0:
        print(f"  Phase 2 (Demasking): P50: {np.percentile(s_lat_p2, 50):5.2f} ms | P90: {np.percentile(s_lat_p2, 90):5.2f} ms | P95: {np.percentile(s_lat_p2, 95):5.2f} ms | P99: {np.percentile(s_lat_p2, 99):5.2f} ms", flush=True)

    print("\nLatency Breakdown — Large Texts (450+ Chars, 734-1056 chars):", flush=True)
    if len(l_lat_p1) > 0:
        print(f"  Phase 1 (Masking):   P50: {np.percentile(l_lat_p1, 50):5.2f} ms | P90: {np.percentile(l_lat_p1, 90):5.2f} ms | P95: {np.percentile(l_lat_p1, 95):5.2f} ms | P99: {np.percentile(l_lat_p1, 99):5.2f} ms", flush=True)
    if len(l_lat_p2) > 0:
        print(f"  Phase 2 (Demasking): P50: {np.percentile(l_lat_p2, 50):5.2f} ms | P90: {np.percentile(l_lat_p2, 90):5.2f} ms | P95: {np.percentile(l_lat_p2, 95):5.2f} ms | P99: {np.percentile(l_lat_p2, 99):5.2f} ms", flush=True)

    print("\nDocker Final Stats:", flush=True)
    res = subprocess.run(["docker", "stats", "--no-stream", "zero-pii-vault", "zero-pii-redis"], capture_output=True, text=True)
    print(res.stdout, flush=True)
    print("=" * 80, flush=True)


if __name__ == "__main__":
    asyncio.run(main())
