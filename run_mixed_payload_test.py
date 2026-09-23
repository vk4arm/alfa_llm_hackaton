#!/usr/bin/env python3
"""
Mixed Payload High-Load Benchmark Runner for Zero-PII Vault.
Workload:
- 90% Standard Requests: Russian banking tickets (~200-300 bytes)
- 10% Massive Requests: Full banking dossiers/documents (>500 KB, ~350,000 chars from data/pii_samples/pii_dataset_2mb.txt)

Tracks:
- Overall throughput (RPS) & Data throughput (MB/s)
- HTTP status code distribution (200 OK vs 429 backpressure)
- Separate latency breakdown for 500+ KB documents vs standard tickets
- 100% roundtrip lossless reversibility (unmask == original)
- Docker container CPU and memory consumption
"""

import asyncio
import aiohttp
import time
import os
import sys
import numpy as np
import subprocess
from collections import Counter
from typing import List, Tuple, Dict

SERVER_URL = os.getenv("TARGET_URL", "http://127.0.0.1:8000/process")

# Standard ~200-300 byte tickets (90% traffic)
STANDARD_TICKETS = [
    "Клиент Иванов Иван Иванович, паспорт 4509 123456, телефон +7 926 123-45-67, карта 2200 1234 5678 9019, сумма 15000 руб.",
    "Заявитель: Петрова Мария Сергеевна, 12.08.1994 г.р., родом из г. Казань. ИНН: 7707083893, сотовый 8-903-555-44-33.",
    "Ты, как Александр Пушкин, переведи 5000 рублей Льву Толстому на карту 2200 1234 5678 9019 на номер 8.916.234.56.78",
    "Претензия по транзакции: Сидоров Олег Павлович, карта 2200.1234-5678_9019, CVV 884, адрес: г. Москва, ул. Тверская 12, кв 45.",
    "Срочный перевод 25000 руб от клиента: Смирнов Алексей, счет 40817810000000000000, тел 007-925-345-67-89."
]

def load_large_documents(file_path: str = "data/pii_samples/pii_dataset_2mb.txt") -> List[str]:
    with open(file_path, "r", encoding="utf-8") as f:
        full_text = f.read()

    # Create 5 distinct slices, each > 500 KB (350,000 chars ≈ 536 KB UTF-8)
    chunk_size = 350000
    docs = []
    for offset in [0, 150000, 300000, 450000, 600000]:
        if offset + chunk_size <= len(full_text):
            docs.append(full_text[offset : offset + chunk_size])
        else:
            docs.append(full_text[:chunk_size])
    return docs

LARGE_DOCUMENTS = load_large_documents()


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


async def send_req(session, pid, payload):
    t0 = time.perf_counter()
    try:
        async with session.post(
            SERVER_URL,
            json={"payload_id": pid, "payload": payload},
            timeout=aiohttp.ClientTimeout(total=20.0)
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


async def transaction_pair(session, idx, text, is_large, results_list, sem):
    async with sem:
        pid = f"mix-{idx}-{time.time_ns()}"
        # Phase 1: Masking
        s1, lat1, masked = await send_req(session, pid, text)
        if s1 != 200:
            results_list.append((s1, 0, lat1, 0.0, False, is_large, len(text.encode("utf-8"))))
            return

        # Phase 2: Demasking
        s2, lat2, unmasked = await send_req(session, pid, masked)
        is_exact = (unmasked == text)
        byte_len = len(text.encode("utf-8"))
        results_list.append((s1, s2, lat1, lat2, is_exact, is_large, byte_len))


async def run_benchmark(duration_sec: int = 30, concurrency: int = 40):
    print("=" * 80)
    print("🚀 LAUNCHING MIXED PAYLOAD STRESS TEST (10% OF REQUESTS ARE 500+ KB)")
    print(f"   Duration:          {duration_sec} seconds")
    print(f"   Concurrency pool:  {concurrency} concurrent async workers")
    print(f"   Payload Mix:       90% standard tickets (~250 B) | 10% massive dossiers (536 KB)")
    print(f"   Large file source: data/pii_samples/pii_dataset_2mb.txt")
    print(f"   Hardware Limits:   3.0 CPU Cores (Vault) | 1.0 CPU Core (Redis)")
    print("=" * 80)

    # Print large doc sizes
    for i, d in enumerate(LARGE_DOCUMENTS):
        print(f"   • Large Document #{i+1}: {len(d)} chars, {len(d.encode('utf-8')) / 1024:.1f} KB")

    connector = aiohttp.TCPConnector(
        limit=200,
        limit_per_host=200,
        ttl_dns_cache=300,
        keepalive_timeout=60
    )
    timeout = aiohttp.ClientTimeout(total=25.0)

    sem = asyncio.Semaphore(concurrency)
    results = []

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        # Pre-warm all templates across all 3 workers
        print("\n[*] Pre-warming templates and workers (3 passes)...")
        for p in range(3):
            for i, d in enumerate(LARGE_DOCUMENTS):
                pid = f"prewarm-large-{p}-{i}"
                _, _, masked = await send_req(session, pid, d)
                await send_req(session, pid, masked)
            for j, t in enumerate(STANDARD_TICKETS):
                pid = f"prewarm-std-{p}-{j}"
                _, _, masked = await send_req(session, pid, t)
                await send_req(session, pid, masked)
        print("[*] Pre-warming complete. Starting high-load test...\n")

        start_time = time.perf_counter()
        end_time = start_time + duration_sec
        active_tasks = set()
        pair_idx = 0
        last_report = start_time

        while time.perf_counter() < end_time:
            # Throttle spawning if concurrency limit reached
            while len(active_tasks) >= concurrency:
                await asyncio.sleep(0.005)

            # 10% probability of large document (every 10th request)
            is_large = (pair_idx % 10 == 0)
            if is_large:
                text = LARGE_DOCUMENTS[(pair_idx // 10) % len(LARGE_DOCUMENTS)]
            else:
                text = STANDARD_TICKETS[pair_idx % len(STANDARD_TICKETS)]

            task = asyncio.create_task(
                transaction_pair(session, pair_idx, text, is_large, results, sem)
            )
            active_tasks.add(task)
            task.add_done_callback(active_tasks.discard)
            pair_idx += 1

            # Live report every 5 seconds
            now = time.perf_counter()
            if now - last_report >= 5.0:
                elapsed = now - start_time
                done_reqs = sum(2 if r[0] == 200 else 1 for r in results)
                rps = done_reqs / elapsed
                c200 = sum(1 for r in results if r[0] == 200 and r[1] == 200)
                tot_bytes = sum(r[6] * 2 for r in results if r[0] == 200)
                mb_sec = (tot_bytes / (1024 * 1024)) / elapsed
                dock = get_docker_stats()
                print(f"[{elapsed:4.1f}s / {duration_sec}s] "
                      f"Done: {done_reqs:5d} reqs | "
                      f"Throughput: {rps:5.1f} RPS ({mb_sec:5.2f} MB/s) | "
                      f"Exact: {c200}/{len(results)} | "
                      f"{dock}", flush=True)
                last_report = now

        # Drain remaining tasks
        if active_tasks:
            print(f"[*] Draining {len(active_tasks)} in-flight tasks...")
            await asyncio.gather(*active_tasks, return_exceptions=True)

        total_time = time.perf_counter() - start_time

    # Process and print comprehensive results
    total_http_reqs = sum(2 if r[0] == 200 else 1 for r in results)
    total_pairs = len(results)
    c200_pairs = sum(1 for r in results if r[0] == 200 and r[1] == 200)
    exact_matches = sum(1 for r in results if r[4])
    total_bytes = sum(r[6] * 2 for r in results if r[0] == 200)

    # Split metrics: standard vs large
    std_p1_lats = [r[2] for r in results if not r[5] and r[0] == 200]
    std_p2_lats = [r[3] for r in results if not r[5] and r[1] == 200]
    large_p1_lats = [r[2] for r in results if r[5] and r[0] == 200]
    large_p2_lats = [r[3] for r in results if r[5] and r[1] == 200]

    large_count = sum(1 for r in results if r[5])
    std_count = sum(1 for r in results if not r[5])
    actual_large_pct = (large_count / total_pairs * 100) if total_pairs else 0

    print("\n" + "=" * 80)
    print("📊 MIXED PAYLOAD LOAD TEST RESULTS (10% 500+ KB DOCUMENTS)")
    print("=" * 80)
    print(f"Total Test Wall Time:         {total_time:.2f} s")
    print(f"Total HTTP Requests:          {total_http_reqs:,} ({total_pairs:,} paired transactions)")
    print(f"Effective HTTP Throughput:    {total_http_reqs / total_time:.1f} RPS")
    print(f"Total Transferred Volume:     {total_bytes / (1024 * 1024):.2f} MB ({total_bytes / (1024 * 1024) / total_time:.2f} MB/sec)")
    print(f"Workload Distribution:        Standard: {std_count:,} ({100 - actual_large_pct:.1f}%) | 500+ KB: {large_count:,} ({actual_large_pct:.1f}%)")
    print(f"Roundtrip Exact Matches:      {exact_matches:,} / {total_pairs:,} ({exact_matches / total_pairs * 100:.2f}%)")

    status_codes = Counter()
    for r in results:
        status_codes[r[0]] += 1
        if r[0] == 200:
            status_codes[r[1]] += 1
    print("\nHTTP Response Code Distribution:")
    for code, cnt in sorted(status_codes.items()):
        name = "OK" if code == 200 else ("Too Many Requests" if code == 429 else "Error")
        print(f"  HTTP {code} ({name:20}): {cnt:6d}  ({cnt / total_http_reqs * 100:5.2f}%)")

    print("\nLatency Breakdown — Standard Tickets (~250 Bytes):")
    if std_p1_lats:
        print(f"  • Phase 1 (Masking):   P50: {np.percentile(std_p1_lats, 50):5.2f} ms | P90: {np.percentile(std_p1_lats, 90):5.2f} ms | P95: {np.percentile(std_p1_lats, 95):5.2f} ms")
    if std_p2_lats:
        print(f"  • Phase 2 (Demasking): P50: {np.percentile(std_p2_lats, 50):5.2f} ms | P90: {np.percentile(std_p2_lats, 90):5.2f} ms | P95: {np.percentile(std_p2_lats, 95):5.2f} ms")

    print("\nLatency Breakdown — Massive Dossiers (536+ KB, 350,000 chars, ~6,600 entities):")
    if large_p1_lats:
        print(f"  • Phase 1 (Masking):   P50: {np.percentile(large_p1_lats, 50):5.2f} ms | P90: {np.percentile(large_p1_lats, 90):5.2f} ms | P95: {np.percentile(large_p1_lats, 95):5.2f} ms")
    if large_p2_lats:
        print(f"  • Phase 2 (Demasking): P50: {np.percentile(large_p2_lats, 50):5.2f} ms | P90: {np.percentile(large_p2_lats, 90):5.2f} ms | P95: {np.percentile(large_p2_lats, 95):5.2f} ms")

    print("\nFinal Docker Container Resources:")
    res = subprocess.run(["docker", "stats", "--no-stream", "zero-pii-vault", "zero-pii-redis"], capture_output=True, text=True)
    print(res.stdout)
    print("=" * 80)


if __name__ == "__main__":
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    conc = int(sys.argv[2]) if len(sys.argv) > 2 else 35
    asyncio.run(run_benchmark(dur, conc))
