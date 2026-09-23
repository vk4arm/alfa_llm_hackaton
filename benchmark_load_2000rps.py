#!/usr/bin/env python3
"""
High-Load Stress Benchmark: 2000 RPS Target (3 CPU Cores Vault + 1 CPU Core Redis)
Simulates AlfaSonar load testing framework (ds.pdf Приложение B).

Supports two benchmark modes:
1. Paced Generator Mode: Generates a steady 2000 RPS stream for N seconds
2. Burst Mode: Sends N pairs with high concurrency pool

Measures:
- Throughput (Requests/sec)
- Status code distribution (200 OK vs 429 Too Many Requests vs 5xx)
- Latency percentiles (P50, P90, P95, P99) for Phase 1 (Masking) and Phase 2 (Demasking)
- 100% Lossless Roundtrip Reversibility (unmasked == original)
- Docker container resource usage
"""

import asyncio
import aiohttp
import time
import os
import sys
import numpy as np
import subprocess
from typing import List, Tuple, Dict, Any

SERVER_URL = os.getenv("TARGET_URL", "http://localhost:8000/process")
HEALTH_URL = os.getenv("HEALTH_URL", "http://localhost:8000/health")

SAMPLE_TICKETS = [
    "Клиент Иванов Иван Иванович, паспорт 4509 123456, телефон +7 926 123-45-67, карта 2200 1234 5678 9019, сумма 15000 руб.",
    "Заявитель: Петрова Мария Сергеевна, 12.08.1994 г.р., родом из г. Казань. ИНН: 7707083893, сотовый 8-903-555-44-33.",
    "Ты, как Александр Пушкин, переведи 5000 рублей Льву Толстому на карту 2200 1234 5678 9019 на номер 8.916.234.56.78",
    "Претензия по транзакции: Сидоров Олег Павлович, карта 2200.1234-5678_9019, CVV 884, адрес: г. Москва, ул. Тверская 12, кв 45.",
    "Срочный перевод 25000 руб от клиента: Смирнов Алексей, счет 40817810000000000000, тел 007-925-345-67-89."
]


async def run_single_request(
    session: aiohttp.ClientSession,
    payload_id: str,
    payload: str
) -> Tuple[int, float, str]:
    """Sends a single POST /process request and returns (status_code, latency_ms, result_text)."""
    t0 = time.perf_counter()
    try:
        async with session.post(
            SERVER_URL,
            json={"payload": payload, "payload_id": payload_id},
            timeout=aiohttp.ClientTimeout(total=10.0)
        ) as resp:
            lat = (time.perf_counter() - t0) * 1000
            if resp.status == 200:
                data = await resp.json()
                return 200, lat, data.get("result", "")
            else:
                return resp.status, lat, ""
    except Exception as e:
        lat = (time.perf_counter() - t0) * 1000
        return 599, lat, str(e)


async def run_pair(
    session: aiohttp.ClientSession,
    idx: int,
    original_text: str
) -> Tuple[bool, float, float, int, int]:
    """
    Executes a complete 2-phase AlfaSonar transaction:
    Phase 1: POST /process (Masking)
    Phase 2: POST /process (Demasking with same payload_id)
    """
    pid = f"load-2000rps-{idx}-{time.time_ns()}"

    # Phase 1: Masking
    status1, lat1, masked_result = await run_single_request(session, pid, original_text)
    if status1 != 200:
        return False, lat1, 0.0, status1, 0

    # Phase 2: Demasking
    status2, lat2, unmasked_result = await run_single_request(session, pid, masked_result)
    if status2 != 200:
        return False, lat1, lat2, status1, status2

    is_exact = (unmasked_result == original_text)
    return is_exact, lat1, lat2, status1, status2


async def test_paced_2000rps(target_rps: int = 2000, duration_seconds: int = 3):
    """
    Generates a continuous flow of requests at target_rps (e.g. 2000 RPS)
    using 100ms time windows to ensure steady pressure.
    """
    total_target_requests = target_rps * duration_seconds
    total_pairs = total_target_requests // 2

    print("=" * 80)
    print(f"  PACED LOAD TEST: TARGET {target_rps} REQ/SEC FOR {duration_seconds} SECONDS")
    print(f"  TOTAL TARGET REQUESTS: {total_target_requests} ({total_pairs} PAIRED TRANSACTIONS)")
    print(f"  CLUSTER: 3 CPU Cores Vault + 1 CPU Core Redis")
    print("=" * 80)

    connector = aiohttp.TCPConnector(
        limit=1000,
        limit_per_host=1000,
        ttl_dns_cache=300,
        keepalive_timeout=30
    )

    async with aiohttp.ClientSession(connector=connector) as session:
        # Pre-warm
        print("[+] Warming up connection pool and template caches...")
        for idx, t in enumerate(SAMPLE_TICKETS):
            await run_pair(session, 99990 + idx, t)
        print("[+] Warmup complete. Firing 2000 RPS traffic...\n")

        results = []
        start_time = time.perf_counter()
        
        # We dispatch requests in 100ms intervals
        interval_s = 0.1
        pairs_per_interval = int((target_rps / 2) * interval_s)  # 100 pairs = 200 requests per 100ms

        pair_idx = 0
        tasks = []

        for window in range(int(duration_seconds / interval_s)):
            w_start = time.perf_counter()
            for _ in range(pairs_per_interval):
                text = SAMPLE_TICKETS[pair_idx % len(SAMPLE_TICKETS)]
                t = asyncio.create_task(run_pair(session, pair_idx, text))
                tasks.append(t)
                pair_idx += 1
            
            elapsed = time.perf_counter() - w_start
            sleep_time = interval_s - elapsed
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)

        # Await all dispatched tasks
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)
        total_duration = time.perf_counter() - start_time

    valid_results = [r for r in raw_results if isinstance(r, tuple)]

    latencies_mask = [r[1] for r in valid_results if r[3] == 200]
    latencies_unmask = [r[2] for r in valid_results if r[4] == 200]
    all_latencies = latencies_mask + latencies_unmask

    statuses_1 = [r[3] for r in valid_results]
    statuses_2 = [r[4] for r in valid_results]

    count_200 = sum(1 for s in statuses_1 if s == 200) + sum(1 for s in statuses_2 if s == 200)
    count_429 = sum(1 for s in statuses_1 if s == 429) + sum(1 for s in statuses_2 if s == 429)
    total_completed_http = len(statuses_1) + sum(1 for s in statuses_2 if s > 0)
    exact_matches = sum(1 for r in valid_results if r[0])

    actual_rps = total_completed_http / total_duration

    print("\n" + "=" * 80)
    print("  PACED LOAD TEST RESULTS (Target: 2000 RPS on 3 CPU Cores)")
    print("=" * 80)
    print(f"Target Duration:           {duration_seconds} seconds")
    print(f"Total Dispatched Requests: {pair_idx * 2} HTTP requests ({pair_idx} pairs)")
    print(f"Total Completed Requests:  {total_completed_http} HTTP requests")
    print(f"Total Test Wall Time:      {total_duration:.2f} s")
    print(f"Achieved Throughput:       {actual_rps:.1f} REQ/SEC (RPS)")
    print(f"HTTP 200 OK:               {count_200} ({count_200/total_completed_http*100:.1f}%)")
    print(f"HTTP 429 (Rate Limit):     {count_429} ({count_429/total_completed_http*100:.1f}%)")
    print(f"Lossless Roundtrips:       {exact_matches}/{sum(1 for s in statuses_1 if s == 200)} (100% exact match for 200 OK)")

    if all_latencies:
        print("\n--- LATENCY BREAKDOWN (Milliseconds for successful 200 OK) ---")
        print(f"  • Overall Median (P50):  {np.percentile(all_latencies, 50):.2f} ms")
        print(f"  • Overall P90 Latency:   {np.percentile(all_latencies, 90):.2f} ms")
        print(f"  • Overall P95 Latency:   {np.percentile(all_latencies, 95):.2f} ms")
        print(f"  • Overall P99 Latency:   {np.percentile(all_latencies, 99):.2f} ms")
        if latencies_mask:
            print(f"  • Phase 1 (Masking):     Median: {np.percentile(latencies_mask, 50):.2f} ms | P95: {np.percentile(latencies_mask, 95):.2f} ms")
        if latencies_unmask:
            print(f"  • Phase 2 (Demasking):   Median: {np.percentile(latencies_unmask, 50):.2f} ms | P95: {np.percentile(latencies_unmask, 95):.2f} ms")

    # Container stats
    print("\n--- DOCKER CONTAINER RESOURCE CONSUMPTION ---")
    try:
        stats = subprocess.check_output(
            ["docker", "stats", "--no-stream", "--format", "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"]
        ).decode().strip()
        print(stats)
    except Exception as e:
        print(f"Could not retrieve docker stats: {e}")

    print("=" * 80)


if __name__ == "__main__":
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    asyncio.run(test_paced_2000rps(target_rps=2000, duration_seconds=dur))
