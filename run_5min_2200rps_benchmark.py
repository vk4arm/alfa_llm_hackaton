#!/usr/bin/env python3
"""
5-Minute Sustained 2200 RPS Load Test Runner for Zero-PII Vault.
Target: 2200 requests per second (1100 paired transactions/second).
Duration: 300 seconds (5 minutes).
Total target requests: 660,000 requests (330,000 paired E2E transactions).
Cluster Limits: 3.0 CPU Cores (zero-pii-vault) | 1.0 CPU Core (zero-pii-redis).
"""

import asyncio
import aiohttp
import time
import os
import sys
import numpy as np
import subprocess
from collections import Counter

SERVER_URL = os.getenv("TARGET_URL", "http://161.104.59.60/process")
HEALTH_URL = os.getenv("HEALTH_URL", "http://161.104.59.60/health")

SAMPLE_TICKETS = [
    "Клиент Иванов Иван Иванович, паспорт 4509 123456, телефон +7 926 123-45-67, карта 2200 1234 5678 9019, сумма 15000 руб.",
    "Заявитель: Петрова Мария Сергеевна, 12.08.1994 г.р., родом из г. Казань. ИНН: 7707083893, сотовый 8-903-555-44-33.",
    "Ты, как Александр Пушкин, переведи 5000 рублей Льву Толстому на карту 2200 1234 5678 9019 на номер 8.916.234.56.78",
    "Претензия по транзакции: Сидоров Олег Павлович, карта 2200.1234-5678_9019, CVV 884, адрес: г. Москва, ул. Тверская 12, кв 45.",
    "Срочный перевод 25000 руб от клиента: Смирнов Алексей, счет 40817810000000000000, тел 007-925-345-67-89."
]


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
        self.sampled_latencies_p1 = []
        self.sampled_latencies_p2 = []
        self.sample_interval = 20  # record latency for 1 in every 20 pairs to keep RAM low
        self.start_time = 0.0

    async def record_pair(self, s1: int, s2: int, lat1: float, lat2: float, is_exact: bool):
        async with self.lock:
            self.total_completed_pairs += 1
            self.total_http_requests += (2 if s1 == 200 else 1)
            self.status_counts[s1] += 1
            if s1 == 200:
                self.status_counts[s2] += 1
                if is_exact:
                    self.exact_matches += 1

            if self.total_completed_pairs % self.sample_interval == 0:
                if s1 == 200:
                    self.sampled_latencies_p1.append(lat1)
                    if s2 == 200:
                        self.sampled_latencies_p2.append(lat2)


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


async def transaction_pair(session, idx, original_text, tracker, inflight_sem):
    async with inflight_sem:
        pid = f"load5m-{idx}-{time.time_ns()}"
        # Phase 1: Masking
        s1, lat1, masked = await send_req(session, pid, original_text)
        if s1 != 200:
            await tracker.record_pair(s1, 0, lat1, 0.0, False)
            return

        # Phase 2: Demasking
        s2, lat2, unmasked = await send_req(session, pid, masked)
        is_exact = (unmasked == original_text)
        await tracker.record_pair(s1, s2, lat1, lat2, is_exact)


async def main():
    target_duration_sec = int(os.getenv("TEST_DURATION_SEC", "300"))  # 300s = 5 minutes
    target_rps = int(os.getenv("TARGET_RPS", "2200"))
    target_pairs_per_sec = target_rps // 2  # 1100 pairs/sec = 2200 req/sec
    batch_interval = 0.05  # 50 ms
    pairs_per_batch = int(target_pairs_per_sec * batch_interval)  # 55 pairs per 50 ms
    total_target_requests = target_rps * target_duration_sec
    total_target_pairs = target_pairs_per_sec * target_duration_sec

    print("=" * 80)
    print(f"🔥 LAUNCHING 5-MINUTE SUSTAINED 2200 RPS LOAD TEST")
    print(f"   Target Request Rate:     {target_rps} requests/second")
    print(f"   Target Pair Rate:        {target_pairs_per_sec} paired transactions/second")
    print(f"   Target Duration:         {target_duration_sec} seconds (5.0 minutes)")
    print(f"   Total Target Requests:   {total_target_requests} requests ({total_target_pairs} pairs)")
    print(f"   Hardware Limits:         3.0 CPU Cores (Vault) | 1.0 CPU Core (Redis)")
    print("=" * 80)

    # TCP Connector with large connection pool
    connector = aiohttp.TCPConnector(
        limit=1000,
        limit_per_host=1000,
        ttl_dns_cache=300,
        keepalive_timeout=60
    )
    timeout = aiohttp.ClientTimeout(total=10.0)

    tracker = MetricsTracker()
    inflight_sem = asyncio.Semaphore(600)  # Bound in-flight concurrent coroutines

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        # Pre-warm
        print("[*] Pre-warming connection pool and server template caches...")
        for idx, t in enumerate(SAMPLE_TICKETS):
            for r in range(2):
                pid = f"prewarm-{idx}-{r}"
                _, _, masked = await send_req(session, pid, t)
                await send_req(session, pid, masked)
        print("[*] Target service warm and healthy. Commencing 5-minute sustained traffic...\n")

        tracker.start_time = time.perf_counter()
        start_time = tracker.start_time
        batches_total = int(target_duration_sec / batch_interval)
        last_report_time = start_time
        last_report_reqs = 0

        pair_global_idx = 0
        active_tasks = set()

        for b in range(batches_total):
            b_start = time.perf_counter()

            for _ in range(pairs_per_batch):
                txt = SAMPLE_TICKETS[pair_global_idx % len(SAMPLE_TICKETS)]
                task = asyncio.create_task(
                    transaction_pair(session, pair_global_idx, txt, tracker, inflight_sem)
                )
                active_tasks.add(task)
                task.add_done_callback(active_tasks.discard)
                pair_global_idx += 1

            now = time.perf_counter()
            elapsed_total = now - start_time
            sleep_time = (b + 1) * batch_interval - elapsed_total
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)

            # Periodic reporting every 30 seconds
            if now - last_report_time >= 30.0:
                period_sec = now - last_report_time
                async with tracker.lock:
                    curr_reqs = tracker.total_http_requests
                    curr_pairs = tracker.total_completed_pairs
                    curr_exact = tracker.exact_matches
                    c200 = tracker.status_counts[200]
                    c429 = tracker.status_counts[429]
                    c5xx = tracker.status_counts[500] + tracker.status_counts[599] + tracker.status_counts[408]
                    p1_lat = tracker.sampled_latencies_p1[-100:] if tracker.sampled_latencies_p1 else [0]
                    p2_lat = tracker.sampled_latencies_p2[-100:] if tracker.sampled_latencies_p2 else [0]

                interval_rps = (curr_reqs - last_report_reqs) / period_sec
                cum_rps = curr_reqs / elapsed_total
                pct_200 = (c200 / curr_reqs * 100) if curr_reqs else 100.0
                pct_exact = (curr_exact / curr_pairs * 100) if curr_pairs else 100.0
                p1_med = np.median(p1_lat) if p1_lat else 0.0
                p2_med = np.median(p2_lat) if p2_lat else 0.0
                dock_stats = get_docker_stats()

                mins, secs = divmod(int(elapsed_total), 60)
                tot_mins = target_duration_sec // 60
                print(
                    f"[{mins:02d}:{secs:02d} / {tot_mins:02d}:00] "
                    f"Done: {curr_reqs:7d} reqs | "
                    f"Rate: {interval_rps:6.1f} RPS (avg {cum_rps:6.1f}) | "
                    f"200 OK: {pct_200:5.1f}% | "
                    f"Exact: {pct_exact:5.1f}% | "
                    f"P50 P1: {p1_med:5.2f}ms, P2: {p2_med:5.2f}ms | "
                    f"{dock_stats}"
                )
                last_report_time = now
                last_report_reqs = curr_reqs

        # Wait for any lingering in-flight tasks to complete
        if active_tasks:
            print(f"[*] Waiting for {len(active_tasks)} lingering in-flight tasks to flush...")
            await asyncio.gather(*active_tasks, return_exceptions=True)

        final_time = time.perf_counter() - start_time

    # Final summary calculations
    async with tracker.lock:
        total_reqs = tracker.total_http_requests
        total_pairs = tracker.total_completed_pairs
        exact_matches = tracker.exact_matches
        status_counts = dict(tracker.status_counts)
        lats_p1 = np.array(tracker.sampled_latencies_p1)
        lats_p2 = np.array(tracker.sampled_latencies_p2)

    throughput = total_reqs / final_time

    print("\n" + "=" * 80)
    print("📊 5-MINUTE SUSTAINED 2200 RPS LOAD TEST: FINAL RESULTS")
    print("=" * 80)
    print(f"Total Test Duration:          {final_time:.2f} seconds ({final_time / 60:.2f} minutes)")
    print(f"Total HTTP Requests:          {total_reqs:,}")
    print(f"Total Paired E2E Sessions:    {total_pairs:,}")
    print(f"Effective Throughput:         {throughput:.1f} RPS")
    print(f"Roundtrip Reversibility:      {exact_matches:,} / {total_pairs:,} ({exact_matches / total_pairs * 100:.2f}% exact matches)")
    print("\nHTTP Response Code Breakdown:")
    for code, count in sorted(status_counts.items()):
        name = "OK" if code == 200 else ("Rate Limit (429)" if code == 429 else "Error")
        pct = (count / total_reqs) * 100 if total_reqs else 0
        print(f"  HTTP {code} ({name:20}): {count:7d}  ({pct:5.2f}%)")

    print("\nLatency Percentiles (Sampled across test):")
    if len(lats_p1) > 0:
        print(f"  Phase 1 (Masking):   P50: {np.percentile(lats_p1, 50):5.2f} ms | P90: {np.percentile(lats_p1, 90):5.2f} ms | P95: {np.percentile(lats_p1, 95):5.2f} ms | P99: {np.percentile(lats_p1, 99):5.2f} ms")
    if len(lats_p2) > 0:
        print(f"  Phase 2 (Demasking): P50: {np.percentile(lats_p2, 50):5.2f} ms | P90: {np.percentile(lats_p2, 90):5.2f} ms | P95: {np.percentile(lats_p2, 95):5.2f} ms | P99: {np.percentile(lats_p2, 99):5.2f} ms")

    print("\nDocker Final Stats:")
    res = subprocess.run(["docker", "stats", "--no-stream", "zero-pii-vault", "zero-pii-redis"], capture_output=True, text=True)
    print(res.stdout)
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
