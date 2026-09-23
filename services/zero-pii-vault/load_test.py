import asyncio
import time
import random
import aiohttp
import os
import uvloop
import uuid

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

TARGET_RPS = 2100
DURATION_SEC = 300
PORT = 8000
URL_PROCESS = f"http://127.0.0.1:{PORT}/process"

stats = {
    "req_sent": 0,
    "req_process_success": 0,
    "req_demask_success": 0,
    "req_error": 0,
    "masking_verified": 0,
    "unmasking_verified": 0,
    "total_latency_process": 0.0,
    "total_latency_demask": 0.0,
}

def load_datasets():
    print("Loading datasets...")
    with open("/Users/victor/work/СТРАННОЕ/alfa/data/pii_samples/pii_dataset_5mb.txt", "r", encoding="utf-8") as f:
        large_text = f.read()
    
    chunk_size = 500 * 1024
    large_chunks = [large_text[i:i+chunk_size] for i in range(0, len(large_text), chunk_size) if len(large_text[i:i+chunk_size]) >= chunk_size * 0.8]
    if not large_chunks:
        large_chunks = [large_text[:chunk_size]]
        
    with open("/Users/victor/work/СТРАННОЕ/alfa/data/pii_samples/pii_dataset_100kb.txt", "r", encoding="utf-8") as f:
        small_text = f.read()
    small_chunks = small_text.split("================================================================================")
    small_chunks = [c.strip() for c in small_chunks if c.strip()]
    
    print(f"Loaded {len(large_chunks)} large chunks (>=500KB) and {len(small_chunks)} small chunks.")
    return large_chunks, small_chunks

async def worker(session, large_chunks, small_chunks, queue):
    while True:
        try:
            req_id = queue.get_nowait()
        except asyncio.QueueEmpty:
            break
            
        is_large = random.random() < 0.10
        payload_text = random.choice(large_chunks) if is_large else random.choice(small_chunks)
        payload_id = str(uuid.uuid4())
        payload = {"payload": payload_text, "payload_id": payload_id}
        
        stats["req_sent"] += 1
        
        try:
            # ФАЗА 1: Маскирование
            t0 = time.monotonic()
            async with session.post(URL_PROCESS, json=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    t1 = time.monotonic()
                    stats["req_process_success"] += 1
                    stats["total_latency_process"] += (t1 - t0)
                    
                    masked = data.get("result", "")
                    if len(masked) != len(payload_text) or "[" in masked:
                        stats["masking_verified"] += 1
                    
                    # ФАЗА 2: Демаскирование
                    demask_payload = {"payload": masked, "payload_id": payload_id}
                    t2 = time.monotonic()
                    async with session.post(URL_PROCESS, json=demask_payload) as d_resp:
                        if d_resp.status == 200:
                            d_data = await d_resp.json()
                            t3 = time.monotonic()
                            stats["req_demask_success"] += 1
                            stats["total_latency_demask"] += (t3 - t2)
                            
                            demasked = d_data.get("result", "")
                            if demasked == payload_text:
                                stats["unmasking_verified"] += 1
                        else:
                            stats["req_error"] += 1
                else:
                    stats["req_error"] += 1
        except Exception as e:
            stats["req_error"] += 1
            
        queue.task_done()

async def main():
    large_chunks, small_chunks = load_datasets()
    
    print(f"Starting load test: target {TARGET_RPS} RPS, duration {DURATION_SEC}s (10% requests > 500KB)")
    
    start_time = time.time()
    end_time = start_time + DURATION_SEC
    
    sem = asyncio.Semaphore(150)
    
    conn = aiohttp.TCPConnector(limit=300, force_close=False, enable_cleanup_closed=True)
    timeout = aiohttp.ClientTimeout(total=30.0)
    
    async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
        async def single_request():
            async with sem:
                is_large = random.random() < 0.10
                payload_text = random.choice(large_chunks) if is_large else random.choice(small_chunks)
                payload_id = str(uuid.uuid4())
                payload = {"payload": payload_text, "payload_id": payload_id}
                
                stats["req_sent"] += 1
                try:
                    # ФАЗА 1: Маскирование
                    t0 = time.monotonic()
                    async with session.post(URL_PROCESS, json=payload) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            t1 = time.monotonic()
                            stats["req_process_success"] += 1
                            stats["total_latency_process"] += (t1 - t0)
                            
                            masked = data.get("result", "")
                            if len(masked) != len(payload_text) or "[" in masked:
                                stats["masking_verified"] += 1
                            
                            # ФАЗА 2: Демаскирование
                            demask_payload = {"payload": masked, "payload_id": payload_id}
                            t2 = time.monotonic()
                            async with session.post(URL_PROCESS, json=demask_payload) as d_resp:
                                if d_resp.status == 200:
                                    d_data = await d_resp.json()
                                    t3 = time.monotonic()
                                    stats["req_demask_success"] += 1
                                    stats["total_latency_demask"] += (t3 - t2)
                                    
                                    demasked = d_data.get("result", "")
                                    if demasked == payload_text:
                                        stats["unmasking_verified"] += 1
                                else:
                                    stats["req_error"] += 1
                        else:
                            stats["req_error"] += 1
                except Exception:
                    stats["req_error"] += 1

        tasks = set()
        last_log = time.time()
        
        while time.time() < end_time:
            now = time.time()
            elapsed = now - start_time
            target_count = int(elapsed * TARGET_RPS)
            to_send = target_count - stats["req_sent"]
            
            if to_send > 0:
                batch = min(to_send, 100)
                for _ in range(batch):
                    task = asyncio.create_task(single_request())
                    tasks.add(task)
                    task.add_done_callback(tasks.discard)
            else:
                await asyncio.sleep(0.005)
                
            if time.time() - last_log >= 30:
                last_log = time.time()
                curr_elapsed = time.time() - start_time
                print(f"[{int(curr_elapsed)}s/{DURATION_SEC}s] Sent: {stats['req_sent']}, Masked: {stats['req_process_success']}, Demasked: {stats['req_demask_success']}, In-flight: {len(tasks)}, Errors: {stats['req_error']}")
                
        print(f"Test duration reached ({DURATION_SEC}s). Draining remaining {len(tasks)} in-flight requests...")
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
            
        real_duration = time.time() - start_time
        actual_rps = stats["req_sent"] / real_duration
        
        print("\n=================== LOAD TEST RESULTS ===================")
        print(f"Target Duration: {DURATION_SEC} s | Actual Duration: {real_duration:.2f} s")
        print(f"Total Requests Dispatched: {stats['req_sent']}")
        print(f"Phase 1 (Masking) Completed: {stats['req_process_success']}")
        print(f"Phase 2 (Demasking) Completed: {stats['req_demask_success']}")
        print(f"Errors (HTTP != 200 / Timeout): {stats['req_error']}")
        print(f"Throughput Achieved: {actual_rps:.2f} requests/sec")
        
        if stats['req_process_success'] > 0:
            avg_proc = stats['total_latency_process'] / stats['req_process_success'] * 1000
            print(f"Avg Masking Latency: {avg_proc:.2f} ms")
        if stats['req_demask_success'] > 0:
            avg_demask = stats['total_latency_demask'] / stats['req_demask_success'] * 1000
            print(f"Avg Demasking Latency: {avg_demask:.2f} ms")
            
        mask_acc = (stats['masking_verified'] / stats['req_process_success'] * 100) if stats['req_process_success'] > 0 else 0
        demask_acc = (stats['unmasking_verified'] / stats['req_demask_success'] * 100) if stats['req_demask_success'] > 0 else 0
        print(f"Masking Quality (PII detected and replaced): {mask_acc:.2f}% ({stats['masking_verified']}/{stats['req_process_success']})")
        print(f"Demasking Exact Match Accuracy: {demask_acc:.2f}% ({stats['unmasking_verified']}/{stats['req_demask_success']})")
        print("=========================================================\n")

if __name__ == "__main__":
    asyncio.run(main())
