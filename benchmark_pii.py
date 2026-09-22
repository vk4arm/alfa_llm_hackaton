#!/usr/bin/env python3
"""
Performance & Accuracy Benchmark for Natasha PII Masker
Evaluates latency, throughput, entity recognition, and reversibility
across 3 test datasets: 15 KB, 100 KB, and 2 MB.
"""

import os
import sys
import time
import tracemalloc
from collections import Counter

# Add service directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "services", "zero-pii-vault", "src")))
from masker import NatashaPIIMasker
from vault import ZeroPiiVault

def run_benchmark_on_file(file_path: str, chunked: bool = False):
    file_name = os.path.basename(file_path)
    file_size_bytes = os.path.getsize(file_path)
    file_size_kb = file_size_bytes / 1024
    file_size_mb = file_size_bytes / (1024 * 1024)

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    vault = ZeroPiiVault()
    
    print(f"\n{'='*70}")
    print(f"BENCHMARK: {file_name} ({file_size_kb:.1f} KB / {file_size_mb:.2f} MB)")
    print(f"{'='*70}")

    if not chunked:
        # Measure Memory & Latency for single pass
        tracemalloc.start()
        t0 = time.perf_counter()
        
        masked_text, session_id, mapping = vault.mask_text(content)
        
        elapsed_sec = time.perf_counter() - t0
        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Measure Unmasking Latency
        t_unmask_0 = time.perf_counter()
        unmasked_text = vault.unmask_text(masked_text, session_id)
        elapsed_unmask_sec = time.perf_counter() - t_unmask_0

        # Check reversibility
        roundtrip_ok = (unmasked_text == content)

        # Entity count breakdown
        token_types = Counter(k.split("_")[0].strip("[]") for k in mapping.keys())

        print(f"Processing Mode: Single String")
        print(f"Masking Latency:       {elapsed_sec * 1000:.2f} ms ({elapsed_sec:.3f} s)")
        print(f"Unmasking Latency:     {elapsed_unmask_sec * 1000:.2f} ms")
        print(f"Throughput:            {file_size_kb / elapsed_sec:.2f} KB/s ({file_size_mb / elapsed_sec:.2f} MB/s)")
        print(f"Peak RAM Usage:        {peak_mem / (1024 * 1024):.2f} MB")
        print(f"Reversibility Check:   {'100% EXACT (PASSED)' if roundtrip_ok else 'FAILED'}")
        print(f"Total Entities Masked: {len(mapping)}")
        print(f"Entity Breakdown:")
        for ent, count in sorted(token_types.items()):
            print(f"  • {ent:<16} : {count:>5} occurrences")
            
        # Sample output preview (first 10 lines of masked text)
        print("\nMasked Preview (First 8 lines):")
        for line in masked_text.strip().split("\n")[:8]:
            print(f"  > {line}")

        vault.purge_session(session_id)
        return {
            "name": file_name,
            "size_kb": file_size_kb,
            "latency_ms": elapsed_sec * 1000,
            "throughput_kb_s": file_size_kb / elapsed_sec,
            "entities": len(mapping),
            "reversibility": roundtrip_ok
        }
    else:
        # Per-record processing (simulates real-world API gateway stream)
        records = [r for r in content.split("=" * 80) if r.strip()]
        num_records = len(records)
        
        tracemalloc.start()
        t0 = time.perf_counter()
        
        total_entities = 0
        all_exact = True
        
        for r in records:
            masked_r, s_id, m = vault.mask_text(r)
            total_entities += len(m)
            unmasked_r = vault.unmask_text(masked_r, s_id)
            if unmasked_r != r:
                all_exact = False
            vault.purge_session(s_id)
            
        elapsed_sec = time.perf_counter() - t0
        _, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        avg_latency_per_record = (elapsed_sec * 1000) / num_records

        print(f"Processing Mode: Per-Record Gateway Stream ({num_records} requests)")
        print(f"Total Latency:         {elapsed_sec * 1000:.2f} ms ({elapsed_sec:.3f} s)")
        print(f"Avg Latency / Request: {avg_latency_per_record:.2f} ms")
        print(f"Throughput:            {file_size_kb / elapsed_sec:.2f} KB/s ({num_records / elapsed_sec:.1f} requests/sec)")
        print(f"Peak RAM Usage:        {peak_mem / (1024 * 1024):.2f} MB")
        print(f"Reversibility Check:   {'100% EXACT (PASSED)' if all_exact else 'FAILED'}")
        print(f"Total Entities Masked: {total_entities}")
        
        return {
            "name": file_name,
            "size_kb": file_size_kb,
            "latency_ms": elapsed_sec * 1000,
            "avg_req_ms": avg_latency_per_record,
            "throughput_kb_s": file_size_kb / elapsed_sec,
            "entities": total_entities,
            "reversibility": all_exact
        }

if __name__ == "__main__":
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "data", "pii_samples"))
    f_15k = os.path.join(base_dir, "pii_dataset_15kb.txt")
    f_100k = os.path.join(base_dir, "pii_dataset_100kb.txt")
    f_2mb = os.path.join(base_dir, "pii_dataset_2mb.txt")

    print("\n" + "#" * 70)
    print("  ZERO-PII VAULT: PERFORMANCE & ACCURACY BENCHMARK SUITE")
    print("#" * 70)

    # 1. 15 KB benchmark (Direct & Per-Request)
    run_benchmark_on_file(f_15k, chunked=False)
    run_benchmark_on_file(f_15k, chunked=True)

    # 2. 100 KB benchmark (Direct & Per-Request)
    run_benchmark_on_file(f_100k, chunked=False)
    run_benchmark_on_file(f_100k, chunked=True)

    # 3. 2 MB benchmark (Per-Request Gateway Stream)
    run_benchmark_on_file(f_2mb, chunked=True)
