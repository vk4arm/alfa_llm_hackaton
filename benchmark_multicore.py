#!/usr/bin/env python3
"""
Multi-Core (4 Cores) vs Single-Core PII Masking Benchmark Suite
Compares single-core baseline against 4-core parallel processing across
15 KB, 100 KB, and 2 MB datasets.
"""

import os
import sys
import time
import tracemalloc
from typing import List, Dict, Any

# Configure thread environment before loading numpy/natasha
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["VECLIB_MAXIMUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "services", "zero-pii-vault", "src")))
from masker import NatashaPIIMasker
from parallel import ParallelPIIMasker

def load_records(file_path: str) -> List[str]:
    with open(file_path, "r", encoding="utf-8") as f:
        return [r for r in f.read().split("=" * 80) if r.strip()]

def benchmark_single_core(records: List[str]) -> Dict[str, Any]:
    masker = NatashaPIIMasker()
    # Warmup
    masker.mask(records[0])
    
    t0 = time.perf_counter()
    masked_items = []
    for r in records:
        masked_text, s_id, mapping = masker.mask(r)
        masked_items.append((masked_text, mapping))
    t_mask = time.perf_counter() - t0
    
    t1 = time.perf_counter()
    all_exact = True
    for orig, (m_text, mapping) in zip(records, masked_items):
        unm = masker.unmask(m_text, mapping)
        if unm != orig:
            all_exact = False
    t_unmask = time.perf_counter() - t1
    
    total_entities = sum(len(m[1]) for m in masked_items)
    
    return {
        "mask_time_sec": t_mask,
        "unmask_time_sec": t_unmask,
        "total_time_sec": t_mask + t_unmask,
        "req_per_sec": len(records) / t_mask,
        "ms_per_req": (t_mask * 1000) / len(records),
        "entities": total_entities,
        "all_exact": all_exact
    }

def benchmark_multi_core(records: List[str], p_masker: ParallelPIIMasker, chunksize: int = 16) -> Dict[str, Any]:
    t0 = time.perf_counter()
    masked_items = p_masker.mask_batch(records, chunksize=chunksize)
    t_mask = time.perf_counter() - t0
    
    t1 = time.perf_counter()
    unmasked = p_masker.unmask_batch([(m[0], m[2]) for m in masked_items], chunksize=chunksize)
    t_unmask = time.perf_counter() - t1
    
    all_exact = (unmasked == records)
    total_entities = sum(len(m[2]) for m in masked_items)
    
    return {
        "mask_time_sec": t_mask,
        "unmask_time_sec": t_unmask,
        "total_time_sec": t_mask + t_unmask,
        "req_per_sec": len(records) / t_mask,
        "ms_per_req": (t_mask * 1000) / len(records),
        "entities": total_entities,
        "all_exact": all_exact
    }

def main():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "data", "pii_samples"))
    datasets = [
        ("15 KB", os.path.join(base_dir, "pii_dataset_15kb.txt"), 4),
        ("100 KB", os.path.join(base_dir, "pii_dataset_100kb.txt"), 8),
        ("2 MB", os.path.join(base_dir, "pii_dataset_2mb.txt"), 25),
    ]

    print("=" * 80)
    print("  ZERO-PII VAULT: MULTI-CORE (4 CORES) vs SINGLE-CORE BENCHMARK")
    print("=" * 80)

    # Initialize and pre-warm 4-core worker pool
    print("\n[+] Initializing and pre-warming 4-core worker pool...")
    p_masker = ParallelPIIMasker(num_workers=4)
    p_masker.start()
    
    # Warm up workers with 4 dummy requests
    dummy = "Тестовая заявка клиента: Иванов Иван Иванович, паспорт 4512 123456, телефон +79031234567"
    p_masker.mask_batch([dummy] * 4, chunksize=1)
    print("[+] Worker pool ready.\n")

    summary_rows = []

    for label, path, c_size in datasets:
        file_size_kb = os.path.getsize(path) / 1024
        records = load_records(path)
        num_records = len(records)
        
        print(f"\n>>> Running benchmark on {label} dataset ({num_records} records, {file_size_kb:.1f} KB)...")
        
        # Single-core
        res_single = benchmark_single_core(records)
        print(f"  [1 Core]  Masking: {res_single['mask_time_sec']:.3f} s | {res_single['req_per_sec']:.1f} req/s | {res_single['ms_per_req']:.2f} ms/req")
        
        # 4 Cores
        res_multi = benchmark_multi_core(records, p_masker, chunksize=c_size)
        print(f"  [4 Cores] Masking: {res_multi['mask_time_sec']:.3f} s | {res_multi['req_per_sec']:.1f} req/s | {res_multi['ms_per_req']:.2f} ms/req")
        
        speedup = res_single["mask_time_sec"] / res_multi["mask_time_sec"]
        print(f"  >>> Speedup: {speedup:.2f}x | Reversibility: {'100% OK' if res_multi['all_exact'] else 'FAIL'}")
        
        summary_rows.append({
            "dataset": label,
            "size_kb": f"{file_size_kb:.1f} KB",
            "records": num_records,
            "entities": res_multi["entities"],
            "single_time": f"{res_single['mask_time_sec']:.3f} s",
            "single_rps": f"{res_single['req_per_sec']:.1f}",
            "multi_time": f"{res_multi['mask_time_sec']:.3f} s",
            "multi_rps": f"{res_multi['req_per_sec']:.1f}",
            "multi_lat": f"{res_multi['ms_per_req']:.2f} ms",
            "speedup": f"{speedup:.2f}x",
            "reversibility": "100% EXACT" if res_multi["all_exact"] else "FAIL"
        })

    p_masker.stop()

    print("\n" + "=" * 80)
    print("  FINAL BENCHMARK COMPARISON TABLE (1 CORE vs 4 CORES)")
    print("=" * 80)
    header = f"| {'Датасет':<8} | {'Размер':<9} | {'Документов':<10} | {'1 ядро':<10} | {'4 ядра':<10} | {'Ускорение':<10} | {'Задержка (4 ядра)':<17} | {'Пропускная спос.':<18} | {'Обратимость':<11} |"
    sep = "|" + "-"*10 + "|" + "-"*11 + "|" + "-"*12 + "|" + "-"*12 + "|" + "-"*12 + "|" + "-"*12 + "|" + "-"*19 + "|" + "-"*20 + "|" + "-"*13 + "|"
    print(header)
    print(sep)
    for r in summary_rows:
        row_str = f"| {r['dataset']:<8} | {r['size_kb']:<9} | {r['records']:<10} | {r['single_time']:<10} | {r['multi_time']:<10} | {r['speedup']:<10} | {r['multi_lat']:<17} | {r['multi_rps'] + ' req/s':<18} | {r['reversibility']:<11} |"
        print(row_str)
    print("=" * 80)

if __name__ == "__main__":
    main()
