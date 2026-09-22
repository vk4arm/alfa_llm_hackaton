"""
Многоядерный параллельный процессор маскирования ПДн (Zero-PII Vault).
Оптимизирован для многопроцессорных серверов без конфликтов за блокировку GIL.

Обеспечивает высокую пропускную способность пакетной обработки обращений клиентов
и банковской тайны (152-ФЗ, 395-1) на пуле из N рабочих процессов.
"""

import os
import sys
import uuid
from typing import List, Tuple, Dict, Optional
from concurrent.futures import ProcessPoolExecutor

# Принудительное ограничение внутренних потоков линейной алгебры BLAS/MKL
# до 1 потока на процесс во избежание деградации производительности от трэшинга ядер CPU
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["VECLIB_MAXIMUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

# Поддержка как относительного, так и абсолютного импорта
try:
    from .masker import NatashaPIIMasker
except ImportError:
    from masker import NatashaPIIMasker

_worker_masker: Optional[NatashaPIIMasker] = None

def _init_masker_worker(granular_address: bool = False):
    """
    Инициализатор рабочего процесса: выполняется ровно 1 раз при старте воркера.
    Загружает конфигурацию из YAML, эмбеддинги Natasha и скомпилированные регулярные выражения.
    Последующая обработка документов происходит с нулевым временем холодного старта.
    """
    global _worker_masker
    os.environ["OMP_NUM_THREADS"] = "1"
    os.environ["OPENBLAS_NUM_THREADS"] = "1"
    os.environ["MKL_NUM_THREADS"] = "1"
    os.environ["VECLIB_MAXIMUM_THREADS"] = "1"
    os.environ["NUMEXPR_NUM_THREADS"] = "1"
    _worker_masker = NatashaPIIMasker(granular_address=granular_address)

def _worker_mask_task(task_data: Tuple[int, str, Optional[str]]) -> Tuple[int, str, str, Dict[str, str]]:
    """Worker task: masks a single document."""
    global _worker_masker
    idx, text, session_id = task_data
    if _worker_masker is None:
        _worker_masker = NatashaPIIMasker()
    masked_text, session_id, mapping = _worker_masker.mask(text, session_id=session_id)
    return idx, masked_text, session_id, mapping

def _worker_unmask_task(task_data: Tuple[int, str, Dict[str, str]]) -> Tuple[int, str]:
    """Worker task: reverses tokenization for a single document."""
    global _worker_masker
    idx, masked_text, mapping = task_data
    if _worker_masker is None:
        _worker_masker = NatashaPIIMasker()
    unmasked = _worker_masker.unmask(masked_text, mapping)
    return idx, unmasked

class ParallelPIIMasker:
    """
    Multi-core coordinator for high-throughput PII anonymization.
    Distributes batches of customer requests across N worker processes.
    """
    def __init__(self, num_workers: int = 4, granular_address: bool = False):
        self.num_workers = num_workers
        self.granular_address = granular_address
        self._executor: Optional[ProcessPoolExecutor] = None

    def start(self):
        """Starts the persistent process pool and pre-warms workers."""
        if self._executor is None:
            self._executor = ProcessPoolExecutor(
                max_workers=self.num_workers,
                initializer=_init_masker_worker,
                initargs=(self.granular_address,)
            )

    def stop(self):
        """Gracefully shuts down the worker pool."""
        if self._executor is not None:
            self._executor.shutdown(wait=True)
            self._executor = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def mask_batch(
        self,
        texts: List[str],
        session_ids: Optional[List[str]] = None,
        chunksize: int = 16
    ) -> List[Tuple[str, str, Dict[str, str]]]:
        """
        Masks a list of documents in parallel across worker processes.
        Preserves original document ordering.
        Returns: List of (masked_text, session_id, mapping)
        """
        if not texts:
            return []

        should_shutdown = False
        if self._executor is None:
            self.start()
            should_shutdown = True

        try:
            tasks = []
            for idx, text in enumerate(texts):
                s_id = session_ids[idx] if session_ids and idx < len(session_ids) else None
                tasks.append((idx, text, s_id))

            # Distribute tasks across worker processes
            results = list(self._executor.map(_worker_mask_task, tasks, chunksize=chunksize))
            
            # Sort by original index to ensure deterministic ordering
            results.sort(key=lambda x: x[0])
            return [(r[1], r[2], r[3]) for r in results]
        finally:
            if should_shutdown:
                self.stop()

    def unmask_batch(
        self,
        masked_items: List[Tuple[str, Dict[str, str]]],
        chunksize: int = 16
    ) -> List[str]:
        """
        Unmasks a list of (masked_text, mapping) pairs in parallel.
        Preserves original document ordering.
        """
        if not masked_items:
            return []

        should_shutdown = False
        if self._executor is None:
            self.start()
            should_shutdown = True

        try:
            tasks = [(idx, item[0], item[1]) for idx, item in enumerate(masked_items)]
            results = list(self._executor.map(_worker_unmask_task, tasks, chunksize=chunksize))
            results.sort(key=lambda x: x[0])
            return [r[1] for r in results]
        finally:
            if should_shutdown:
                self.stop()
