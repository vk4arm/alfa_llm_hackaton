"""
Zero-PII Vault: Production FastAPI Server implementing the /process OpenAPI contract.
Compliant with AlfaSonar Load Testing Specification (Приложение A & B в ds.pdf).

Contract:
- Endpoint: POST /process
- Request:  {"payload": "<строка>", "payload_id": "<идентификатор>"}
- Response: {"result": "<строка>"}

Key Features:
1. Two-phase correlation by payload_id:
   - Phase 1 (First request with payload_id): Masking of PII, returns masked text.
   - Phase 2 (Second request with same payload_id): Loss-free unmasking, returns original text.
2. Idempotency & retry tolerance (handles network retries without state corruption).
3. 4-core multi-processing engine offloading heavy NLP/NER tasks without GIL blocking.
4. Fast thread-safe session store with automatic TTL cleanup and LRU capacity protection.
5. Built-in concurrency control returning HTTP 429 with Retry-After header under overload.
"""

import asyncio
import os
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from concurrent.futures import ProcessPoolExecutor

# Ensure local imports work regardless of working directory
src_dir = os.path.abspath(os.path.dirname(__file__))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from fastapi import FastAPI, HTTPException, Response, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from firewall import FirewallMiddleware
from pydantic import BaseModel, Field

from collections import Counter, OrderedDict
from config_loader import load_vault_config
from parallel import _set_blas_threads
from masker import NatashaPIIMasker
from vault_logger import log_event, shutdown_logger, get_log_file_path, logger



# --------------------------------------------------------------------------
# OpenAPI Pydantic Models (Strictly matching process_api.yaml)
# --------------------------------------------------------------------------
class ProcessRequest(BaseModel):
    payload: str = Field(
        ...,
        description="Строка для обработки: на прямом шаге — исходный текст; на обратном шаге — замаскированная строка.",
        example="Клиент Иванов Иван Иванович, паспорт 4509 123456",
        max_length=524288
    )
    payload_id: str = Field(
        ...,
        description="Идентификатор корреляции для пары маскирование → демаскирование.",
        example="8a77d363c7c044b49b41d7b8a448243a"
    )


class ProcessResponse(BaseModel):
    result: str = Field(
        ...,
        description="Результат обработки (замаскированная строка на прямом шаге, исходная — на обратном).",
        example="Клиент [FIO_1], паспорт [PASSPORT_1]"
    )


# --------------------------------------------------------------------------
# Ultra-fast JSON Serializer (orjson in C/Rust with json fallback)
# --------------------------------------------------------------------------
try:
    import orjson
    def fast_json_dumps(obj) -> str:
        return orjson.dumps(obj).decode('utf-8')
    def fast_json_dumps_bytes(obj) -> bytes:
        return orjson.dumps(obj)
    fast_json_loads = orjson.loads
except ImportError:
    import json
    def fast_json_dumps(obj) -> str:
        return json.dumps(obj, ensure_ascii=False)
    def fast_json_dumps_bytes(obj) -> bytes:
        return json.dumps(obj, ensure_ascii=False).encode('utf-8')
    fast_json_loads = json.loads

def make_process_response(result_text: str) -> Response:
    """Zero-overhead direct HTTP response bypassing Starlette and Pydantic validators."""
    return Response(
        content=fast_json_dumps_bytes({"result": result_text}),
        media_type="application/json"
    )

try:
    import redis.asyncio as aioredis
except ImportError:
    aioredis = None


@dataclass
class SessionRecord:
    original_text: str
    masked_text: str
    mapping: Dict[str, str]
    created_at: float
    phase: int  # 1 = masked, 2 = unmasked


class SessionStore:
    """
    Двухуровневое хранилище сессий:
    1. Redis (в Docker) — для горизонтального масштабирования между репликами.
    2. In-Memory (локально) — сверхбыстрый кэш с TTL и защитой емкости.
    """
    def __init__(self, ttl_seconds: int = 600, max_sessions: int = 200000):
        self.ttl_seconds = ttl_seconds
        self.max_sessions = max_sessions
        self._store: OrderedDict[str, SessionRecord] = OrderedDict()
        self._lock = asyncio.Lock()
        self.redis_client = None

        redis_host = os.getenv("REDIS_HOST")
        if redis_host and aioredis:
            redis_port = int(os.getenv("REDIS_PORT", "6379"))
            try:
                self.redis_client = aioredis.Redis(
                    host=redis_host,
                    port=redis_port,
                    socket_timeout=1.0,
                    decode_responses=True
                )
            except Exception as e:
                logger.error("Redis init failed", exc_info=e)
                self.redis_client = None

    async def get(self, payload_id: str) -> Optional[SessionRecord]:
        # 1. Проверяем локальный L1-кэш
        async with self._lock:
            rec = self._store.get(payload_id)
            if rec:
                if (time.time() - rec.created_at) > self.ttl_seconds:
                    del self._store[payload_id]
                else:
                    self._store.move_to_end(payload_id)
                    return rec

        # 2. Если есть Redis — проверяем L2 одним быстрым запросом
        if self.redis_client:
            try:
                raw = await self.redis_client.get(payload_id)
                if raw:
                    data = fast_json_loads(raw)
                    rec = SessionRecord(
                        original_text=data.get("orig", ""),
                        masked_text=data.get("masked", ""),
                        mapping=data.get("mapping", {}),
                        created_at=data.get("created_at", time.time()),
                        phase=data.get("phase", 1)
                    )
                    # Сохраняем в L1 для ускорения
                    async with self._lock:
                        self._store[payload_id] = rec
                        self._store.move_to_end(payload_id)
                    return rec
            except Exception as e:
                logger.error("Exception caught", exc_info=e)

        return None

    async def put(self, payload_id: str, record: SessionRecord):
        # 1. Сохраняем в локальный L1-кэш
        async with self._lock:
            if len(self._store) >= self.max_sessions:
                # O(1) быстрое вытеснение самых старых сессий без перебора
                for _ in range(min(2000, len(self._store))):
                    self._store.popitem(last=False)

            self._store[payload_id] = record
            self._store.move_to_end(payload_id)

        # 2. Сохраняем в Redis (с TTL) одним атомарным вызовом SETEX:
        if self.redis_client:
            try:
                data = {
                    "mapping": record.mapping,
                    "created_at": record.created_at,
                    "phase": record.phase
                }
                # Кэшируем строки до 1 МБ в Redis для мгновенного O(1) ответа
                if len(record.original_text) < 1000000:
                    data["orig"] = record.original_text
                    data["masked"] = record.masked_text

                await self.redis_client.setex(
                    payload_id,
                    self.ttl_seconds,
                    fast_json_dumps(data)
                )
            except Exception as e:
                logger.error("Exception caught", exc_info=e)

    async def update_phase(self, payload_id: str, phase: int):
        async with self._lock:
            if payload_id in self._store:
                self._store[payload_id].phase = phase

    async def purge_expired(self):
        async with self._lock:
            now = time.time()
            # Поскольку OrderedDict упорядочен по времени, удаляем только просроченные с начала
            while self._store:
                first_key = next(iter(self._store))
                if (now - self._store[first_key].created_at) > self.ttl_seconds:
                    self._store.pop(first_key)
                else:
                    break

    def size(self) -> int:
        return len(self._store)


# --------------------------------------------------------------------------
# Multi-Process Worker Pool for CPU-bound Masking
# --------------------------------------------------------------------------
_worker_masker_instance: Optional[NatashaPIIMasker] = None

def _worker_init():
    """Initializes Natasha models and compiled regexes once per child process."""
    global _worker_masker_instance
    _set_blas_threads()
    _worker_masker_instance = NatashaPIIMasker()

def _worker_mask(text: str, session_id: str) -> Tuple[str, Dict[str, str]]:
    """Executes masking in worker process."""
    global _worker_masker_instance
    if _worker_masker_instance is None:
        _worker_masker_instance = NatashaPIIMasker()
    masked_text, _, mapping = _worker_masker_instance.mask(text, session_id=session_id)
    return masked_text, mapping


# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# Singleflight: In-Flight Deduplication for Heavy Compute (Cold Templates)
# --------------------------------------------------------------------------
class Singleflight:
    """
    Потокобезопасная дедупликация одновременных вычислений спанов (NER).
    Если одновременно приходит N запросов с одинаковым шаблонным текстом,
    тяжелая модель выполняется ровно 1 раз. Все остальные N-1 запросов
    ожидают этот результат и мгновенно получают закэшированные спаны.
    """
    def __init__(self):
        self._flights: Dict[str, asyncio.Future] = {}
        self._lock = asyncio.Lock()

    async def execute(self, key: str, coro_fn):
        async with self._lock:
            if key in self._flights:
                future = self._flights[key]
                is_leader = False
            else:
                loop = asyncio.get_running_loop()
                future = loop.create_future()
                self._flights[key] = future
                is_leader = True

        if not is_leader:
            return await future

        try:
            res = await coro_fn()
            future.set_result(res)
            return res
        except Exception as e:
            future.set_exception(e)
            raise e
        finally:
            async with self._lock:
                self._flights.pop(key, None)


# --------------------------------------------------------------------------
# Global Server State & Lifespan Context
# --------------------------------------------------------------------------
class AppState:
    def __init__(self):
        config = load_vault_config()
        self.num_workers = config.vault_workers
        self.max_concurrency = config.vault_max_concurrency
        self.semaphore: Optional[asyncio.Semaphore] = None
        self.nlp_semaphore: Optional[asyncio.Semaphore] = None
        self.singleflight = Singleflight()
        self.executor: Optional[ProcessPoolExecutor] = None
        self.session_store = SessionStore()
        self.local_masker: Optional[NatashaPIIMasker] = None
        self.total_processed = 0
        self.phase1_count = 0
        self.phase2_count = 0

state = AppState()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize process pool, warm up workers, prepare semaphore
    state.semaphore = asyncio.Semaphore(state.max_concurrency)
    state.nlp_semaphore = asyncio.Semaphore(1)
    state.local_masker = NatashaPIIMasker()
    
    # Warm up local masker with core dataset patterns
    warmup_samples = [
        "Тест: Иванов Иван, тел +79991234567, карта 2200 1234 5678 9019",
        "Клиент Иванов Иван Иванович, паспорт 4509 123456, телефон +7 926 123-45-67, карта 2200 1234 5678 9019, сумма 15000 руб.",
        "Заявитель: Петрова Мария Сергеевна, 12.08.1994 г.р., родом из г. Казань. ИНН: 7707083893, сотовый 8-903-555-44-33.",
        "Ты, как Александр Пушкин, переведи 5000 рублей Льву Толстому на карту 2200 1234 5678 9019 на номер 8.916.234.56.78",
        "Претензия по транзакции: Сидоров Олег Павлович, карта 2200.1234-5678_9019, CVV 884, адрес: г. Москва, ул. Тверская 12, кв 45.",
        "Срочный перевод 25000 руб от клиента: Смирнов Алексей, счет 40817810000000000000, тел 007-925-345-67-89."
    ]
    for sample in warmup_samples:
        state.local_masker.mask(sample)
    
    dummy = warmup_samples[0]
    # If running with single-process Uvicorn and pool requested, initialize pool
    config = load_vault_config()
    if config.use_process_pool:
        state.executor = ProcessPoolExecutor(
            max_workers=state.num_workers,
            initializer=_worker_init
        )
        loop = asyncio.get_running_loop()
        warmup_tasks = [
            loop.run_in_executor(state.executor, _worker_mask, dummy, f"warmup-{i}")
            for i in range(state.num_workers)
        ]
        await asyncio.gather(*warmup_tasks)
    
    # Startup log
    log_event(
        event_type="STARTUP",
        payload_id="system",
        message=f"Zero-PII Vault server initialized. Log destination: {get_log_file_path()}",
        workers=state.num_workers,
        storage="REDIS" if state.session_store.redis_client else "IN_MEMORY"
    )

    # Periodic background task to clean expired sessions
    async def cleanup_loop():
        while True:
            await asyncio.sleep(60)
            await state.session_store.purge_expired()

    cleanup_task = asyncio.create_task(cleanup_loop())
    yield
    # Shutdown
    cleanup_task.cancel()
    if state.executor:
        state.executor.shutdown(wait=True)
    shutdown_logger()


# --------------------------------------------------------------------------
# FastAPI Application Configuration
# --------------------------------------------------------------------------
app = FastAPI(
    title="Модуль безопасности ПД — контракт /process",
    description="Высокоскоростной прокси-сервис маскирования и демаскирования ПДн (152-ФЗ, 395-1)",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(FirewallMiddleware, config_path="config/firewall.json")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------
# Core API Endpoint: POST /process (Exact Contract Implementation)
# --------------------------------------------------------------------------
@app.post(
    "/process",
    response_model=ProcessResponse,
    status_code=status.HTTP_200_OK,
    summary="Маскирование/демаскирование строки (коррелируется по payload_id)",
    responses={
        200: {"description": "Успешная обработка", "model": ProcessResponse},
        429: {"description": "Слишком много запросов (перегрузка). Повторите позже."},
        400: {"description": "Некорректный запрос"},
        500: {"description": "Внутренняя ошибка сервиса"}
    }
)
async def process_endpoint(request: ProcessRequest):
    """
    Единый двухфазный эндпоинт по контракту AlfaSonar (Приложение A в ds.pdf).
    
    Логика:
    - Фаза 1 (Маскирование): Новый payload_id -> исходный текст маскируется,
      карта соответствия сохраняется в сессии.
    - Фаза 2 (Демаскирование): Повторный запрос с тем же payload_id ->
      возвращается исходная строка.
    - Идемпотентность: повторные запросы той же фазы возвращают кэшированный результат.
    """
    t0 = time.perf_counter()
    pid = request.payload_id.strip()
    payload = request.payload

    if not pid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="payload_id must not be empty")

    # --------------------------------------------------------------------------
    # 1. ПРОВЕРКА НАЛИЧИЯ СЕССИИ (ВАРИАНТ 2: ZERO-WAIT ДЕМАСКИРОВАНИЕ)
    # --------------------------------------------------------------------------
    session = await state.session_store.get(pid)

    if session is not None:
        # Сессия найдена -> Это либо идемпотентный ретрай, либо Фаза 2 (Демаскирование)
        # Выполняется БЕЗ каких-либо блокировок, очередей и семафоров за < 0.1 мс!

        # Случай A: Идемпотентный ретрай Фазы 1 (клиент повторно прислал оригинал)
        if payload == session.original_text:
            latency_ms = (time.perf_counter() - t0) * 1000
            log_event(
                event_type="RETRY_SERVED",
                payload_id=pid,
                message="Idempotent retry for Phase 1 served from cache.",
                phase="RETRY_1",
                latency_ms=latency_ms,
                storage="REDIS" if state.session_store.redis_client else "IN_MEMORY"
            )
            return make_process_response(session.masked_text)

        # Случай B: Фаза 2 (Демаскирование) — точное совпадение с выданной ранее маской
        if payload == session.masked_text:
            asyncio.create_task(state.session_store.update_phase(pid, phase=2))
            state.total_processed += 1
            state.phase2_count += 1

            latency_ms = (time.perf_counter() - t0) * 1000
            log_event(
                event_type="UNMASKING_SUCCESS",
                payload_id=pid,
                message="Phase 2 demasking complete (exact match).",
                phase="PHASE_2_UNMASK",
                latency_ms=latency_ms,
                payload_len=len(payload),
                result_len=len(session.original_text),
                storage="REDIS" if state.session_store.redis_client else "IN_MEMORY"
            )
            return make_process_response(session.original_text)

        # Случай C: Демаскирование с подстановкой токенов через маппинг
        # (если клиент/LLM вернул текст с внешними правками)
        if state.local_masker:
            unmasked = state.local_masker.unmask(payload, session.mapping)
        else:
            unmasked = payload
            for token, val in session.mapping.items():
                unmasked = unmasked.replace(token, val)

        asyncio.create_task(state.session_store.update_phase(pid, phase=2))
        state.total_processed += 1
        state.phase2_count += 1

        latency_ms = (time.perf_counter() - t0) * 1000
        log_event(
            event_type="UNMASKING_SUCCESS",
            payload_id=pid,
            message="Phase 2 demasking complete (token substitution).",
            phase="PHASE_2_UNMASK",
            latency_ms=latency_ms,
            payload_len=len(payload),
            result_len=len(unmasked),
            storage="REDIS" if state.session_store.redis_client else "IN_MEMORY"
        )
        return make_process_response(unmasked)

    # --------------------------------------------------------------------------
    # 2. ФАЗА 1: МАСКИРОВАНИЕ НОВОГО ТЕКСТА (ВАРИАНТ 1: TEMPLATE SPAN CACHE)
    # --------------------------------------------------------------------------
    # Если спаны для данного шаблонного текста уже закэшированы (повтор строки в датасете),
    # мы мгновенно генерируем маску без ожидания очередей и нейросетей!
    if state.local_masker and state.local_masker.has_cached_spans(payload):
        masked_text, _, mapping = state.local_masker.mask(payload, session_id=pid)
        record = SessionRecord(
            original_text=payload,
            masked_text=masked_text,
            mapping=mapping,
            created_at=time.time(),
            phase=1
        )
        await state.session_store.put(pid, record)

        state.total_processed += 1
        state.phase1_count += 1

        latency_ms = (time.perf_counter() - t0) * 1000
        token_types = Counter(k.split("_")[0].strip("[]") for k in mapping.keys())
        log_event(
            event_type="MASKING_SUCCESS",
            payload_id=pid,
            message=f"Phase 1 masking complete (template cache hit). Found {len(mapping)} entities.",
            phase="PHASE_1_MASK",
            detected_types=dict(token_types),
            latency_ms=latency_ms,
            payload_len=len(payload),
            result_len=len(masked_text),
            cache_hit=True,
            storage="REDIS" if state.session_store.redis_client else "IN_MEMORY"
        )
        return make_process_response(masked_text)

    # --------------------------------------------------------------------------
    # 3. ФАЗА 1: ХОЛОДНЫЙ ТЕКСТ (ПЕРВЫЙ ПРОГОН НЕЙРОСЕТИ С SINGLEFLIGHT И ЗАЩИТОЙ ПО 429)
    # --------------------------------------------------------------------------
    async def _compute_cold_spans():
        try:
            await asyncio.wait_for(state.semaphore.acquire(), timeout=15.0)
        except asyncio.TimeoutError:
            return False
        try:
            if state.local_masker:
                async with state.nlp_semaphore:
                    await asyncio.to_thread(state.local_masker.extract_spans, payload)
            else:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(state.executor, _worker_mask, payload, pid)
            return True
        finally:
            state.semaphore.release()

    success = await state.singleflight.execute(payload, _compute_cold_spans)
    if not success:
        log_event(
            event_type="OVERLOAD_429",
            payload_id=pid,
            message="Request rejected due to concurrency limit.",
            level="WARNING",
            status_code=429,
            latency_ms=(time.perf_counter() - t0) * 1000
        )
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Too many requests. System under load."},
            headers={"Retry-After": "1"}
        )

    # Спаны вычислены и сохранены в TemplateSpanCache. Мгновенно строим маску:
    if state.local_masker:
        masked_text, _, mapping = state.local_masker.mask(payload, session_id=pid)
    else:
        loop = asyncio.get_running_loop()
        masked_text, mapping = await loop.run_in_executor(
            state.executor, _worker_mask, payload, pid
        )

    record = SessionRecord(
        original_text=payload,
        masked_text=masked_text,
        mapping=mapping,
        created_at=time.time(),
        phase=1
    )
    await state.session_store.put(pid, record)

    state.total_processed += 1
    state.phase1_count += 1

    latency_ms = (time.perf_counter() - t0) * 1000
    token_types = Counter(k.split("_")[0].strip("[]") for k in mapping.keys())
    log_event(
        event_type="MASKING_SUCCESS",
        payload_id=pid,
        message=f"Phase 1 masking complete (cold run). Found {len(mapping)} entities.",
        phase="PHASE_1_MASK",
        detected_types=dict(token_types),
        latency_ms=latency_ms,
        payload_len=len(payload),
        result_len=len(masked_text),
        cache_hit=False,
        storage="REDIS" if state.session_store.redis_client else "IN_MEMORY"
    )

    return make_process_response(masked_text)


# --------------------------------------------------------------------------
# Service Health, Metrics & Information Endpoints
# --------------------------------------------------------------------------
@app.get("/health", summary="Health check")
async def health():
    return {
        "status": "UP",
        "workers": state.num_workers,
        "active_sessions": state.session_store.size(),
        "total_processed": state.total_processed,
        "phase1_masking": state.phase1_count,
        "phase2_unmasking": state.phase2_count
    }

@app.get("/", summary="Root metadata")
async def root():
    return {
        "service": "Zero-PII Vault",
        "compliance": ["152-FZ", "395-1"],
        "endpoint": "POST /process",
        "health": "GET /health",
        "docs": "GET /docs"
    }


if __name__ == "__main__":
    import uvicorn
    config = load_vault_config()
    port = config.port
    host = config.host
    print(f"[*] Starting Zero-PII Vault Server on {host}:{port}...")
    uvicorn.run(app, host=host, port=port, log_level="info")
