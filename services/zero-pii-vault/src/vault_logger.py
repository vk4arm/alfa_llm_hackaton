"""
Non-blocking, High-Performance Asynchronous Logger for Zero-PII Vault.
Compliant with 152-FZ & 395-1 (Strict zero-leakage of raw personal data).

Features:
1. Zero-latency non-blocking queuing: request threads enqueue log records in nanoseconds
   via Python SimpleQueue; a dedicated background thread flushes to disk.
2. Target log file: /log/alfapii.log (with automatic fallback to local ./logs/alfapii.log
   if running outside Docker without root permissions).
3. Structured JSON logging format:
   - timestamp (ISO-8601)
   - payload_id (correlation key)
   - phase (PHASE_1_MASK, PHASE_2_UNMASK, RETRY)
   - detected_types (dict of entity counts: FIO, CARD, PASSPORT...)
   - latency_ms
   - payload_len, result_len
   - storage_backend (REDIS / IN_MEMORY)
   - client_ip, status_code
4. Rotating file handler (50 MB per file, 5 backups) to prevent disk exhaustion.
"""

import json
import logging
import os
import queue
import sys
import time
from datetime import datetime, timezone
from logging.handlers import QueueHandler, QueueListener, RotatingFileHandler
from typing import Any, Dict, Optional


def resolve_log_path() -> str:
    """
    Resolves the log file path.
    Prioritizes /log/alfapii.log.
    If /log is not writable (e.g. running unprivileged on macOS outside Docker),
    falls back to ./logs/alfapii.log.
    """
    try:
        from config_loader import load_vault_config
        env_log = load_vault_config().vault_log_file
    except ImportError:
        env_log = os.getenv("VAULT_LOG_FILE", "/var/logs/alfapii.log")
    
    # Try primary target directory
    target_dir = os.path.dirname(env_log)
    try:
        os.makedirs(target_dir, exist_ok=True)
        # Test writability with unique filename per process to avoid worker race condition
        test_file = os.path.join(target_dir, f".perm_test_{os.getpid()}_{time.time_ns()}")
        with open(test_file, "w") as f:
            f.write("ok")
        try:
            os.remove(test_file)
        except OSError:
            pass
        return env_log
    except (PermissionError, OSError):
        # Fallback to local logs directory
        local_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs"))
        os.makedirs(local_dir, exist_ok=True)
        return os.path.join(local_dir, "alfapii.log")


class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as structured, single-line JSON entries."""
    def format(self, record: logging.LogRecord) -> str:
        data: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage()
        }
        # Merge extra attributes if provided
        if hasattr(record, "vault_event"):
            data.update(record.vault_event)
        return json.dumps(data, ensure_ascii=False)


# Initialize Queue and Background Listener
_LOG_QUEUE: queue.SimpleQueue = queue.SimpleQueue()
_ACTUAL_LOG_PATH = resolve_log_path()

_file_handler = RotatingFileHandler(
    _ACTUAL_LOG_PATH,
    maxBytes=50 * 1024 * 1024,  # 50 MB
    backupCount=5,
    encoding="utf-8"
)
_file_handler.setFormatter(StructuredJsonFormatter())

# Also log to stdout in container for docker logs
_console_handler = logging.StreamHandler(sys.stdout)
_console_handler.setFormatter(
    logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
)

_listener = QueueListener(_LOG_QUEUE, _file_handler, _console_handler, respect_handler_level=True)
_listener.start()

# Logger setup using QueueHandler for 0-latency non-blocking emit
_logger = logging.getLogger("zero_pii_vault")
_logger.setLevel(logging.INFO)
_logger.addHandler(QueueHandler(_LOG_QUEUE))
_logger.propagate = False


def log_event(
    event_type: str,
    payload_id: str,
    message: str,
    level: str = "INFO",
    phase: Optional[str] = None,
    detected_types: Optional[Dict[str, int]] = None,
    latency_ms: Optional[float] = None,
    payload_len: Optional[int] = None,
    result_len: Optional[int] = None,
    storage: Optional[str] = None,
    status_code: int = 200,
    **kwargs
):
    """
    Submits a structured audit event to the non-blocking queue.
    NEVER logs raw customer personal data.
    """
    vault_event: Dict[str, Any] = {
        "event_type": event_type,
        "payload_id": payload_id,
        "status_code": status_code,
    }
    if phase:
        vault_event["phase"] = phase
    if detected_types:
        vault_event["detected_types"] = detected_types
        vault_event["total_entities"] = sum(detected_types.values())
    if latency_ms is not None:
        vault_event["latency_ms"] = round(latency_ms, 3)
    if payload_len is not None:
        vault_event["payload_len"] = payload_len
    if result_len is not None:
        vault_event["result_len"] = result_len
    if storage:
        vault_event["storage"] = storage
    if kwargs:
        vault_event.update(kwargs)

    log_fn = getattr(_logger, level.lower(), _logger.info)
    log_fn(message, extra={"vault_event": vault_event})


def get_log_file_path() -> str:
    """Returns the active log file path."""
    return _ACTUAL_LOG_PATH


def shutdown_logger():
    """Flushes remaining records and shuts down background listener."""
    _listener.stop()

logger = _logger

