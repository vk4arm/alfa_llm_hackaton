"""
AUDIT WORM LOGGER & TELEMETRY
Immutable Audit Trail (Write Once Read Many) for Bank Information Security
and Prometheus Metrics Provider with native Kaspersky KUMA SIEM (CEF) support.
"""

import json
import time
from typing import Dict, Any, Optional

class AuditWormLogger:
    """
    Audit logger supporting Write-Once-Read-Many (WORM) storage and
    Common Event Format (CEF) streaming for Kaspersky KUMA SIEM.
    """

    # Маппинг событий на коды и критичность по стандарту KUMA / ArcSight CEF
    EVENT_MAPPING = {
        "JAILBREAK_BLOCKED": {
            "code": "SEC-001",
            "name": "PromptInjectionBlocked",
            "severity": 8,  # High
            "kuma_rule": "ALFA_AI_001_JAILBREAK_BURST"
        },
        "PII_MASKED": {
            "code": "DLP-001",
            "name": "BankingSecrecyMasked",
            "severity": 2,  # Low/Info
            "kuma_rule": "ALFA_AI_002_MASS_DEANONYMIZATION"
        },
        "NLI_CONTRADICTION": {
            "code": "NLI-001",
            "name": "HallucinationBlocked",
            "severity": 5,  # Medium
            "kuma_rule": "ALFA_AI_004_SYSTEMATIC_HALLUCINATIONS"
        },
        "CIRCUIT_TRIPPED": {
            "code": "SYS-001",
            "name": "CircuitBreakerOpened",
            "severity": 7,  # High
            "kuma_rule": "ALFA_AI_003_CIRCUIT_BREAKER_TRIPPED"
        },
        "CACHE_HIT": {
            "code": "INF-001",
            "name": "SemanticCacheHit",
            "severity": 1,  # Informational
            "kuma_rule": None
        },
        "CASCADE_FALLBACK": {
            "code": "SYS-002",
            "name": "ModelCascadeFailover",
            "severity": 4,  # Warning
            "kuma_rule": None
        }
    }

    def __init__(
        self,
        kafka_topic: str = "alfa.ai.gateway.audit.worm",
        kuma_topic: str = "alfa.kuma.ai-gateway.events",
        kuma_cef_host: Optional[str] = None
    ):
        self.kafka_topic = kafka_topic
        self.kuma_topic = kuma_topic
        self.kuma_cef_host = kuma_cef_host
        self.local_audit_log = []

    def to_cef(self, record: Dict[str, Any]) -> str:
        """
        Сериализует запись аудита в стандартный формат Common Event Format (CEF)
        для приема коллектором Kaspersky Unified Monitoring and Analysis Platform (KUMA).
        Формат: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        """
        event_type = record.get("event_type", "GENERIC_EVENT")
        mapping = self.EVENT_MAPPING.get(event_type, {
            "code": "GEN-001",
            "name": event_type,
            "severity": 3,
            "kuma_rule": None
        })

        details = record.get("details", {})
        tenant_id = record.get("tenant_id", "unknown-tenant")
        session_id = record.get("session_id", "unknown-session")
        src_ip = details.get("src_ip", "127.0.0.1")
        msg = details.get("msg", event_type)
        model = details.get("model", "unknown-model")
        tax_ms = details.get("proxy_tax_ms", 0.0)

        cef_string = (
            f"CEF:0|AlfaBank|AlfaAIGateway|2.4.0|{mapping['code']}|{mapping['name']}|"
            f"{mapping['severity']}|src={src_ip} suser={tenant_id} msg={msg} "
            f"cs1Label=Model cs1={model} cs2Label=SessionID cs2={session_id} "
            f"cs3Label=ProxyTaxMs cs3={tax_ms}"
        )
        return cef_string

    def log_event(
        self,
        event_type: str,
        tenant_id: str,
        priority: str,
        session_id: str,
        details: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Emits an immutable audit record and attaches Kaspersky KUMA CEF payload.
        Events: PII_MASKED, JAILBREAK_BLOCKED, CIRCUIT_TRIPPED, NLI_CONTRADICTION, etc.
        """
        record = {
            "timestamp": time.time(),
            "event_type": event_type,
            "tenant_id": tenant_id,
            "priority": priority,
            "session_id": session_id,
            "details": details,
            "worm_sealed": True
        }
        
        # Генерация CEF-события для интеграции с KUMA SIEM
        record["cef_payload"] = self.to_cef(record)
        
        self.local_audit_log.append(record)
        # В production контуре:
        # 1. Отправка в Kafka WORM топик: kafka_producer.send(self.kafka_topic, json.dumps(record))
        # 2. Передача в коллектор KUMA SIEM: syslog_tls.send(record["cef_payload"])
        return record

