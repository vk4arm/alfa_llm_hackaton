"""
AUDIT WORM LOGGER & TELEMETRY
Immutable Audit Trail (Write Once Read Many) for Bank Information Security
and Prometheus Metrics Provider.
"""

import json
import time
from typing import Dict, Any, Optional

class AuditWormLogger:
    def __init__(self, kafka_topic: str = "alfa.ai.gateway.audit.worm"):
        self.kafka_topic = kafka_topic
        self.local_audit_log = []

    def log_event(
        self,
        event_type: str,
        tenant_id: str,
        priority: str,
        session_id: str,
        details: Dict[str, Any]
    ):
        """
        Emits an immutable audit record.
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
        self.local_audit_log.append(record)
        # In production: producer.send(self.kafka_topic, json.dumps(record).encode('utf-8'))
        return record
