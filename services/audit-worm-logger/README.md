# Audit WORM Logger (`audit-worm-logger`)

Сервис неизменяемого аудита информационной безопасности и экспорта метрик.

### Возможности:
- Сброс событий безопасности (PII маскирование, атаки, переключения Circuit Breaker) в Apache Kafka с флагом WORM (Write Once, Read Many).
- Экспорт Prometheus-метрик: Proxy Tax latency, TTFT, Token Generation Rate, Circuit Breaker Fallback Counts.
- Соответствие стандартам Банка России 683-П и 716-П.
