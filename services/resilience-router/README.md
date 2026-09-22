# Resilience Router & Circuit Breaker (`resilience-router`)

Диспетчер отказоустойчивости и каскадной деградации моделей.

### Возможности:
- Реализация машины состояний Circuit Breaker (CLOSED / OPEN / HALF-OPEN).
- Мониторинг насыщения KV-кэша vLLM (> 95%) и латентности TTFT.
- Каскадное переключение на резервные пулы: Tier-1 (72B) ➔ Tier-2 (32B) ➔ Tier-3 (14B/7B).
