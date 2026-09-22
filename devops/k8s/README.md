# Kubernetes Deployment Manifests (`devops/k8s/`)

Комплект производственных манифестов для развертывания **Alfa AI Gateway** в корпоративном Kubernetes-кластере банка.

---

## 🏛️ Структура манифестов

| Файл | Назначение |
| :--- | :--- |
| **`00-namespace.yaml`** | Пространство имен `alfa-ai-gateway` со строгими Pod Security Standards (`restricted`). |
| **`01-config-secrets.yaml`** | ConfigMap с сетевыми адресами, порогами Circuit Breaker и секреты (Redis, Keycloak, Kafka). |
| **`02-network-policies.yaml`** | Сегментация Zero-Trust: запрет внешнего интернета (Air-Gap) и доступ только к On-Prem vLLM. |
| **`10-gateway-core.yaml`** | Основной API-шлюз (Deployment, ClusterIP Service, HorizontalPodAutoscaler 3–20 реплик). |
| **`11-zero-pii-vault.yaml`** | Модуль маскирования банковской тайны (152-ФЗ / 395-1) с горизонтальным масштабированием. |
| **`12-ru-guardrails.yaml`** | Сервис входной/выходной фильтрации атак и токсичности (< 10 мс). |
| **`13-resilience-router.yaml`** | Диспетчер Circuit Breaker и каскадного переключения моделей. |
| **`14-semantic-cache.yaml`** | Семантический векторный кэш для среза повторяющихся запросов. |
| **`15-nli-fact-guard.yaml`** | Cross-Encoder NLI и числовой аудитор финансовых регламентов. |
| **`16-audit-worm-logger.yaml`** | Неизменяемый WORM-аудит безопасности, стриминг CEF в **Kaspersky KUMA SIEM** и экспорт Prometheus-метрик. |
| **`20-infrastructure.yaml`** | Кластерный Redis (Session Vault) и Qdrant (Vector DB) в виде StatefulSet. |
| **`kustomization.yaml`** | Диспетчер сборки Kustomize для применения всего стека одной командой. |

---

## 🚀 Развертывание в кластере (Kustomize)

### 1. Тестовая валидация (Dry-Run):
```bash
kubectl apply -k devops/k8s/ --dry-run=client
```

### 2. Применение манифестов:
```bash
kubectl apply -k devops/k8s/
```

### 3. Проверка статуса подов:
```bash
kubectl get pods -n alfa-ai-gateway -o wide
```

---

## 🛡️ Требования к информационной безопасности и интеграция с «Лабораторией Касперского»:

1. **Kaspersky Unified Monitoring and Analysis Platform (KUMA SIEM):**
   - Модуль `audit-worm-logger` передает события безопасности (Jailbreak, PII Tokenization, Hallucination Contradiction, Circuit Tripped) по протоколу Syslog over TLS (порт 6514) в формате CEF (Common Event Format).
   - `NetworkPolicy` (`allow-egress-to-kuma-siem`) изолирует трафик, разрешая только порт 6514 и порт 9092 Kafka.
2. **Kaspersky Container Security (KCS):**
   - Все образы микросервисов перед деплоем проходят автоматическое сканирование KCS на известные CVE в библиотеках Python и бинарных модулях.
   - KCS Runtime Sensor контролирует поведение подов и предотвращает попытки Container Escape на физические хосты GPU.
3. **Air-Gap и сетевые политики (`NetworkPolicy`):**
   - Блокируются любые исходящие соединения во внешний интернет.
   - Разрешены только внутренние IP-адреса GPU-серверов инференса `10.120.45.0/24` (Tier-1 `Qwen-72B`, Tier-2 `Qwen-32B`, Tier-3 `Qwen-14B`).
4. **Безопасность контейнеров (`PodSecurityContext`):**
   - Все поды работают от непривилегированного пользователя (`runAsNonRoot: true`, `UID: 10001`).
   - Файловая система контейнеров смонтирована в режиме `readOnlyRootFilesystem: true`.
   - Запрещено повышение привилегий (`allowPrivilegeEscalation: false`).

