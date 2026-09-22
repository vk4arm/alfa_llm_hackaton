# Модель угроз безопасности и компенсация рисков

> 🛡️ **Интерактивная визуализация**: Доступна [**Интерактивная HTML-версия модели угроз**](threat_model.html) с живым симулятором CEF-событий для KUMA SIEM, интерактивным фильтром матрицы OWASP LLM 2025 и архитектурной картой эшелонированной защиты.

Документ определяет модель угроз для корпоративного LLM-шлюза банка (**Alfa AI Gateway**) в соответствии с требованиями **ФСТЭК России**, положений **Банка России 683-П / 716-П / 757-П**, стандарта **ГОСТ Р 57580.1**, классификации **OWASP Top 10 for LLM Applications (2025)**, а также регламентирует применение специализированных средств защиты информации и компенсации рисков (стек KUMA SIEM, KCS, KSS, KATA / EDR Expert, KWTS) и сопоставление с ведущими международными решениями (Splunk, Palo Alto Prisma Cloud, Trend Micro, CrowdStrike, Cloudflare).

---

## 1. Модель нарушителя и классификация угроз

### 1.1. Модель нарушителя
1. **Внешний злоумышленник (Н1):** не имеет легитимного доступа к сети банка; действует через публичный API мобильного банка или веб-интерфейс, пытаясь провести Prompt Injection, вызвать отказ в обслуживании (DoS GPU) или обойти антифрод.
2. **Недобросовестный внутренний пользователь / сотрудник (Н2):** имеет учетную запись во внутренних АС (CRM, бэк-офис); пытается извлечь конфиденциальные кредитные политики, персональные данные VIP-клиентов или системные промпты.
3. **Квалифицированная APT-группировка (Н3):** целенаправленная таргетированная атака на кластер серверов инференса с целью закрепления в закрытом сегменте ЦОД, компрометации весов моделей или отравления базы RAG.

---

### 1.2. Матрица угроз (OWASP LLM + Финтех-специфика)

| ID | Категория угрозы | Описание вектора атаки | Риски для банка | Эшелон нейтрализации в шлюзе | Компенсация угрозы |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TH-01** | **Prompt Injection & Jailbreak** (LLM01) | Внедрение скрытых инструкций (`DAN`, «забудь правила», Base64 обфускация) в запрос к чат-боту или кредитному суфлеру. | Несанкционированное одобрение условий, компрометация логики АС. | Входной фильтр **Ru-Guardrails** (RuJailbreak Cosine Matcher, < 10 мс). | **Kaspersky KUMA**: корреляционное правило `AI_RULE_JAILBREAK_SPIKE`. |
| **TH-02** | **Sensitive Data Leakage** (LLM02 / 152-ФЗ) | Случайная или умышленная передача номеров карт, паспортов РФ, выписок в запросах, их оседание в логах и весах. | Нарушение 152-ФЗ, 395-1 «О банковской тайне», штрафы ЦБ РФ. | **Zero-PII Vault**: алгоритм Луна, Natasha NER, эфемерный Redis TTL 300с. | **Kaspersky KUMA**: контроль аномального объема де-токенизации. |
| **TH-03** | **RAG Poisoning & Malicious Docs** (LLM04) | Загрузка в базу знаний скомпрометированных PDF/DOCX файлов с эксплойтами или искаженными регламентами. | Искажение ответов модели, выполнение вредоносного кода при парсинге. | Хеширование и подпись чанков регламентов в Qdrant. | **Kaspersky Security for Storage (KSS)**: глубокая проверка файлов до векторизации. |
| **TH-04** | **Financial Hallucination** (LLM05) | Искажение моделью процентных ставок по кредитам, лимитов или условий страхования при ответе клиенту. | Прямые финансовые и судебные претензии к банку. | **NLI Fact Guard** (mDeBERTa Cross-Encoder) + Числовой валидатор ставок. | **Kaspersky KUMA**: алерт при систематическом падении Faithfulness Score. |
| **TH-05** | **GPU Denial of Service** (LLM10) | Атака сверхдлинным контекстом (> 32k токенов) для переполнения KV-кэша и вызова Out-Of-Memory в vLLM. | Отказ обслуживания в мобильном банке в пиковые часы. | **Circuit Breaker** (отсечение при KV > 95%), Weighted Fair Queuing (QoS). | **Kaspersky Anti Targeted Attack (KATA)**: детекция L7 DoS аномалий. |
| **TH-06** | **Supply Chain & Model Tampering** (LLM03) | Внедрение бэкдоров в открытые веса (Qwen/DeepSeek), уязвимости в зависимостях (PyTorch, transformers, vLLM). | Удаленное выполнение кода (RCE) на GPU-серверах банка. | Изолированный Air-Gap контур, запрет внешней телеметрии. | **Kaspersky Container Security (KCS)**: сканирование образов и контроль рантайма. |
| **TH-07** | **System Prompt Leakage** (LLM07) | Извлечение внутренних алгоритмов скоринга и инструкций через наводящие вопросы. | Раскрытие коммерческой тайны и параметров кредитного конвейера. | **Ru-Guardrails Output Filter**: детекция маркеров системного контекста. | **Kaspersky KUMA**: фиксация инцидента утечки промпта. |
| **TH-08** | **Lateral Movement в контур GPU** | Попытка атакующего захватить соседние ноды кластера инференса после компрометации вспомогательного сервиса. | Полный захват вычислительного кластера ЦОД. | **Kubernetes NetworkPolicies** (Zero-Trust) + mTLS между подами. | **Kaspersky EDR Expert**: блокировка аномальных процессов на хостах. |

---

## 2. Архитектура интеграции со средствами компенсации рисков

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        ПЕРИМЕТР БЕЗОПАСНОСТИ ИБ БАНКА                                  │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│   [ Клиентский трафик ] ──> [ Kaspersky Web Traffic Security (KWTS) ]                   │
│                                           │                                            │
│                                           ▼                                            │
│   [ Входящие RAG-документы ] ──> [ Kaspersky Security for Storage (KSS) ]              │
│                                           │ (Проверка PDF/DOCX на эксплойты)           │
│                                           ▼                                            │
│   ┌────────────────────────── KUBERNETES КЛАСТЕР ──────────────────────────────────┐   │
│   │                                                                                │   │
│   │   [ Kaspersky Container Security (KCS) ] ──> Аудит образов и рантайма подов    │   │
│   │                                                                                │   │
│   │   [ Gateway Core ] ──> [ Zero-PII Vault ] ──> [ Ru-Guardrails ]                │   │
│   │          │                                                                     │   │
│   │          ▼                                                                     │   │
│   │   [ Audit WORM Logger ] ─── (Syslog / CEF по TLS) ──────────────┐              │   │
│   │                                                                 │              │   │
│   └─────────────────────────────────────────────────────────────────┼──────────────┘   │
│                                                                     │                  │
│                                                                     ▼                  │
│   ┌────────────────────────────────────────────────────────────────────────────┐       │
│   │              Kaspersky Unified Monitoring and Analysis Platform (KUMA)     │       │
│   │                 (Централизованная SIEM-система Банка)                      │       │
│   ├────────────────────────────────────────────────────────────────────────────┤       │
│   │  • Корреляция событий ИИ-шлюза (CEF формат)                                │       │
│   │  • Мониторинг атак Prompt Injection и де-маскирования                     │       │
│   │  • Сценарии инцидентного реагирования (Playbooks)                          │       │
│   └────────────────────────────────────────────────────────────────────────────┘       │
│                                                                                        │
│   [ Изолированные ноды GPU vLLM ] <──> [ Kaspersky Anti Targeted Attack (KATA/EDR) ]    │
│                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Детализация средств защиты и сопоставление с международными аналогами

Для обеспечения технологической нейтральности и гибкости архитектура шлюза спроектирована по принципу **Vendor-Agnostic Interface**: взаимодействие со средствами защиты осуществляется через стандартизированные протоколы (Syslog TLS / ArcSight CEF, ICAP, eBPF, OCI). Это позволяет использовать как развернутый в контуре банка стек продуктов, так и международные решения корпоративного класса (Global Tier-1):

| Класс средств защиты | Продукт в контуре банка | Международные аналоги (Global Tier-1) | Стандарт интеграции | Роль в контуре LLM-шлюза |
| :--- | :--- | :--- | :--- | :--- |
| **SIEM & Security Analytics** | **KUMA SIEM** | **Splunk Enterprise Security**, **IBM QRadar**, **Microsoft Sentinel**, **Elastic Security** | Syslog TLS (порт 6514), CEF, Kafka | Прием WORM-логов, корреляция всплесков Jailbreak и аномалий де-маскирования ПДн |
| **Container & K8s Security** | **Kaspersky Container Security (KCS)** | **Palo Alto Prisma Cloud**, **Aqua Security**, **Sysdig Secure**, **Wiz** | OCI Image Scan, eBPF sensor, K8s Admission | Сканирование образов Python/vLLM на CVE до релиза, блокировка Container Escape на GPU |
| **Storage & RAG Anti-Malware** | **Kaspersky Security for Storage (KSS)** | **Trend Micro Deep Security / Cloud One**, **Trellix Storage Security** | ICAP Protocol, RPC Storage API | Потоковый пре-скан клиентских PDF-досье и регламентов до векторизации в Qdrant |
| **EDR & Host Defense (GPU)** | **KATA & EDR Expert** | **CrowdStrike Falcon**, **SentinelOne Singularity**, **Microsoft Defender for Endpoint** | Linux Kernel Module, eBPF telemetry | Контроль целостности ядра Linux на серверах NVIDIA A100, защита видеодрайверов и CUDA |
| **Perimeter Web WAF & Proxy** | **Kaspersky Web Traffic Security (KWTS)** | **Cloudflare WAF / API Shield**, **F5 BIG-IP Advanced WAF**, **Akamai App & API Protector** | HTTP/2, WebSocket, ГОСТ TLS 1.3 | Фильтрация входящих клиентских сессий, защита от сетевого флуда и L7 DoS на периметре |

---

### 3.1. KUMA SIEM (Security Information and Event Management)
**Назначение:** центральный сбор, нормализация и корреляция событий безопасности со всех узлов LLM-шлюза.
* **Протокол передачи:** Syslog по TLS (mTLS) или выделенный топик Apache Kafka `alfa.kuma.ai-gateway.events`.
* **Формат данных:** Common Event Format (CEF).
* **Специализированные правила корреляции в KUMA:**
  1. `ALFA_AI_001_JAILBREAK_BURST`: фиксация более 3 попыток Prompt Injection в течение 60 секунд с одного IP/Tenant ID ➔ временная блокировка токена на уровне WAF.
  2. `ALFA_AI_002_MASS_DEANONYMIZATION`: превышение порога в 100 операций де-маскирования ПДн в минуту одним пользователем ➔ алерт в Security Operations Center (SOC) на риск дампа базы клиентов.
  3. `ALFA_AI_003_CIRCUIT_BREAKER_TRIPPED`: переход Circuit Breaker в состояние `OPEN` ➔ оповещение дежурного инженера эксплуатации GPU.
  4. `ALFA_AI_004_SYSTEMATIC_HALLUCINATIONS`: NLI Faithfulness Score < 0.50 в более чем 10% ответов за 15 минут ➔ сигнал о деградации весов модели или сбое RAG-поиска.

---

### 3.2. Kaspersky Container Security (KCS)
**Назначение:** защита жизненного цикла контейнеризации в среде Kubernetes (`alfa-ai-gateway`).
* **CI/CD сканирование (Pre-deployment):**
  * Проверка базовых образов Python 3.11 и бинарных зависимостей vLLM на известные CVE.
  * Поиск захардкоженных секретов, ключей API и сертификатов до деплоя в кластер.
* **Runtime Protection (В процессе работы):**
  * Блокировка попыток запуска неразрешенных бинарных файлов внутри контейнеров.
  * Контроль неизменяемости файловой системы (`readOnlyRootFilesystem`).
  * Предотвращение попыток выхода из контейнера (Container Escape) на хост-ноды с ускорителями NVIDIA A100.

---

### 3.3. Kaspersky Security for Storage (KSS)
**Назначение:** защита контура RAG (Retrieval-Augmented Generation) от вредоносных документов.
* В банковских сценариях сотрудники и клиенты загружают файлы (выписки, PDF-сканы паспортов, кредитные договоры).
* Модуль **KSS** осуществляет потоковую антивирусную проверку и эвристический анализ каждого документа **до** его передачи в парсеры текста и векторную базу Qdrant.
* Предотвращает эксплуатацию уязвимостей в библиотеках парсинга (PyPDF, pdfplumber, python-docx).

---

### 3.4. Kaspersky Anti Targeted Attack Platform (KATA) & EDR Expert
**Назначение:** защита сетевого контура и хостов инференса от сложных целевых атак (APT).
* **Сетевые сенсоры KATA:** глубокий анализ трафика между Шлюзом и пулом vLLM, обнаружение признаков эксплуатации сетевых протоколов и L7 DoS атак.
* **EDR-агенты на GPU-серверах:** мониторинг активности в пространстве ядра Linux, защита драйверов NVIDIA и CUDA-библиотек от несанкционированных инъекций памяти.

---

## 4. Спецификация формата событий CEF для SIEM-систем (KUMA, Splunk, QRadar)

Каждое критичное событие безопасности сериализуется модулем `audit-worm-logger` по стандарту ArcSight / KUMA CEF:

```
CEF:0|AlfaBank|AlfaAIGateway|2.4.0|{EventCode}|{EventName}|{Severity}|src={SourceIP} suser={TenantID} msg={Message} cs1Label=Model cs1={ModelName} cs2Label=SessionID cs2={SessionUUID} cs3Label=ProxyTaxMs cs3={LatencyMs}
```

### Примеры сформированных сообщений:

1. **Событие блокировки атаки Jailbreak (Severity: High / 8):**
   ```
   CEF:0|AlfaBank|AlfaAIGateway|2.4.0|SEC-001|PromptInjectionBlocked|8|src=10.14.22.81 suser=mobile-banking msg=Detected DAN jailbreak attempt cs1Label=Model cs1=qwen-2.5-72b cs2Label=Rule cs2=ru_jailbreak_cosine
   ```

2. **Событие маскирования банковской тайны (Severity: Low / 2):**
   ```
   CEF:0|AlfaBank|AlfaAIGateway|2.4.0|DLP-001|BankingSecrecyMasked|2|src=10.14.50.12 suser=crm-operator msg=Masked 1 credit card (Luhn valid) and 1 Russian passport cs2Label=SessionID cs2=550e8400-e29b-41d4-a716-446655440000
   ```

3. **Событие детекции галлюцинации по ставке вклада (Severity: Medium / 5):**
   ```
   CEF:0|AlfaBank|AlfaAIGateway|2.4.0|NLI-001|HallucinationBlocked|5|src=10.14.22.81 suser=retail-faq msg=Faithfulness score 0.14 below threshold 0.75. Rate contradiction: 24.5% vs 19.2% cs1Label=Model cs1=qwen-2.5-72b
   ```
