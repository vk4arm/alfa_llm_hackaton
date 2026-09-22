# Архитектурные решения: Корпоративный LLM-прокси (AI Gateway) для банка

Документ описывает техническую архитектуру, компоненты, алгоритмы устойчивости к нагрузкам, механизмы российской цензуры, защиты персональных данных и предотвращения галлюцинаций в корпоративном LLM-шлюзе банка (с акцентом на работу с китайскими моделями семейств **Qwen 2.5** и **DeepSeek**).

---

## 1. Архитектурные цели и принципы проектирования

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       КЛЮЧЕВЫЕ АРХИТЕКТУРНЫЕ СТОЛПЫ                         │
├───────────────────┬────────────────────┬──────────────────┬─────────────────┤
│   Zero-Trust &    │ High Availability  │ Low Latency &    │ Explainability  │
│  Data Sovereignty │  & Overload Guard  │ Smart Caching    │ & Fact Integrity│
│  (152-ФЗ / 395-1) │ (Circuit Breaker)  │  (< 20 ms tax)   │ (NLI Grounding) │
└───────────────────┴────────────────────┴──────────────────┴─────────────────┘
```

1. **Изоляция данных (Zero-Trust & Air-Gap):** Прокси и все модели инференса разворачиваются исключительно во внутреннем закрытом контуре банка. Ни один байт данных клиентов не покидает сетевой периметр.
2. **Нулевая утечка ПДн в веса и логи (Zero-PII Vault):** Персональные данные и банковская тайна маскируются до попадания в модель и размаскируются перед выдачей клиенту. Модель оперирует только синтетическими псевдотокенами.
3. **Устойчивость к исчерпанию GPU (Adaptive Overload Protection):** Инференс больших моделей нестабилен по времени и памяти. Архитектура гарантирует непрерывность обслуживания через Circuit Breaker, адаптивный сброс очередей (Load Shedding) и каскадный фоллбэк на более легкие квантованные модели.
4. **Двухуровневые Guardrails без ущерба производительности:** Легковесные классификаторы (<10 мс) на входе и выходе; ресурсоемкий факт-чекинг (NLI) применяется только к RAG-сценариям с критичными финансовыми данными.
5. **Совместимость с OpenAI API:** Унифицированный протокол `/v1/chat/completions` со стримингом токенов (Server-Sent Events) для бесшовной интеграции с корпоративными сервисами банка.

---

## 2. Диаграмма 1: Общая топология корпоративного контура банка

Детальное разделение сетевых периметров: клиентские приложения в ДМЗ, кластер LLM-прокси в сервисном контуре и защищенный пул серверов инференса vLLM с моделями Qwen и DeepSeek.

```mermaid
%%{init: {
  'theme': 'base',
  'themeVariables': {
    'primaryColor': '#eff6ff',
    'primaryBorderColor': '#3b82f6',
    'primaryTextColor': '#1e3a8a',
    'lineColor': '#475569',
    'fontFamily': 'Inter, system-ui, sans-serif'
  }
}}%%
flowchart TB
    subgraph DMZ[" 🌐 ВНЕШНИЙ КОНТУР И КЛИЕНТСКИЕ СИСТЕМЫ (DMZ) "]
        direction LR
        Mobile["📱 Мобильный банк<br/>(iOS / Android)"]
        WebClient["💻 Интернет-банк<br/>(Web SPA)"]
        OperatorUI["🎧 АРМ Оператора<br/>(Контакт-центр)"]
        BackOffice["🏢 Бэк-офис & CRM<br/>(Внутренние АС)"]
    end

    subgraph SEC_LAYER[" 🛡️ ПЕРИМЕТР БЕЗОПАСНОСТИ (WAF / mTLS / API Gateway) "]
        WAF["Корпоративный WAF & API Gateway<br/>(Rate Limit, mTLS, JWT Валидация)"]
    end

    subgraph PROXY_CORE[" ⚡ КЛАСТЕР LLM-ПРОКСИ (AI GATEWAY CORE) "]
        direction TB
        
        subgraph IngressPipe["1. Входной конвейер (Pre-processing)"]
            AuthMod["🔑 RBAC & Квоты<br/>(Token Bucket)"]
            PIIMask["🔒 Zero-PII Vault<br/>(Luhn, Regex, NER)"]
            InpTox["🛡️ Ru-Guardrails In<br/>(Toxicity & Jailbreak)"]
        end

        subgraph RoutingPipe["2. Интеллектуальная маршрутизация & Кэш"]
            SemCache["⚡ Semantic Cache<br/>(Redis + Vector)"]
            CircuitBrk["🛑 Circuit Breaker &<br/>Priority Queues"]
            Router["🔀 Model Selector &<br/>Prefix-Aware Load Balancer"]
        end

        subgraph EgressPipe["3. Выходной конвейер (Post-processing)"]
            OutTox["💬 Output Tone &<br/>Toxicity Classifier"]
            FactGuard["⚖️ NLI Fact Checker<br/>(RAG Faithfulness)"]
            PIIUnmask["🔓 Zero-PII Restore<br/>(Де-анонимизация)"]
        end

        IngressPipe --> RoutingPipe
        RoutingPipe --> EgressPipe
    end

    subgraph INFRA_STORAGE[" 💾 ХРАНИЛИЩА СОСТОЯНИЙ И ТЕЛЕМЕТРИИ "]
        direction TB
        RedisVault[("🗄️ Redis Cluster<br/>• Session PII Map (TTL=300s)<br/>• Quotas & Token Bucket")]
        VectorCache[("🔍 Vector DB (Qdrant / Milvus)<br/>• Semantic Cache Embeddings<br/>• RuJailbreak Vectors")]
        KafkaAudit[("🛡️ Kaspersky KUMA SIEM & Kafka<br/>• CEF Format & Correlation<br/>• Immutable WORM Audit")]
    end

    subgraph ONPREM_GPU[" 🚀 ИЗОЛИРОВАННЫЙ ON-PREM GPU-КЛАСТЕР (vLLM / SGLang) "]
        direction TB
        subgraph Tier1["Tier-1: Основной пул (High-Precision)"]
            Qwen72B["👑 Qwen-2.5-72B-Instruct<br/>(4-8x NVIDIA A100 / H100)"]
            DeepSeek["🧠 DeepSeek-V3 / R1 (MoE)<br/>(Cluster vLLM Pods)"]
        end
        subgraph Tier2["Tier-2: Резервный пул (Fallback & Mid-Load)"]
            Qwen32B["⚡ Qwen-2.5-32B-Instruct<br/>(2x NVIDIA A100)"]
            Qwen14B["⚡ Qwen-2.5-14B-Instruct<br/>(1x NVIDIA A100)"]
        end
        subgraph Tier3["Tier-3: Экстренный пул (Ultra-Fast / Degradation)"]
            Qwen7B["🚨 Qwen-2.5-7B-AWQ / INT4<br/>(T4 / A10 / CPU-Fallback)"]
        end
    end

    %% Связи потоков
    Mobile & WebClient & OperatorUI & BackOffice --> WAF
    WAF --> AuthMod
    AuthMod --> PIIMask --> InpTox --> SemCache

    SemCache -- "Кэш HIT (Латентность < 15 мс)" --> PIIUnmask
    SemCache -- "Кэш MISS" --> CircuitBrk --> Router

    Router -- "Нормальная нагрузка" --> Tier1
    Router -- "Tier-1 перегружен (CB Open)" --> Tier2
    Router -- "Критический пик" --> Tier3

    Tier1 & Tier2 & Tier3 --> OutTox --> FactGuard --> PIIUnmask
    PIIUnmask --> WAF

    %% Инфраструктурные связи
    PIIMask <--> RedisVault
    PIIUnmask <--> RedisVault
    AuthMod <--> RedisVault
    SemCache <--> VectorCache
    InpTox -.-> VectorCache
    IngressPipe & EgressPipe & CircuitBrk -.-> KafkaAudit

    %% Стилизация
    classDef clientNode fill:#f0f9ff,stroke:#0284c7,stroke-width:2px,color:#0369a1,rx:6,ry:6;
    classDef secNode fill:#fef2f2,stroke:#ef4444,stroke-width:2px,color:#991b1b,rx:6,ry:6;
    classDef proxyNode fill:#eff6ff,stroke:#2563eb,stroke-width:2px,color:#1e40af,rx:6,ry:6;
    classDef storageNode fill:#fefce8,stroke:#eab308,stroke-width:2px,color:#854d0e,rx:6,ry:6;
    classDef gpuTier1 fill:#f0fdf4,stroke:#16a34a,stroke-width:2px,color:#14532d,rx:6,ry:6;
    classDef gpuTier2 fill:#ecfdf5,stroke:#059669,stroke-width:2px,color:#065f46,rx:6,ry:6;
    classDef gpuTier3 fill:#fff7ed,stroke:#ea580c,stroke-width:2px,color:#9a3412,rx:6,ry:6;

    class Mobile,WebClient,OperatorUI,BackOffice clientNode;
    class WAF secNode;
    class AuthMod,PIIMask,InpTox,SemCache,CircuitBrk,Router,OutTox,FactGuard,PIIUnmask proxyNode;
    class RedisVault,VectorCache,KafkaAudit storageNode;
    class Qwen72B,DeepSeek gpuTier1;
    class Qwen32B,Qwen14B gpuTier2;
    class Qwen7B gpuTier3;
```

---

## 3. Диаграмма 2: Сквозной жизненный цикл запроса (Sequence Diagram)

Визуализация полного пути обработки транзакции с подсветкой этапов жизненного цикла.

```mermaid
%%{init: {
  'theme': 'base',
  'themeVariables': {
    'primaryColor': '#eff6ff',
    'primaryTextColor': '#1e293b',
    'primaryBorderColor': '#3b82f6',
    'lineColor': '#64748b',
    'actorBkg': '#1e293b',
    'actorBorder': '#0f172a',
    'actorTextColor': '#ffffff',
    'signalColor': '#2563eb',
    'signalTextColor': '#1e293b',
    'activationBkgColor': '#dbeafe',
    'activationBorderColor': '#3b82f6',
    'noteBkgColor': '#fef3c7',
    'noteBorderColor': '#f59e0b',
    'noteTextColor': '#92400e',
    'fontFamily': 'Inter, system-ui, sans-serif'
  }
}}%%
sequenceDiagram
    autonumber
    actor App as 📱 Клиентский сервис
    participant GW as ⚡ LLM Proxy
    participant Vault as 🔒 PII Vault (Redis)
    participant GuardIn as 🛡️ Input Guardrails
    participant Cache as ⚡ Semantic Cache
    participant CB as 🛑 Circuit Breaker
    participant LLM as 🧠 vLLM (Qwen-72B)
    participant GuardOut as ⚖️ Output Fact/Tox Guard

    rect rgb(240, 249, 255)
        Note over App,GW: ЭТАП 1: Аутентификация, Лимиты и Обезличивание
        App->>+GW: POST /v1/chat/completions (Промпт + ПДн клиента)
        GW->>GW: Проверка API-Key / JWT и остатка токенов (Token Bucket)
        GW->>+Vault: Обезличивание: замена паспорта, карт, ФИО на псевдотокены
        Vault-->>-GW: Очищенный промпт + session_id (TTL=300с)
    end

    rect rgb(254, 242, 242)
        Note over GW,GuardIn: ЭТАП 2: Входной комплаенс и цензура
        GW->>+GuardIn: Проверка: RuJailbreak + RuBERT-Tiny-Toxicity (< 10 мс)
        alt Запрос содержит мат / инъекцию
            GuardIn-->>GW: ❌ Нарушение политик (Policy Violation)
            GW-->>App: 400 Bad Request ("Запрос отклонен системой безопасности")
        else Запрос безопасен
            GuardIn-->>-GW: ✅ Одобрено
        end
    end

    rect rgb(254, 252, 232)
        Note over GW,Cache: ЭТАП 3: Семантическое кэширование
        GW->>+Cache: Проверка схожести эмбеддинга (Cosine Similarity > 0.95)
        alt Попадание в кэш (Cache Hit)
            Cache-->>GW: Сохраненный ответ (Latency ~12 мс)
        else Промах (Cache Miss)
            Cache-->>-GW: MISS (Переход к генерации)
        end
    end

    rect rgb(240, 253, 244)
        Note over GW,LLM: ЭТАП 4: Отказоустойчивый инференс
        alt Кэш промахнулся
            GW->>+CB: Запрос слота выполнения (Проверка состояния цепи)
            alt Цепь CLOSED (В норме)
                CB->>+LLM: Запрос инференса (Streaming SSE)
                LLM-->>-CB: Поток токенов от Qwen-2.5-72B
                CB-->>-GW: Успешный сырой ответ
            else Цепь OPEN (Перегрузка / Latency > SLA)
                CB->>CB: Fallback: вызов резервной Qwen-2.5-14B / 32B
                CB-->>GW: Ответ резервной модели
            end
        end
    end

    rect rgb(245, 243, 255)
        Note over GW,GuardOut: ЭТАП 5: Верификация ответа и восстановление данных
        GW->>+GuardOut: 1) Проверка тональности<br/>2) NLI-проверка фактов (Faithfulness против RAG-контекста)
        alt Обнаружена галлюцинация фактов
            GuardOut-->>GW: ⚠️ Faithfulness Score < 0.85
            GW->>GW: Подстановка безопасной заглушки («Недостаточно данных в регламенте»)
        else Ответ достоверен
            GuardOut-->>-GW: ✅ Ответ верифицирован
        end

        GW->>+Vault: Де-анонимизация (замена [TOKEN_1] на реальные значения)
        Vault-->>-GW: Персонализированный финальный текст
    end

    GW-->>-App: 200 OK (Stream SSE / JSON Response)
    Note over GW: Асинхронный сброс метрик в Prometheus и CEF-событий в Kaspersky KUMA SIEM
```

---

## 4. Диаграмма 3: Защита от перегрузки (Circuit Breaker & Fallback Cascade)

Детальная машина состояний с критериями перехода и алгоритм каскадного переключения моделей.

```mermaid
%%{init: {
  'theme': 'base',
  'themeVariables': {
    'primaryColor': '#eff6ff',
    'primaryBorderColor': '#3b82f6',
    'lineColor': '#475569',
    'fontFamily': 'Inter, system-ui, sans-serif'
  }
}}%%
stateDiagram-v2
    direction TB

    state "🟢 СОСТОЯНИЕ: CLOSED (Штатный режим)" as StateClosed {
        [*] --> Monitoring
        Monitoring --> InspectMetrics : Сбор TTFT, P99 Latency, Error Rate (5xx)
        InspectMetrics --> Monitoring : Ошибки < 5% И P99 < 2500 мс
    }

    state "🔴 СОСТОЯНИЕ: OPEN (Защита от перегрузки)" as StateOpen {
        [*] --> FastFailover
        FastFailover --> CascadeFallback : Мгновенное перенаправление на Tier-2/Tier-3
        FastFailover --> ShedLoad : Сброс фоновых низкоприоритетных задач (HTTP 429)
        FastFailover --> CooldownTimer : Ожидание восстановления (30 секунд)
    }

    state "🟡 СОСТОЯНИЕ: HALF-OPEN (Пробное зондирование)" as StateHalfOpen {
        [*] --> CanaryProbe
        CanaryProbe --> SendCanaryTraffic : 5% запросов направляются на основной пул
        SendCanaryTraffic --> EvaluateCanary : Анализ успешности пробных запросов
    }

    StateClosed --> StateOpen : Ошибки > 15% ИЛИ Latency P99 > 5000 мс ИЛИ KV-кэш > 95%
    StateOpen --> StateHalfOpen : Таймер Cooldown истек (30с)
    StateHalfOpen --> StateClosed : Успешность пробных запросов > 95%
    StateHalfOpen --> StateOpen : Сбои в пробном трафике (Повторный таймер)
```

### Алгоритм каскадной деградации (Decision Tree)

```mermaid
%%{init: {
  'theme': 'base',
  'themeVariables': {
    'primaryColor': '#f8fafc',
    'primaryBorderColor': '#64748b',
    'lineColor': '#475569',
    'fontFamily': 'Inter, system-ui, sans-serif'
  }
}}%%
flowchart TD
    ReqIn(["Входящий запрос"]) --> CheckPri{"Класс обслуживания (QoS)?"}
    
    CheckPri -- "High: Мобильный банк / Чат клиента" --> RouteTier1["1. Попытка: Qwen-2.5-72B"]
    CheckPri -- "Medium: Внутренние АС / CRM" --> CheckGPU{"Загрузка GPU кластера?"}
    CheckPri -- "Low: Фоновый скоринг / Батчи" --> PriorityQueue["Постановка в буферную очередь (Fair Queue)"]

    CheckGPU -- "< 75%" --> RouteTier1
    CheckGPU -- ">= 75%" --> RouteTier2["2. Попытка: Qwen-2.5-32B"]

    RouteTier1 --> StatusT1{"Статус ответа Tier-1?"}
    StatusT1 -- "200 OK (Latency < 2.5s)" --> Deliver(["Возврат клиенту"])
    StatusT1 -- "Timeout / 503 / CB Open" --> RouteTier2

    RouteTier2 --> StatusT2{"Статус ответа Tier-2?"}
    StatusT2 -- "200 OK" --> Deliver
    StatusT2 -- "Перегружен" --> RouteTier3["3. Попытка: Qwen-2.5-14B / 7B-AWQ"]

    RouteTier3 --> StatusT3{"Статус ответа Tier-3?"}
    StatusT3 -- "200 OK" --> Deliver
    StatusT3 -- "Полный отказ всех GPU" --> FallbackCache["4. Семантический кэш / Регламентированная заглушка (429 + Retry-After)"]

    classDef okNode fill:#f0fdf4,stroke:#16a34a,stroke-width:2px,color:#14532d;
    classDef warnNode fill:#fefce8,stroke:#ca8a04,stroke-width:2px,color:#854d0e;
    classDef alertNode fill:#fef2f2,stroke:#dc2626,stroke-width:2px,color:#991b1b;
    classDef normalNode fill:#f1f5f9,stroke:#475569,stroke-width:1.5px,color:#1e293b;

    class Deliver okNode;
    class RouteTier2,RouteTier3 warnNode;
    class FallbackCache alertNode;
    class ReqIn,CheckPri,CheckGPU,RouteTier1,PriorityQueue normalNode;
```

---

## 5. Диаграмма 4: Двухуровневый конвейер цензуры и факт-чекинга (Guardrails Pipeline)

```mermaid
%%{init: {
  'theme': 'base',
  'themeVariables': {
    'primaryColor': '#eff6ff',
    'primaryBorderColor': '#3b82f6',
    'lineColor': '#475569',
    'fontFamily': 'Inter, system-ui, sans-serif'
  }
}}%%
flowchart LR
    subgraph STAGE_IN[" 🛡️ ЭТАП 1: Входные фильтры (Latency < 12 мс) "]
        direction TB
        RawIn["Исходный запрос клиента"] --> DetectJailbreak["Детектор инъекций:<br/>RuJailbreak + Cosine Similarity"]
        DetectJailbreak --> InpToxModel["RuBERT-Tiny-Toxicity:<br/>Мат, оскорбления, агрессия"]
        InpToxModel --> PII_Extractor["Экстрактор ПДн:<br/>Regex (карты/паспорта) + Natasha NER"]
        PII_Extractor --> CleanPrompt["Обезличенный валидный промпт"]
    end

    subgraph STAGE_LLM[" 🧠 ЭТАП 2: Инференс "]
        direction TB
        CleanPrompt --> ModelGen["vLLM Генерация<br/>(Qwen-2.5 on-prem)"]
        ModelGen --> RawAnswer["Ответ модели"]
    end

    subgraph STAGE_OUT[" ⚖️ ЭТАП 3: Выходной контроль и факт-чекинг "]
        direction TB
        RawAnswer --> OutToxCheck["Ru-Toxicity Check:<br/>Тональность ответа модели"]
        OutToxCheck --> StopTopics["Регуляторный стоп-лист:<br/>ФЗ-114, 149-ФЗ, запрещенные темы"]
        StopTopics --> NLI_Eval["NLI Cross-Encoder:<br/>mDeBERTa-v3 / RuBERT-NLI<br/>(Faithfulness vs RAG Context)"]
        NLI_Eval --> NumAudit["Числовой аудитор:<br/>Сверка ставок, сумм и дат"]
        NumAudit --> SchemaCheck["JSON Schema Validator<br/>(Structured Output)"]
        SchemaCheck --> FinalApproved["Верифицированный ответ"]
    end

    STAGE_IN ==> STAGE_LLM ==> STAGE_OUT

    classDef stageIn fill:#f0f9ff,stroke:#0284c7,stroke-width:2px,color:#0369a1,rx:6,ry:6;
    classDef stageLLM fill:#f0fdf4,stroke:#16a34a,stroke-width:2px,color:#14532d,rx:6,ry:6;
    classDef stageOut fill:#fdf4ff,stroke:#a855f7,stroke-width:2px,color:#581c87,rx:6,ry:6;

    class RawIn,DetectJailbreak,InpToxModel,PII_Extractor,CleanPrompt stageIn;
    class ModelGen,RawAnswer stageLLM;
    class OutToxCheck,StopTopics,NLI_Eval,NumAudit,SchemaCheck,FinalApproved stageOut;
```

---

## 6. Диаграмма 5: Zero-PII Vault (Токенизация банковской тайны)

Схема гарантирует, что номера банковских карт, паспортные данные и ФИО клиентов не сохраняются в логах инференса модели и не попадают в кэш.

```mermaid
%%{init: {
  'theme': 'base',
  'themeVariables': {
    'primaryColor': '#eff6ff',
    'primaryBorderColor': '#3b82f6',
    'lineColor': '#475569',
    'fontFamily': 'Inter, system-ui, sans-serif'
  }
}}%%
flowchart TB
    subgraph Step1[" 1. ВХОДЯЩИЙ НЕОБРАБОТАННЫЙ ЗАПРОС "]
        RawUserMsg["'Переведи 15 000 руб с карты 4276 3800 1234 5678 на счет Иванова Петра Сергеевича, паспорт 4515 889900'"]
    end

    subgraph Step2[" 2. ДЕТЕКЦИЯ И ТОКЕНИЗАЦИЯ (ПРОКСИ) "]
        direction LR
        CardDetect["💳 Карта:<br/>Regex + Алгоритм Луна"]
        FioDetect["👤 ФИО:<br/>Natasha (Ru-NER)"]
        PassDetect["📄 Паспорт:<br/>Серия / Номер РФ"]
    end

    subgraph Step3[" 3. ЭФЕМЕРНЫЙ SESSION VAULT (REDIS) "]
        SessionMap[("🔑 Redis Session Vault (TTL = 300 сек)<br/>----------------------------------------<br/>[CARD_1]  ➔ '4276 3800 1234 5678'<br/>[FIO_1]   ➔ 'Иванов Петр Сергеевич'<br/>[PASS_1]  ➔ '4515 889900'")]
    end

    subgraph Step4[" 4. БЕЗОПАСНЫЙ ИНФЕРЕНС (ОБЕЗЛИЧЕННЫЙ) "]
        SanitizedPrompt["'Переведи 15 000 руб с карты [CARD_1] на счет [FIO_1], паспорт [PASS_1]'"]
        ModelExec["🧠 Модель Qwen-2.5-72B<br/>(В логах и KV-кэше НЕТ персональных данных)"]
        ModelRawResp["'Перевод 15 000 руб с карты [CARD_1] в адрес получателя [FIO_1] успешно подготовлен'"]
    end

    subgraph Step5[" 5. ДЕ-ТОКЕНИЗАЦИЯ И ВОЗВРАТ КЛИЕНТУ "]
        RestoreEngine["🔄 Процессор восстановления:<br/>Подстановка реальных данных из Redis Session Vault"]
        FinalClearResp["'Перевод 15 000 руб с карты 4276 3800 1234 5678 в адрес получателя Иванов Петр Сергеевич успешно подготовлен'"]
    end

    Step1 --> CardDetect & FioDetect & PassDetect
    CardDetect & FioDetect & PassDetect --> SessionMap
    CardDetect & FioDetect & PassDetect --> SanitizedPrompt
    SanitizedPrompt --> ModelExec --> ModelRawResp
    ModelRawResp --> RestoreEngine
    SessionMap --> RestoreEngine
    RestoreEngine --> FinalClearResp

    classDef plainBox fill:#f8fafc,stroke:#475569,stroke-width:1.5px,color:#1e293b,rx:6,ry:6;
    classDef detectBox fill:#e0f2fe,stroke:#0284c7,stroke-width:2px,color:#0369a1,rx:6,ry:6;
    classDef vaultBox fill:#fefce8,stroke:#ca8a04,stroke-width:2px,color:#854d0e,rx:6,ry:6;
    classDef safeBox fill:#f0fdf4,stroke:#16a34a,stroke-width:2px,color:#14532d,rx:6,ry:6;

    class RawUserMsg,FinalClearResp plainBox;
    class CardDetect,FioDetect,PassDetect,RestoreEngine detectBox;
    class SessionMap vaultBox;
    class SanitizedPrompt,ModelExec,ModelRawResp safeBox;
```

---

## 7. Диаграмма 6: Схема очередей с приоритетами (Fair Priority Queuing & QoS)

Гарантия того, что клиенты в мобильном банке получают ответ без задержек, даже если бэк-офис запустил пакетный анализ миллионов документов.

```mermaid
%%{init: {
  'theme': 'base',
  'themeVariables': {
    'primaryColor': '#eff6ff',
    'primaryBorderColor': '#3b82f6',
    'lineColor': '#475569',
    'fontFamily': 'Inter, system-ui, sans-serif'
  }
}}%%
flowchart LR
    subgraph INGRESS_STREAMS[" Входящие потоки трафика "]
        StreamVIP["🔴 Realtime / VIP (SLA < 1.5s)<br/>Чат моб. банка, Суфлер звонка"]
        StreamStd["🟡 Standard / Internal (SLA < 5s)<br/>CRM-ассистент, поиск регламентов"]
        StreamBatch["🟢 Batch / Offline (SLA < 30min)<br/>Скоринг архива, ночная суммаризация"]
    end

    subgraph QUEUE_ENGINE[" Диспетчер очередей (Weighted Fair Queuing) "]
        direction TB
        Q_High["Очередь P0 (Вес: 70%)<br/>Выделенный резерв GPU-слотов"]
        Q_Med["Очередь P1 (Вес: 20%)<br/>Динамический пул"]
        Q_Low["Очередь P2 (Вес: 10%)<br/>Фоновый пул со сбросом"]
    end

    subgraph SCHEDULER[" GPU Scheduler & Worker Pool "]
        WorkerAlloc["Планировщик воркеров:<br/>• Вытеснение фоновых задач при росте P0<br/>• Rate Limit по Tenant ID<br/>• Управление параллелизмом vLLM"]
    end

    subgraph EXECUTORS[" Доступные GPU слоты "]
        GPU_Slots["Инференс vLLM<br/>(Параллельные контекстные слоты PagedAttention)"]
    end

    StreamVIP --> Q_High
    StreamStd --> Q_Med
    StreamBatch --> Q_Low

    Q_High --> WorkerAlloc
    Q_Med --> WorkerAlloc
    Q_Low --> WorkerAlloc

    WorkerAlloc --> GPU_Slots

    classDef p0Style fill:#fef2f2,stroke:#ef4444,stroke-width:2px,color:#991b1b,rx:6,ry:6;
    classDef p1Style fill:#fefce8,stroke:#eab308,stroke-width:2px,color:#854d0e,rx:6,ry:6;
    classDef p2Style fill:#f0fdf4,stroke:#22c55e,stroke-width:2px,color:#14532d,rx:6,ry:6;
    classDef schedStyle fill:#eff6ff,stroke:#3b82f6,stroke-width:2px,color:#1e40af,rx:6,ry:6;

    class StreamVIP,Q_High p0Style;
    class StreamStd,Q_Med p1Style;
    class StreamBatch,Q_Low p2Style;
    class WorkerAlloc,GPU_Slots schedStyle;
```

---

## 8. Спецификация API и корпоративных заголовков

Прокси полностью поддерживает стандарт **OpenAI Chat Completions API**, расширяя его специфичными банковскими заголовками.

### 8.1. Заголовки запроса (Request Headers)
| Заголовок | Тип | Обязательный | Описание |
| :--- | :--- | :--- | :--- |
| `Authorization` | `Bearer <token>` | Да | Внутренний токен сервиса (интеграция с Keycloak / Единой платформой авторизации банка). |
| `X-Bank-Tenant-ID` | `string` | Да | Идентификатор подразделения/системы (`retail-mobile`, `contact-center`, `credit-underwriting`) для учета квот и биллинга (Chargeback). |
| `X-Bank-Priority` | `HIGH \| MEDIUM \| LOW` | Нет (default: `MEDIUM`) | Приоритет в очереди выполнения (Weighted Fair Queue). |
| `X-Bank-Guardrails` | `STRICT \| MODERATE \| AUDIT_ONLY` | Нет (default: `STRICT`) | Режим работы цензуры и детекции галлюцинаций. |
| `X-Bank-PII-Masking` | `BOOLEAN` | Нет (default: `true`) | Включение автоматического обезличивания персональных данных. |

### 8.2. Диагностические заголовки ответа (Response Headers)
| Заголовок | Значение | Описание |
| :--- | :--- | :--- |
| `X-LLM-Selected-Model` | `qwen-2.5-72b-instruct` | Модель, фактически выполнившая генерацию (с учетом фоллбэка). |
| `X-LLM-Fallback-Triggered` | `true \| false` | Флаг срабатывания каскадного переключения из-за перегрузки основного пула. |
| `X-LLM-Cache-Hit` | `true \| false` | Флаг мгновенного ответа из семантического кэша. |
| `X-LLM-TTFT-Ms` | `185` | Time-To-First-Token в миллисекундах. |
| `X-LLM-Total-Latency-Ms` | `840` | Полное время выполнения запроса со всеми проверками. |
| `X-Guardrails-Faithfulness` | `0.94` | Оценка достоверности фактов (NLI Score против переданного контекста). |

---

## 9. Рекомендуемый стек технологий для реализации

* **Ядро прокси (Gateway Core):** Python (FastAPI + AsyncIO + uvloop) ИЛИ Go (Gin/Fiber).
* **Сетевой балансировщик и Ingress:** Envoy Proxy / Nginx с поддержкой HTTP/2 и стриминга SSE.
* **Хранилище сессий и очередей:** Redis Cluster (распределенный Token Bucket, эфемерный Vault для ПДн с TTL).
* **Векторный поиск для кэша:** Qdrant / Milvus (хранение эмбеддингов типовых вопросов с порогом косинусной близости 0.95).
* **ML-компоненты безопасности (Ru-Guardrails on CPU/ONNX):**
  * `cointegrated/rubert-tiny-toxicity` (ONNX Runtime, задержка < 8 мс на обычном CPU).
  * `mDeBERTa-v3-base-xnli` (ONNX Runtime, NLI-верификация фактов).
  * Библиотека `natasha` + Сборка оптимизированных регулярных выражений (карты, паспорта, телефоны).
* **Инференс моделей:** vLLM / SGLang в Kubernetes (интеграция по стандартному протоколу vLLM OpenAI API).
* **Наблюдаемость и SIEM:** Prometheus (метрики RPS, TTFT, квоты) + Grafana + **Kaspersky KUMA SIEM** (неизменяемый WORM-аудит ИБ в формате CEF, Kafka topic `alfa.kuma.ai-gateway.events`).
* **Экосистема защиты контейнеров и хостов:** **Kaspersky Container Security (KCS)** (сканирование CVE образов и рантайм-защита подов Kubernetes) + **Kaspersky Security for Storage (KSS)** (проверка RAG-документов до векторизации) + **Kaspersky Anti Targeted Attack (KATA) / EDR Expert** (защита закрытого сегмента GPU-инференса).

---

## 10. Модель угроз и компенсация рисков

Полная спецификация модели угроз и архитектуры эшелонированной защиты представлена в отдельном документе:
👉 **[Модель угроз безопасности и компенсация рисков](file:///Users/victor/work/СТРАННОЕ/alfa/docs/THREAT_MODEL_AND_KASPERSKY_INTEGRATION.md)**

### Краткая сводка эшелонированной защиты:
1. **Kaspersky Unified Monitoring and Analysis Platform (KUMA SIEM):**
   * Прием событий аудита шлюза по стандарту CEF (Common Event Format) через mTLS Syslog или Kafka.
   * Реализация 4 специализированных правил корреляции: `ALFA_AI_001_JAILBREAK_BURST`, `ALFA_AI_002_MASS_DEANONYMIZATION`, `ALFA_AI_003_CIRCUIT_BREAKER_TRIPPED`, `ALFA_AI_004_SYSTEMATIC_HALLUCINATIONS`.
2. **Kaspersky Container Security (KCS):**
   * Предотвращение уязвимостей в цепочке поставок (Supply Chain): сканирование базовых образов Python 3.11 и бинарных зависимостей vLLM на известные CVE.
   * Контроль рантайма подов (`readOnlyRootFilesystem`), блокировка запуска несанкционированных процессов и попыток Container Escape.
3. **Kaspersky Security for Storage (KSS):**
   * Потоковая антивирусная и эвристическая проверка клиентских файлов и банковских выписок (PDF, DOCX) **до** их парсинга и занесения чанков в векторную базу Qdrant (защита от RAG Poisoning).
4. **Kaspersky Anti Targeted Attack (KATA) & EDR Expert:**
   * Глубокий анализ L7-трафика между шлюзом и кластером инференса vLLM; защита пространства ядра и CUDA-драйверов на физических нодах с NVIDIA A100.

