/**
 * ALFA AI GATEWAY — ARCHITECTURE PORTAL ENGINE
 * Interactive Schematics, Live Flow Simulation, Hardware Sizing & Inspector
 */

function initPortal() {
  // =========================================================================
  // 1. ДАННЫЕ 6 АРХИТЕКТУРНЫХ СХЕМ И УЗЛОВ
  // =========================================================================
  const SCHEMATICS_DATA = {
    'topology': {
      id: 'topology',
      title: 'Топология контуров банка и сегментация безопасности',
      tag: 'СХЕМА 1: СЕТЕВОЙ ПЕРИМЕТР',
      desc: 'Строгое разделение: клиентский ДМЗ, защищенный шлюз и изолированный On-Prem GPU-кластер vLLM.',
      mermaidKey: 'topology'
    },
    'sequence': {
      id: 'sequence',
      title: 'Сквозной жизненный цикл запроса (Sequence Flow)',
      tag: 'СХЕМА 2: ТРАНЗАКЦИОННЫЙ ЦИКЛ',
      desc: 'Пошаговый конвейер: Аутентификация ➔ Обезличивание ➔ Кэш ➔ Инференс ➔ NLI-аудит ➔ Де-маскирование.',
      mermaidKey: 'sequence'
    },
    'circuit-breaker': {
      id: 'circuit-breaker',
      title: 'Circuit Breaker и каскадная деградация моделей (72B ➔ 32B ➔ 14B)',
      tag: 'СХЕМА 3: ОТКАЗОУСТОЙЧИВОСТЬ',
      desc: 'Машина состояний Hystrix-паттерна и дерево решений перенаправления трафика при перегрузке GPU.',
      mermaidKey: 'circuit-breaker'
    },
    'guardrails': {
      id: 'guardrails',
      title: 'Двухуровневый контур цензуры и анти-галлюцинаций (Guardrails)',
      tag: 'СХЕМА 4: ИНФОРМАЦИОННАЯ БЕЗОПАСНОСТЬ',
      desc: 'Входные сверхбыстрые фильтры (<10 мс) + выходной NLI Cross-Encoder факт-чекинг кредитных регламентов.',
      mermaidKey: 'guardrails'
    },
    'vault': {
      id: 'vault',
      title: 'Zero-PII Vault: Обратимое маскирование банковской тайны (152-ФЗ / 395-1)',
      tag: 'СХЕМА 5: ЗАЩИТА ДАННЫХ',
      desc: 'Алгоритм Луна для карт, паспорта РФ, Natasha Ru-NER и эфемерный Redis Session Vault с TTL 300с.',
      mermaidKey: 'vault'
    },
    'qos': {
      id: 'qos',
      title: 'Fair Priority Queuing & Управление качеством обслуживания (QoS)',
      tag: 'СХЕМА 6: УПРАВЛЕНИЕ НАГРУЗКОЙ',
      desc: 'Приоритизация очередей: Выделенный резерв для мобильного банка и вытеснение фонового скоринга.',
      mermaidKey: 'qos'
    }
  };

  // Технические спецификации компонентов для инспектора (Side Drawer)
  const NODE_SPECS = {
    'mobile-app': {
      title: 'Мобильный банк (iOS / Android)',
      sub: 'Критичный клиентский канал (Realtime P0)',
      icon: '📱',
      sla: 'P99 < 1 500 мс | Доступность 99.99%',
      tax: '0 мс (Источник запроса)',
      hw: 'Клиентские устройства / mTLS Pinning',
      sec: 'GOST TLS 1.3, JWT Device Token, WAF защита от ботнетов',
      desc: 'Основной канал коммуникации розничных клиентов банка. Запросы обслуживаются по наивысшему приоритету P0. При перегрузках инференса гарантируется резерв GPU-мощностей.'
    },
    'waf-ingress': {
      title: 'WAF & Ingress API Gateway',
      sub: 'Периметр защиты и маршрутизации банка',
      icon: '🛡️',
      sla: 'P99 < 5 мс | 50 000 RPS',
      tax: '3.2 мс',
      hw: 'Envoy / Nginx Cluster (3x реплики)',
      sec: 'mTLS терминация, проверка подписи JWT Keycloak, Rate Limiting (Token Bucket)',
      desc: 'Точка входа всех входящих запросов. Проверяет сертификаты, валидирует заголовок X-Bank-Tenant-ID и ограничивает всплески трафика.'
    },
    'zero-pii-vault': {
      title: 'Zero-PII Vault Tokenizer',
      sub: 'Обезличивание персональных данных и тайны',
      icon: '🔒',
      sla: 'P99 < 8 мс | 100% точность Luhn',
      tax: '4.8 мс',
      hw: 'CPU Nodes (Natasha Ru-NER + C-Regex extensions)',
      sec: 'Соответствие 152-ФЗ, 395-1 «О банковской тайне», ЦБ РФ 683-П',
      desc: 'Мгновенно детектирует 16-значные карты по алгоритму Луна, серии/номера паспортов РФ и ФИО клиентов. Заменяет их на синтетические токены [CARD_1], [FIO_1], а реальные значения кладет в Redis с TTL=300с.'
    },
    'ru-guardrails-in': {
      title: 'Ru-Guardrails Input Filter',
      sub: 'Детектор инъекций и токсичности',
      icon: '⚔️',
      sla: 'P99 < 10 мс',
      tax: '6.5 мс',
      hw: 'ONNX Runtime CPU / 2 Cores',
      sec: 'cointegrated/rubert-tiny-toxicity + RuJailbreak база эмбеддингов',
      desc: 'Фильтрует вредоносные промпты (Jailbreak, DAN-режимы), мат, оскорбления и угрозы до обращения к дорогостоящим GPU-моделям.'
    },
    'semantic-cache': {
      title: 'Semantic Cache (Redis + Vector DB)',
      sub: 'Интеллектуальное кэширование ответов',
      icon: '⚡',
      sla: 'P99 < 15 мс (Cache Hit)',
      tax: '8.1 мс при поиске',
      hw: 'Qdrant Cluster + Redis Enterprise (RAM)',
      sec: 'Хранение только обезличенных векторов, изоляция по тенантам',
      desc: 'Ищет семантически близкие вопросы по косинусной близости эмбеддингов (порог > 0.95). Срезает до 35% нагрузки со стандартных FAQ-запросов контакт-центра.'
    },
    'circuit-router': {
      title: 'Circuit Breaker & Smart Router',
      sub: 'Диспетчер нагрузки и каскадный балансировщик',
      icon: '🔀',
      sla: 'P99 < 2 мс | Hystrix Pattern',
      tax: '1.2 мс',
      hw: 'Встроенный в ядро прокси Go/Python движок',
      sec: 'Защита от каскадных сбоев, изоляция пулов инференса',
      desc: 'Контролирует saturation KV-кэша, TTFT и ошибки 5xx. При сбое нод Qwen-72B мгновенно перенаправляет поток на резервный кластер Qwen-32B без обрыва сессии клиента.'
    },
    'qwen-72b': {
      title: 'Tier-1: Qwen-2.5-72B-Instruct',
      sub: 'Основной пул высокой точности (On-Prem)',
      icon: '👑',
      sla: 'TTFT ~ 180 мс | Скорость 45 токенов/с',
      tax: '600–1200 мс генерация',
      hw: '4-8x NVIDIA A100 80GB NVLink / H100 (vLLM PagedAttention)',
      sec: 'Полный Air-Gap контур, отключение внешней телеметрии',
      desc: 'Флагманская модель для комплексных задач: кредитный скоринг, юридический анализ документов, сложные финансовые консультации.'
    },
    'qwen-32b': {
      title: 'Tier-2: Qwen-2.5-32B / 14B',
      sub: 'Резервный пул и средняя нагрузка',
      icon: '⚡',
      sla: 'TTFT ~ 110 мс | Скорость 85 токенов/с',
      tax: '300–600 мс генерация',
      hw: '2x NVIDIA A100 (vLLM Continuous Batching)',
      sec: 'On-premise периметр банка',
      desc: 'Быстрая модель для подхвата трафика при перегрузке Tier-1, а также для стандартных диалогов суфлера контакт-центра.'
    },
    'qwen-7b': {
      title: 'Tier-3: Qwen-2.5-7B-AWQ',
      sub: 'Экстренный пул низкой задержки (Low-Latency Fallback)',
      icon: '🚨',
      sla: 'TTFT ~ 45 мс | Скорость 140 токенов/с',
      tax: '120–250 мс генерация',
      hw: '1x NVIDIA T4 / A10 или CPU-кластер',
      sec: 'Изолированный контур',
      desc: 'Используется для мгновенной классификации, суммаризации и экстренного обслуживания клиентов при полном отказе тяжелых GPU.'
    },
    'nli-fact-guard': {
      title: 'NLI Fact Checker (Анти-галлюцинатор)',
      sub: 'Верификация фактов относительно регламентов',
      icon: '⚖️',
      sla: 'P99 < 15 мс',
      tax: '12.4 мс',
      hw: 'ONNX Runtime (mDeBERTa-v3 / RuBERT-NLI)',
      sec: 'Контроль искажения ставок, лимитов и тарифов',
      desc: 'Оценивает логическое следование (Entailment vs Contradiction) между сгенерированным текстом и официальным RAG-регламентом банка.'
    },
    'kafka-siem': {
      title: 'Apache Kafka SIEM WORM Trail',
      sub: 'Шина неизменяемого аудита ИБ',
      icon: '📨',
      sla: 'P99 < 5 мс (Async Write)',
      tax: '0 мс (Фоновый сброс)',
      hw: 'Kafka Cluster 3x брокера',
      sec: 'WORM (Write Once Read Many), аудит инцидентов ИБ 24/7',
      desc: 'Фиксирует каждое событие маскирования, блокировки атак, фактчекинга и переключения Circuit Breaker для расследований безопасности.'
    }
  };

  // Исходные Mermaid коды схем
  const MERMAID_SOURCES = {
    'topology': `flowchart TB
    subgraph DMZ[" 🌐 КЛИЕНТСКИЕ СИСТЕМЫ (DMZ) "]
        Mobile["📱 Мобильный банк"]
        WebClient["💻 Интернет-банк"]
        OperatorUI["🎧 АРМ Оператора"]
    end

    subgraph PROXY_CORE[" ⚡ КЛАСТЕР LLM-ПРОКСИ (AI GATEWAY) "]
        WAF["🛡️ Ingress WAF & API-Key"]
        PIIMask["🔒 Zero-PII Vault (Luhn / NER)"]
        InpTox["⚔️ Ru-Guardrails (< 10ms)"]
        SemCache["⚡ Semantic Cache (Qdrant)"]
        CircuitBrk["🛑 Circuit Breaker Router"]
        FactGuard["⚖️ NLI Fact Checker"]
        PIIUnmask["🔓 Zero-PII Restore"]
    end

    subgraph ONPREM_GPU[" 🚀 ИЗОЛИРОВАННЫЙ ON-PREM GPU КЛАСТЕР "]
        Tier1["👑 Tier-1: Qwen-2.5-72B (4x A100)"]
        Tier2["⚡ Tier-2: Qwen-2.5-32B (2x A100)"]
        Tier3["🚨 Tier-3: Qwen-2.5-14B/7B (AWQ)"]
    end

    Mobile & WebClient & OperatorUI --> WAF --> PIIMask --> InpTox --> SemCache
    SemCache -- "HIT" --> PIIUnmask
    SemCache -- "MISS" --> CircuitBrk
    CircuitBrk -- "Штатно" --> Tier1
    CircuitBrk -- "Перегрузка" --> Tier2
    CircuitBrk -- "Пик" --> Tier3
    Tier1 & Tier2 & Tier3 --> FactGuard --> PIIUnmask`,

    'sequence': `sequenceDiagram
    autonumber
    actor App as 📱 Мобильный банк
    participant GW as ⚡ AI Gateway
    participant Vault as 🔒 Zero-PII Vault
    participant Cache as ⚡ Semantic Cache
    participant LLM as 🧠 vLLM (Qwen-72B)
    participant NLI as ⚖️ NLI Fact Guard

    App->>GW: POST /v1/chat/completions (Запрос с ПДн)
    GW->>Vault: Обезличивание: Карта, Паспорт, ФИО
    Vault-->>GW: [CARD_1], [FIO_1] (TTL=300s в Redis)
    GW->>Cache: Поиск эмбеддинга (Cosine > 0.95)
    alt Cache Miss
        GW->>LLM: Запрос инференса vLLM (SSE Stream)
        LLM-->>GW: Сырой ответ модели
        GW->>NLI: NLI Fact-Check против регламента банка
        NLI-->>GW: ✅ Faithfulness Score: 0.98
    end
    GW->>Vault: Де-анонимизация (Подстановка реальных данных)
    Vault-->>GW: Персонализированный финальный ответ
    GW-->>App: 200 OK (Stream SSE Response)`,

    'circuit-breaker': `stateDiagram-v2
    state "🟢 CLOSED (Штатный режим)" as S_Closed {
        [*] --> HealthCheck
        HealthCheck --> S_Closed: Ошибки < 5%, P99 < 2500ms
    }
    state "🔴 OPEN (Защита от перегрузки)" as S_Open {
        [*] --> Failover
        Failover --> S_Open: Каскадный фоллбэк на Tier-2/3
    }
    state "🟡 HALF-OPEN (Пробное зондирование)" as S_Half {
        [*] --> Canary
        Canary --> S_Half: 5% пробного трафика на 72B
    }
    S_Closed --> S_Open: KV-кэш > 95% ИЛИ Latency > 5000ms
    S_Open --> S_Half: Cooldown 30 сек истек
    S_Half --> S_Closed: Успешность проб > 95%
    S_Half --> S_Open: Ошибки в пробном трафике`,

    'guardrails': `flowchart LR
    In["Промпт клиента"] --> J["RuJailbreak"] --> T["RuBERT-Toxicity"] --> P["Zero-PII"]
    P --> M["vLLM: Qwen-2.5"]
    M --> OT["Out-Toxicity"] --> NLI["NLI Fact-Checker"] --> Num["Числовой аудитор"] --> Out["Ответ клиенту"]`,

    'vault': `flowchart TB
    Raw["'Переведи 15 000 с карты 4276 3800 1234 5678 Иванову'"] --> Det["Детекторы: Luhn + Natasha NER"]
    Det --> Vault[("Redis Session Vault: [CARD_1] -> 4276...")]
    Det --> San["'Переведи 15 000 с карты [CARD_1] [FIO_1]'"]
    San --> LLM["Qwen-72B (В логах НЕТ ПДн)"]
    LLM --> Detok["Де-токенизатор"]
    Vault --> Detok --> Fin["Финальный ответ клиенту"]`,

    'qos': `flowchart LR
    VIP["🔴 Realtime VIP (Чат)"] --> Q0["Очередь P0 (70%)"]
    CRM["🟡 Internal (CRM)"] --> Q1["Очередь P1 (20%)"]
    Batch["🟢 Batch (Скоринг)"] --> Q2["Очередь P2 (10%)"]
    Q0 & Q1 & Q2 --> Sched["GPU Scheduler (Вытеснение батчей)"] --> GPU["PagedAttention GPU Slots"]`
  };

  // =========================================================================
  // 2. УПРАВЛЕНИЕ ТАБАМИ И РЕНДЕРИНГОМ СХЕМ
  // =========================================================================
  let currentSchema = 'topology';
  let currentView = 'svg'; // 'svg' | 'mermaid' | 'specs'
  let isSimulating = false;

  const schemaNavButtons = document.querySelectorAll('.schema-tab-btn');
  const schemaStage = document.getElementById('schemaStage');
  const activeSchemaTitle = document.getElementById('activeSchemaTitle');
  const activeSchemaTag = document.getElementById('activeSchemaTag');
  const activeSchemaDesc = document.getElementById('activeSchemaDesc');
  const viewButtons = document.querySelectorAll('.view-btn');
  const btnSimulateSignal = document.getElementById('btnSimulateSignal');

  // Drawer элементы
  const nodeDrawer = document.getElementById('nodeDrawer');
  const btnCloseDrawer = document.getElementById('btnCloseDrawer');
  const drawerIcon = document.getElementById('drawerIcon');
  const drawerTitle = document.getElementById('drawerTitle');
  const drawerSub = document.getElementById('drawerSub');
  const drawerSla = document.getElementById('drawerSla');
  const drawerTax = document.getElementById('drawerTax');
  const drawerHw = document.getElementById('drawerHw');
  const drawerSec = document.getElementById('drawerSec');
  const drawerDesc = document.getElementById('drawerDesc');

  function renderCurrentSchema() {
    const data = SCHEMATICS_DATA[currentSchema];
    if (!data) return;

    activeSchemaTitle.textContent = data.title;
    activeSchemaTag.textContent = data.tag;
    activeSchemaDesc.textContent = data.desc;

    if (currentView === 'svg') {
      renderSvgSchema(currentSchema);
    } else if (currentView === 'mermaid') {
      renderMermaidSchema(currentSchema);
    } else {
      renderSpecsSchema(currentSchema);
    }
  }

  // Переключение табов схем
  schemaNavButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      schemaNavButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentSchema = btn.getAttribute('data-schema');
      renderCurrentSchema();
    });
  });

  // Переключение режимов отображения (SVG / Mermaid / Specs)
  viewButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      viewButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentView = btn.getAttribute('data-view');
      renderCurrentSchema();
    });
  });

  // Закрытие Drawer инспектора
  if (btnCloseDrawer) {
    btnCloseDrawer.addEventListener('click', () => {
      nodeDrawer.classList.remove('open');
    });
  }

  // Открытие инспектора параметров узла
  window.inspectNode = function(nodeKey) {
    const spec = NODE_SPECS[nodeKey];
    if (!spec) return;

    drawerIcon.textContent = spec.icon;
    drawerTitle.textContent = spec.title;
    drawerSub.textContent = spec.sub;
    drawerSla.textContent = spec.sla;
    drawerTax.textContent = spec.tax;
    drawerHw.textContent = spec.hw;
    drawerSec.textContent = spec.sec;
    drawerDesc.textContent = spec.desc;

    nodeDrawer.classList.add('open');
  };

  // =========================================================================
  // 3. ГЕНЕРАЦИЯ ИНТЕРАКТИВНЫХ ВЕКТОРНЫХ SVG СХЕМ
  // =========================================================================
  function renderSvgSchema(schemaKey) {
    let svgHtml = '';

    if (schemaKey === 'topology') {
      svgHtml = `
        <svg class="schema-svg-canvas" viewBox="0 0 1200 580" id="currentSvg">
          <defs>
            <filter id="glowBlue"><feGaussianBlur stdDeviation="3" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
            <filter id="glowRed"><feGaussianBlur stdDeviation="3" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
            <filter id="glowGreen"><feGaussianBlur stdDeviation="3" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
          </defs>

          <!-- Связующие провода -->
          <path d="M 170 120 C 230 120, 230 220, 290 220" class="wire wire-blue"/>
          <path d="M 170 220 L 290 220" class="wire wire-blue"/>
          <path d="M 170 320 C 230 320, 230 220, 290 220" class="wire wire-blue"/>

          <path d="M 430 220 L 480 220" class="wire wire-green"/>
          <path d="M 620 220 L 670 220" class="wire wire-green"/>
          <path d="M 810 220 L 860 220" class="wire wire-blue"/>

          <!-- Fan-out к GPU -->
          <path d="M 980 220 C 1020 220, 1020 120, 1060 120" class="wire wire-green" id="wireTier1"/>
          <path d="M 980 220 L 1060 220" class="wire wire-blue" id="wireTier2"/>
          <path d="M 980 220 C 1020 220, 1020 320, 1060 320" class="wire wire-amber" id="wireTier3"/>

          <!-- Вертикальные хранилища -->
          <path d="M 550 260 L 550 440" class="wire wire-amber"/>
          <path d="M 740 260 L 740 440" class="wire wire-amber"/>
          <path d="M 920 260 L 920 440" class="wire wire-red"/>

          <!-- Слой бегущих импульсов -->
          <g id="pulseLayer"></g>

          <!-- УЗЛЫ: КЛИЕНТЫ (ДМЗ) -->
          <g class="node-group" onclick="inspectNode('mobile-app')">
            <rect x="30" y="85" width="140" height="70" class="node-box blue"/>
            <text x="50" y="115" class="node-text-title">📱 Мобильный банк</text>
            <text x="50" y="135" class="node-text-sub">Realtime P0 • iOS/Andr</text>
          </g>

          <g class="node-group" onclick="inspectNode('mobile-app')">
            <rect x="30" y="185" width="140" height="70" class="node-box blue"/>
            <text x="50" y="215" class="node-text-title">🎧 АРМ Оператора</text>
            <text x="50" y="235" class="node-text-sub">Суфлер контакт-центра</text>
          </g>

          <g class="node-group" onclick="inspectNode('mobile-app')">
            <rect x="30" y="285" width="140" height="70" class="node-box blue"/>
            <text x="50" y="315" class="node-text-title">🏢 CRM & Бэк-офис</text>
            <text x="50" y="335" class="node-text-sub">Внутренние АС банка</text>
          </g>

          <!-- УЗЛЫ: ШЛЮЗ (КОНВЕЙЕР) -->
          <g class="node-group" onclick="inspectNode('waf-ingress')">
            <rect x="290" y="180" width="140" height="80" class="node-box red"/>
            <text x="310" y="215" class="node-text-title">🛡️ WAF & Ingress</text>
            <text x="310" y="235" class="node-text-sub">mTLS • Rate Limit</text>
          </g>

          <g class="node-group" onclick="inspectNode('zero-pii-vault')">
            <rect x="480" y="180" width="140" height="80" class="node-box green"/>
            <text x="500" y="215" class="node-text-title">🔒 Zero-PII Vault</text>
            <text x="500" y="235" class="node-text-sub">Luhn • Natasha NER</text>
          </g>

          <g class="node-group" onclick="inspectNode('ru-guardrails-in')">
            <rect x="670" y="180" width="140" height="80" class="node-box amber"/>
            <text x="690" y="215" class="node-text-title">⚔️ Ru-Guardrails</text>
            <text x="690" y="235" class="node-text-sub">Toxicity & Jailbreak</text>
          </g>

          <g class="node-group" onclick="inspectNode('circuit-router')">
            <rect x="860" y="180" width="120" height="80" class="node-box blue"/>
            <text x="880" y="215" class="node-text-title">🔀 Router & CB</text>
            <text x="880" y="235" class="node-text-sub">Circuit Breaker</text>
          </g>

          <!-- УЗЛЫ: GPU КЛАСТЕР -->
          <g class="node-group" onclick="inspectNode('qwen-72b')">
            <rect x="1040" y="85" width="150" height="70" class="node-box green"/>
            <text x="1055" y="115" class="node-text-title">👑 Qwen-2.5-72B</text>
            <text x="1055" y="135" class="node-text-sub">Tier-1 • 4x A100 (vLLM)</text>
          </g>

          <g class="node-group" onclick="inspectNode('qwen-32b')">
            <rect x="1040" y="185" width="150" height="70" class="node-box blue"/>
            <text x="1055" y="215" class="node-text-title">⚡ Qwen-2.5-32B</text>
            <text x="1055" y="235" class="node-text-sub">Tier-2 • Резерв 2x A100</text>
          </g>

          <g class="node-group" onclick="inspectNode('qwen-7b')">
            <rect x="1040" y="285" width="150" height="70" class="node-box amber"/>
            <text x="1055" y="315" class="node-text-title">🚨 Qwen-14B/7B</text>
            <text x="1055" y="335" class="node-text-sub">Tier-3 • AWQ Fast-Inf</text>
          </g>

          <!-- УЗЛЫ: ХРАНИЛИЩА -->
          <g class="node-group" onclick="inspectNode('zero-pii-vault')">
            <rect x="470" y="440" width="160" height="65" class="node-box slate"/>
            <text x="490" y="468" class="node-text-title">🗄️ Redis Session Vault</text>
            <text x="490" y="488" class="node-text-sub">Эфемерный PII (TTL 300s)</text>
          </g>

          <g class="node-group" onclick="inspectNode('semantic-cache')">
            <rect x="660" y="440" width="160" height="65" class="node-box slate"/>
            <text x="680" y="468" class="node-text-title">🔍 Vector DB (Qdrant)</text>
            <text x="680" y="488" class="node-text-sub">Эмбеддинги кэша FAQ</text>
          </g>

          <g class="node-group" onclick="inspectNode('kafka-siem')">
            <rect x="850" y="440" width="160" height="65" class="node-box red"/>
            <text x="870" y="468" class="node-text-title">📨 Kafka SIEM WORM</text>
            <text x="870" y="488" class="node-text-sub">Аудит безопасности 24/7</text>
          </g>
        </svg>
      `;
    } else if (schemaKey === 'sequence') {
      svgHtml = `
        <svg class="schema-svg-canvas" viewBox="0 0 1100 560" id="currentSvg">
          <g id="pulseLayer"></g>
          <!-- Вертикальные дорожки акторов -->
          <line x1="120" y1="70" x2="120" y2="500" stroke="rgba(255,255,255,0.15)" stroke-dasharray="4 4"/>
          <line x1="320" y1="70" x2="320" y2="500" stroke="rgba(255,255,255,0.15)" stroke-dasharray="4 4"/>
          <line x1="520" y1="70" x2="520" y2="500" stroke="rgba(255,255,255,0.15)" stroke-dasharray="4 4"/>
          <line x1="720" y1="70" x2="720" y2="500" stroke="rgba(255,255,255,0.15)" stroke-dasharray="4 4"/>
          <line x1="920" y1="70" x2="920" y2="500" stroke="rgba(255,255,255,0.15)" stroke-dasharray="4 4"/>

          <!-- Заголовки акторов -->
          <rect x="50" y="20" width="140" height="40" class="node-box blue" onclick="inspectNode('mobile-app')"/>
          <text x="75" y="45" class="node-text-title">📱 Клиент</text>

          <rect x="250" y="20" width="140" height="40" class="node-box red" onclick="inspectNode('waf-ingress')"/>
          <text x="270" y="45" class="node-text-title">⚡ AI Gateway</text>

          <rect x="450" y="20" width="140" height="40" class="node-box green" onclick="inspectNode('zero-pii-vault')"/>
          <text x="470" y="45" class="node-text-title">🔒 Zero-PII Vault</text>

          <rect x="650" y="20" width="140" height="40" class="node-box amber" onclick="inspectNode('semantic-cache')"/>
          <text x="670" y="45" class="node-text-title">🔍 Semantic Cache</text>

          <rect x="850" y="20" width="140" height="40" class="node-box purple" onclick="inspectNode('qwen-72b')"/>
          <text x="865" y="45" class="node-text-title">🧠 vLLM (Qwen-72B)</text>

          <!-- Шаги взаимодействия -->
          <g class="node-group" onclick="inspectNode('waf-ingress')">
            <path d="M 120 120 L 320 120" stroke="#3b82f6" stroke-width="2" marker-end="url(#arrow)"/>
            <text x="140" y="110" class="node-text-sub">1. POST /v1/chat/completions (Промпт + ПДн)</text>
          </g>

          <g class="node-group" onclick="inspectNode('zero-pii-vault')">
            <path d="M 320 170 L 520 170" stroke="#10b981" stroke-width="2"/>
            <text x="340" y="160" class="node-text-sub">2. Обезличивание: замена на [CARD_1], [FIO_1]</text>
            <path d="M 520 200 L 320 200" stroke="#10b981" stroke-width="2" stroke-dasharray="4 4"/>
            <text x="340" y="220" class="node-text-sub">3. Очищенный промпт + Session ID (TTL=300s)</text>
          </g>

          <g class="node-group" onclick="inspectNode('semantic-cache')">
            <path d="M 320 260 L 720 260" stroke="#f59e0b" stroke-width="2"/>
            <text x="420" y="250" class="node-text-sub">4. Проверка кэша (Косинусная близость > 0.95)</text>
          </g>

          <g class="node-group" onclick="inspectNode('qwen-72b')">
            <path d="M 320 320 L 920 320" stroke="#8b5cf6" stroke-width="2"/>
            <text x="510" y="310" class="node-text-sub">5. vLLM Streaming Инференс (Continuous Batching)</text>
            <path d="M 920 370 L 320 370" stroke="#8b5cf6" stroke-width="2" stroke-dasharray="4 4"/>
            <text x="510" y="390" class="node-text-sub">6. Поток сгенерированных токенов</text>
          </g>

          <g class="node-group" onclick="inspectNode('nli-fact-guard')">
            <rect x="290" y="415" width="220" height="30" class="node-box amber"/>
            <text x="300" y="435" class="node-text-title">⚖️ 7. NLI Fact Check vs Регламент</text>
          </g>

          <g class="node-group" onclick="inspectNode('zero-pii-vault')">
            <path d="M 320 465 L 520 465" stroke="#10b981" stroke-width="2"/>
            <text x="340" y="460" class="node-text-sub">8. Де-маскирование данных</text>
          </g>

          <g class="node-group" onclick="inspectNode('mobile-app')">
            <path d="M 320 495 L 120 495" stroke="#3b82f6" stroke-width="2" stroke-dasharray="4 4"/>
            <text x="140" y="490" class="node-text-sub">9. 200 OK: Финальный ответ клиенту</text>
          </g>
        </svg>
      `;
    } else if (schemaKey === 'circuit-breaker') {
      svgHtml = `
        <svg class="schema-svg-canvas" viewBox="0 0 1100 540" id="currentSvg">
          <g id="pulseLayer"></g>
          <!-- Состояния Circuit Breaker -->
          <g class="node-group" onclick="inspectNode('circuit-router')">
            <rect x="80" y="100" width="260" height="150" class="node-box green"/>
            <circle cx="115" cy="135" r="10" fill="#10b981"/>
            <text x="140" y="140" class="node-text-title" font-size="16">🟢 CLOSED (Штатный)</text>
            <text x="105" y="175" class="node-text-sub">• 100% трафика на Qwen-72B</text>
            <text x="105" y="195" class="node-text-sub">• Ошибки 5xx < 5%</text>
            <text x="105" y="215" class="node-text-sub">• Latency P99 < 2500 мс</text>
          </g>

          <!-- Переход в OPEN -->
          <path d="M 340 175 L 480 175" class="wire wire-red" stroke-width="3"/>
          <text x="360" y="160" class="node-text-sub" fill="#f87171">KV-кэш > 95% ИЛИ Latency > 5s</text>

          <g class="node-group" onclick="inspectNode('circuit-router')">
            <rect x="480" y="100" width="260" height="150" class="node-box red"/>
            <circle cx="515" cy="135" r="10" fill="#ef4444"/>
            <text x="540" y="140" class="node-text-title" font-size="16">🔴 OPEN (Защита)</text>
            <text x="505" y="175" class="node-text-sub">• Каскадный фоллбэк на Tier-2/3</text>
            <text x="505" y="195" class="node-text-sub">• Сброс фоновых очередей (429)</text>
            <text x="505" y="215" class="node-text-sub">• Cooldown таймер: 30 сек</text>
          </g>

          <!-- Переход в HALF-OPEN -->
          <path d="M 610 250 C 610 320, 800 320, 800 250" class="wire wire-amber" stroke-width="2"/>
          <text x="640" y="315" class="node-text-sub" fill="#fbbf24">Таймер 30с истек</text>

          <g class="node-group" onclick="inspectNode('circuit-router')">
            <rect x="760" y="100" width="260" height="150" class="node-box amber"/>
            <circle cx="795" cy="135" r="10" fill="#f59e0b"/>
            <text x="820" y="140" class="node-text-title" font-size="16">🟡 HALF-OPEN (Canary)</text>
            <text x="785" y="175" class="node-text-sub">• 5% пробного трафика на 72B</text>
            <text x="785" y="195" class="node-text-sub">• Проверка успешности ответов</text>
            <text x="785" y="215" class="node-text-sub">• При успехе >95% -> CLOSED</text>
          </g>

          <!-- Дерево решений внизу -->
          <rect x="150" y="380" width="800" height="120" class="node-box slate"/>
          <text x="180" y="415" class="node-text-title">⚡ АЛГОРИТМ КАСКАДНОЙ ДЕГРАДАЦИИ (FALLBACK CASCADE)</text>
          <text x="180" y="445" class="node-text-sub">1. Tier-1: Qwen-2.5-72B (Штатно) ➔ При сбое / таймауте 2.5s переход на:</text>
          <text x="180" y="465" class="node-text-sub">2. Tier-2: Qwen-2.5-32B / 14B (Standby) ➔ При пиковой нагрузке переход на:</text>
          <text x="180" y="485" class="node-text-sub">3. Tier-3: Qwen-2.5-7B-AWQ (Low-latency) ➔ Аварийная заглушка / Semantic Cache</text>
        </svg>
      `;
    } else if (schemaKey === 'guardrails') {
      svgHtml = `
        <svg class="schema-svg-canvas" viewBox="0 0 1150 540" id="currentSvg">
          <g id="pulseLayer"></g>
          <!-- Этап 1: Вход -->
          <rect x="40" y="70" width="320" height="400" class="node-box blue"/>
          <text x="60" y="105" class="node-text-title">🛡️ 1. ВХОДНОЙ ФИЛЬТР (< 12 мс)</text>
          
          <g class="node-group" onclick="inspectNode('ru-guardrails-in')">
            <rect x="60" y="130" width="280" height="65" class="node-box amber"/>
            <text x="80" y="160" class="node-text-title">RuJailbreak Vector Match</text>
            <text x="80" y="180" class="node-text-sub">Блокировка попыток обхода промпта</text>
          </g>

          <g class="node-group" onclick="inspectNode('ru-guardrails-in')">
            <rect x="60" y="215" width="280" height="65" class="node-box amber"/>
            <text x="80" y="245" class="node-text-title">RuBERT-Tiny-Toxicity</text>
            <text x="80" y="265" class="node-text-sub">Мат, оскорбления, агрессия (< 8 мс)</text>
          </g>

          <g class="node-group" onclick="inspectNode('zero-pii-vault')">
            <rect x="60" y="300" width="280" height="65" class="node-box green"/>
            <text x="80" y="330" class="node-text-title">Zero-PII Vault Tokenizer</text>
            <text x="80" y="350" class="node-text-sub">Алгоритм Луна + Natasha Ru-NER</text>
          </g>

          <!-- Связь -->
          <path d="M 360 270 L 440 270" class="wire wire-green" stroke-width="3"/>

          <!-- Этап 2: Инференс -->
          <rect x="440" y="170" width="260" height="200" class="node-box purple" onclick="inspectNode('qwen-72b')"/>
          <text x="470" y="210" class="node-text-title">🧠 2. ИНФЕРЕНС vLLM</text>
          <text x="470" y="240" class="node-text-sub">• Qwen-2.5 On-Prem Cluster</text>
          <text x="470" y="265" class="node-text-sub">• PagedAttention Continuous Batch</text>
          <text x="470" y="290" class="node-text-sub">• Модель оперирует только токенами</text>
          <text x="470" y="315" class="node-text-sub">• В логах НЕТ реальных ПДн</text>

          <!-- Связь -->
          <path d="M 700 270 L 780 270" class="wire wire-blue" stroke-width="3"/>

          <!-- Этап 3: Выходной аудит -->
          <rect x="780" y="70" width="330" height="400" class="node-box green"/>
          <text x="800" y="105" class="node-text-title">⚖️ 3. ВЫХОДНОЙ АУДИТ И ФАКТЫ</text>

          <g class="node-group" onclick="inspectNode('ru-guardrails-in')">
            <rect x="800" y="130" width="290" height="65" class="node-box amber"/>
            <text x="820" y="160" class="node-text-title">Output Tone & Toxicity</text>
            <text x="820" y="180" class="node-text-sub">Проверка тональности ответа модели</text>
          </g>

          <g class="node-group" onclick="inspectNode('nli-fact-guard')">
            <rect x="800" y="215" width="290" height="65" class="node-box green"/>
            <text x="820" y="245" class="node-text-title">NLI Cross-Encoder (mDeBERTa)</text>
            <text x="820" y="265" class="node-text-sub">Анти-галлюцинация vs RAG Регламент</text>
          </g>

          <g class="node-group" onclick="inspectNode('nli-fact-guard')">
            <rect x="800" y="300" width="290" height="65" class="node-box blue"/>
            <text x="820" y="330" class="node-text-title">Числовой аудитор & Schema</text>
            <text x="820" y="350" class="node-text-sub">Сверка % ставок, сумм и дат кредита</text>
          </g>
        </svg>
      `;
    } else if (schemaKey === 'vault') {
      svgHtml = `
        <svg class="schema-svg-canvas" viewBox="0 0 1150 540" id="currentSvg">
          <g id="pulseLayer"></g>
          <!-- Шаг 1: Исходный запрос -->
          <rect x="40" y="40" width="1070" height="70" class="node-box red"/>
          <text x="60" y="70" class="node-text-title">1. ВХОДЯЩИЙ ЗАПРОС КЛИЕНТА (С ЧУВСТВИТЕЛЬНЫМИ ДАННЫМИ):</text>
          <text x="60" y="92" class="node-text-sub" fill="#fca5a5">"Клиент Иванов Иван Иванович, паспорт 4510 123456, переведи 25 000 руб с карты 4276 3800 1234 5678 на накопительный счет"</text>

          <!-- Шаг 2: Детекторы -->
          <g class="node-group" onclick="inspectNode('zero-pii-vault')">
            <rect x="60" y="150" width="280" height="80" class="node-box amber"/>
            <text x="80" y="185" class="node-text-title">💳 Алгоритм Луна (Luhn)</text>
            <text x="80" y="205" class="node-text-sub">Валидация контрольной суммы карты</text>
          </g>

          <g class="node-group" onclick="inspectNode('zero-pii-vault')">
            <rect x="435" y="150" width="280" height="80" class="node-box amber"/>
            <text x="455" y="185" class="node-text-title">👤 Natasha Ru-NER</text>
            <text x="455" y="205" class="node-text-sub">Извлечение ФИО в косвенных падежах</text>
          </g>

          <g class="node-group" onclick="inspectNode('zero-pii-vault')">
            <rect x="810" y="150" width="280" height="80" class="node-box amber"/>
            <text x="830" y="185" class="node-text-title">📄 Regex Паспорта РФ</text>
            <text x="830" y="205" class="node-text-sub">Серия и номер документа гражданина</text>
          </g>

          <!-- Шаг 3: Redis Vault -->
          <g class="node-group" onclick="inspectNode('zero-pii-vault')">
            <rect x="250" y="270" width="650" height="90" class="node-box slate"/>
            <text x="270" y="300" class="node-text-title">🔑 ЭФЕМЕРНЫЙ REDIS SESSION VAULT (TTL = 300 СЕКУНД)</text>
            <text x="270" y="325" class="node-text-sub" font-family="monospace">[CARD_1] ➔ '4276 3800 1234 5678' | [FIO_1] ➔ 'Иванов Иван Иванович' | [PASS_1] ➔ '4510 123456'</text>
            <text x="270" y="345" class="node-text-sub" fill="#34d399">✓ Данные хранятся только в RAM и уничтожаются сразу после ответа</text>
          </g>

          <!-- Шаг 4: Обезличенный инференс -->
          <g class="node-group" onclick="inspectNode('qwen-72b')">
            <rect x="40" y="400" width="1070" height="100" class="node-box green"/>
            <text x="60" y="430" class="node-text-title">4. БЕЗОПАСНЫЙ ИНФЕРЕНС В vLLM (QWEN-72B) И ДЕ-АНОНИМИЗАЦИЯ:</text>
            <text x="60" y="455" class="node-text-sub">• Модель видит только синтетику: "Клиент [FIO_1], паспорт [PASS_1], перевод с карты [CARD_1]"</text>
            <text x="60" y="480" class="node-text-sub" fill="#34d399">• Процессор обратной де-токенизации подставляет реальные значения перед отправкой в Мобильный банк</text>
          </g>
        </svg>
      `;
    } else if (schemaKey === 'qos') {
      svgHtml = `
        <svg class="schema-svg-canvas" viewBox="0 0 1150 540" id="currentSvg">
          <g id="pulseLayer"></g>
          <!-- Потоки -->
          <g class="node-group" onclick="inspectNode('mobile-app')">
            <rect x="40" y="80" width="280" height="85" class="node-box red"/>
            <text x="60" y="115" class="node-text-title">🔴 Realtime VIP (P0)</text>
            <text x="60" y="135" class="node-text-sub">Мобильный банк, Чат клиента (SLA < 1.5s)</text>
          </g>

          <g class="node-group" onclick="inspectNode('mobile-app')">
            <rect x="40" y="215" width="280" height="85" class="node-box amber"/>
            <text x="60" y="250" class="node-text-title">🟡 Standard (P1)</text>
            <text x="60" y="270" class="node-text-sub">CRM суфлер, внутренние АС (SLA < 5s)</text>
          </g>

          <g class="node-group" onclick="inspectNode('mobile-app')">
            <rect x="40" y="350" width="280" height="85" class="node-box blue"/>
            <text x="60" y="385" class="node-text-title">🟢 Batch / Offline (P2)</text>
            <text x="60" y="405" class="node-text-sub">Пакетный скоринг архива (SLA < 1 час)</text>
          </g>

          <!-- Очереди WFQ -->
          <path d="M 320 120 L 440 120" class="wire wire-red" stroke-width="3"/>
          <path d="M 320 255 L 440 255" class="wire wire-amber" stroke-width="3"/>
          <path d="M 320 390 L 440 390" class="wire wire-blue" stroke-width="3"/>

          <rect x="440" y="50" width="300" height="420" class="node-box slate"/>
          <text x="460" y="85" class="node-text-title">⚖️ WEIGHTED FAIR QUEUING (WFQ)</text>
          
          <rect x="460" y="110" width="260" height="70" class="node-box red"/>
          <text x="480" y="140" class="node-text-title">Очередь P0 (Вес: 70%)</text>
          <text x="480" y="160" class="node-text-sub">Выделенные гарантированные GPU слоты</text>

          <rect x="460" y="225" width="260" height="70" class="node-box amber"/>
          <text x="480" y="255" class="node-text-title">Очередь P1 (Вес: 20%)</text>
          <text x="480" y="275" class="node-text-sub">Динамический балансировочный пул</text>

          <rect x="460" y="340" width="260" height="70" class="node-box blue"/>
          <text x="480" y="370" class="node-text-title">Очередь P2 (Вес: 10%)</text>
          <text x="480" y="390" class="node-text-sub">Фоновый пул с мгновенным вытеснением</text>

          <!-- GPU Исполнитель -->
          <path d="M 740 255 L 840 255" class="wire wire-green" stroke-width="3"/>

          <rect x="840" y="150" width="270" height="210" class="node-box green" onclick="inspectNode('qwen-72b')"/>
          <text x="860" y="190" class="node-text-title">🚀 GPU SCHEDULER & SLOTS</text>
          <text x="860" y="220" class="node-text-sub">• vLLM PagedAttention Slots</text>
          <text x="860" y="245" class="node-text-sub">• Приоритетное вытеснение фоновых задач</text>
          <text x="860" y="270" class="node-text-sub">• Защита VIP-клиентов от очередей</text>
          <text x="860" y="295" class="node-text-sub" fill="#34d399">✓ Гарантия P99 < 1.5s в Мобильном банке</text>
        </svg>
      `;
    }

    schemaStage.innerHTML = svgHtml;
  }

  function renderMermaidSchema(schemaKey) {
    const src = MERMAID_SOURCES[schemaKey];
    schemaStage.innerHTML = `
      <div style="width: 100%; height: 100%; padding: 32px; overflow-y: auto; background: rgba(11, 17, 32, 0.95);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
          <span style="font-family: var(--font-mono); font-size: 13px; color: var(--cyber-blue);">Mermaid.js Source Code:</span>
          <button class="btn btn-secondary" onclick="navigator.clipboard.writeText(document.getElementById('mermaidCode').innerText); alert('Mermaid код скопирован в буфер обмена!');">📋 Скопировать код</button>
        </div>
        <pre class="code-box" id="mermaidCode" style="font-size: 13px; line-height: 1.6; white-space: pre-wrap;">${src}</pre>
      </div>
    `;
  }

  function renderSpecsSchema(schemaKey) {
    schemaStage.innerHTML = `
      <div style="width: 100%; height: 100%; padding: 32px; overflow-y: auto; background: rgba(11, 17, 32, 0.95);">
        <h4 style="font-family: var(--font-display); font-size: 18px; margin-bottom: 16px; color: #fff;">Технический регламент и параметры узлов схемы:</h4>
        <table class="matrix-table">
          <thead>
            <tr>
              <th>Узел архитектуры</th>
              <th>Роль и SLA</th>
              <th>Задержка (Tax)</th>
              <th>Оборудование</th>
              <th>Стандарты безопасности</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>WAF & Ingress Gateway</strong></td>
              <td>Периметр безопасности (P99 < 5ms)</td>
              <td>3.2 мс</td>
              <td>Envoy 3x Pods</td>
              <td>mTLS, Keycloak JWT, ГОСТ TLS 1.3</td>
            </tr>
            <tr>
              <td><strong>Zero-PII Vault Tokenizer</strong></td>
              <td>Обезличивание карт и паспортов</td>
              <td>4.8 мс</td>
              <td>CPU Nodes (Natasha NER)</td>
              <td>152-ФЗ, 395-1 «О банковской тайне», ЦБ РФ 683-П</td>
            </tr>
            <tr>
              <td><strong>Ru-Guardrails Input</strong></td>
              <td>Toxicity & Jailbreak фильтрация</td>
              <td>6.5 мс</td>
              <td>ONNX Runtime CPU</td>
              <td>RuBERT-Tiny, RuJailbreak веса</td>
            </tr>
            <tr>
              <td><strong>Semantic Cache</strong></td>
              <td>Срез типовых FAQ-запросов</td>
              <td>8.1 мс (12ms hit)</td>
              <td>Qdrant Cluster + Redis</td>
              <td>Cosine > 0.95, Изоляция по тенантам</td>
            </tr>
            <tr>
              <td><strong>vLLM Tier-1 (Qwen-72B)</strong></td>
              <td>Основной пул высокой точности</td>
              <td>800–1200 мс</td>
              <td>4-8x NVIDIA A100 / H100</td>
              <td>Air-Gapped On-Prem, PagedAttention</td>
            </tr>
            <tr>
              <td><strong>vLLM Tier-2 (Qwen-32B)</strong></td>
              <td>Резервный пул (Failover)</td>
              <td>300–600 мс</td>
              <td>2x NVIDIA A100</td>
              <td>Circuit Breaker Cascading</td>
            </tr>
            <tr>
              <td><strong>NLI Fact Guard</strong></td>
              <td>Проверка следования регламенту</td>
              <td>12.4 мс</td>
              <td>ONNX Cross-Encoder</td>
              <td>mDeBERTa-v3-base-xnli (Faithfulness > 0.85)</td>
            </tr>
          </tbody>
        </table>
      </div>
    `;
  }

  // =========================================================================
  // 4. СИМУЛЯЦИЯ БЕГУЩЕГО СВЕТОВОГО ИМПУЛЬСА (SIGNAL SIMULATION)
  // =========================================================================
  if (btnSimulateSignal) {
    btnSimulateSignal.addEventListener('click', () => {
      if (currentView !== 'svg') {
        currentView = 'svg';
        viewButtons.forEach(b => b.classList.toggle('active', b.getAttribute('data-view') === 'svg'));
        renderCurrentSchema();
      }

      const pulseLayer = document.getElementById('pulseLayer');
      if (!pulseLayer) return;

      btnSimulateSignal.disabled = true;
      btnSimulateSignal.innerHTML = '<span>⚡ Передача сигнала...</span>';

      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('class', 'signal-pulse green');
      circle.setAttribute('r', '8');
      pulseLayer.appendChild(circle);

      let start = null;
      const duration = 2000;

      function animate(time) {
        if (!start) start = time;
        const p = Math.min((time - start) / duration, 1);

        let cx, cy;
        if (p < 0.25) {
          const t = p / 0.25;
          cx = 100 + t * (360 - 100);
          cy = 120 + t * (220 - 120);
        } else if (p < 0.75) {
          const t = (p - 0.25) / 0.50;
          cx = 360 + t * (920 - 360);
          cy = 220;
        } else {
          const t = (p - 0.75) / 0.25;
          cx = 920 + t * (1110 - 920);
          cy = 220 + t * (120 - 220);
        }

        circle.setAttribute('cx', cx);
        circle.setAttribute('cy', cy);

        if (p < 1) {
          requestAnimationFrame(animate);
        } else {
          if (pulseLayer.contains(circle)) {
            pulseLayer.removeChild(circle);
          }
          btnSimulateSignal.innerHTML = '<span>✅ Сигнал доставлен</span>';
          setTimeout(() => {
            btnSimulateSignal.disabled = false;
            btnSimulateSignal.innerHTML = '<span>▶️ Смоделировать сигнал</span>';
          }, 1200);
        }
      }

      requestAnimationFrame(animate);
    });
  }

  // =========================================================================
  // 5. ИНТЕРАКТИВНЫЙ КАЛЬКУЛЯТОР САЙЗИНГА И ЭКОНОМИКИ GPU
  // =========================================================================
  const sliderRps = document.getElementById('sliderRps');
  const sliderContext = document.getElementById('sliderContext');
  const sliderCache = document.getElementById('sliderCache');

  const valRpsBadge = document.getElementById('valRpsBadge');
  const valContextBadge = document.getElementById('valContextBadge');
  const valCacheBadge = document.getElementById('valCacheBadge');

  const kpiGpuCount = document.getElementById('kpiGpuCount');
  const kpiVram = document.getElementById('kpiVram');
  const kpiTokensSec = document.getElementById('kpiTokensSec');
  const kpiSavingsRub = document.getElementById('kpiSavingsRub');
  const kpiTtft = document.getElementById('kpiTtft');

  function calculateGpuSizing() {
    const rps = parseInt(sliderRps.value, 10);
    const contextTokens = parseInt(sliderContext.value, 10);
    const cacheHitPct = parseInt(sliderCache.value, 10);

    valRpsBadge.textContent = `${rps.toLocaleString()} RPS`;
    valContextBadge.textContent = `${contextTokens.toLocaleString()} токенов`;
    valCacheBadge.textContent = `${cacheHitPct}% Cache Hit`;

    // Формула токенов в секунду, поступающих на GPU
    const effectiveRps = rps * (1 - cacheHitPct / 100);
    const tokensPerSec = Math.round(effectiveRps * (contextTokens * 0.15)); // средняя генерация ~15% от контекста

    // Оценка необходимого числа NVIDIA A100 80GB (vLLM выдает ~450 токенов/сек на карту при Continuous Batching)
    const rawGpusNeeded = Math.ceil(tokensPerSec / 450);
    const gpusWithRedundancy = Math.max(4, Math.ceil(rawGpusNeeded * 1.3)); // N+1 отказоустойчивость

    const vramGb = gpusWithRedundancy * 80;

    // Экономия бюджета банка за счет семантического кэша и каскадирования моделей
    // Базовая стоимость часа инференса 1x A100 в On-Prem TCO ~ 420 руб/час
    const savedGpus = Math.max(2, Math.round((rps * 0.15 * contextTokens) / 450 * (cacheHitPct / 100)));
    const yearlySavingsMln = ((savedGpus * 420 * 24 * 365) / 1_000_000).toFixed(1);

    // Расчетный TTFT (Time to First Token)
    let estimatedTtft = 180;
    if (cacheHitPct > 30) estimatedTtft -= 40;
    if (contextTokens > 4000) estimatedTtft += 65;

    // Вывод в UI
    kpiGpuCount.textContent = `${gpusWithRedundancy} x A100`;
    kpiVram.textContent = `${vramGb.toLocaleString()} GB`;
    kpiTokensSec.textContent = `${tokensPerSec.toLocaleString()} tok/s`;
    kpiSavingsRub.textContent = `~ ${yearlySavingsMln} млн ₽`;
    kpiTtft.textContent = `${estimatedTtft} мс`;
  }

  if (sliderRps && sliderContext && sliderCache) {
    sliderRps.addEventListener('input', calculateGpuSizing);
    sliderContext.addEventListener('input', calculateGpuSizing);
    sliderCache.addEventListener('input', calculateGpuSizing);
    calculateGpuSizing();
  }

  // =========================================================================
  // 6. ФИЛЬТРАЦИЯ СРАВНИТЕЛЬНОЙ МАТРИЦЫ
  // =========================================================================
  const matrixFilterButtons = document.querySelectorAll('.matrix-filter-btn');
  const matrixRows = document.querySelectorAll('.matrix-table tbody tr');

  matrixFilterButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      matrixFilterButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const cat = btn.getAttribute('data-cat');

      matrixRows.forEach(row => {
        if (cat === 'all' || row.getAttribute('data-category') === cat) {
          row.style.display = '';
        } else {
          row.style.display = 'none';
        }
      });
    });
  });

  // Первичный рендер схемы по умолчанию
  renderCurrentSchema();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initPortal);
} else {
  initPortal();
}

