# DevOps & Deployment (`devops/`)

Инфраструктурный слой для запуска и развертывания компонентов **Alfa AI Gateway**.

## 🚀 Быстрый запуск в Docker Compose

1. Скопируйте файл переменных окружения:
   ```bash
   cp .env.example .env
   ```
2. Соберите и запустите микросервисы шлюза и базы данных:
   ```bash
   docker-compose up -d --build
   ```
3. Проверьте доступность эндпоинтов:
   - Gateway Health: `http://localhost:8000/healthz`
   - Qdrant UI: `http://localhost:6333/dashboard`
   - Redis: `localhost:6379`

## 📦 Архитектура сети (`alfa-mesh`)

Все сервисы изолированы во внутренней Docker-сети `alfa-mesh`. Внешний доступ имеет только `gateway-core` через WAF/Ingress банка.
