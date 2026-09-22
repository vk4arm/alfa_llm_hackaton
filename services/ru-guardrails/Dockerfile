FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

ENV PYTHONUNBUFFERED=1
EXPOSE 8002

CMD ["python", "-c", "from src.guardrails import RuGuardrails; print('Ru-Guardrails ready')"]
