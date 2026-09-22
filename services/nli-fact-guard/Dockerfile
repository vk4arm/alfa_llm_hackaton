FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

ENV PYTHONUNBUFFERED=1
EXPOSE 8005

CMD ["python", "-c", "from src.fact_checker import NliFactGuard; print('NLI Fact Guard ready')"]
