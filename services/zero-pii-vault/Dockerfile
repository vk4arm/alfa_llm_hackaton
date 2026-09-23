FROM python:3.11-slim

# Create a non-root user and group
RUN groupadd -r piiuser && useradd -r -g piiuser piiuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY config/ ./config/
COPY src/ ./src/

# Create logs directory and assign ownership to piiuser
RUN mkdir -p /var/logs && chown -R piiuser:piiuser /var/logs && chmod -R 755 /var/logs

# Switch to non-root user
USER piiuser

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src
ENV PORT=8000
EXPOSE 8000

CMD ["granian", "--interface", "asgi", "src.server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--backlog", "8192"]
