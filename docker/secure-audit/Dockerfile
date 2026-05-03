FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -u 1000 -m appuser && mkdir -p /app/data && chown appuser /app/data
USER appuser

EXPOSE 5000

# 1 worker + 8 threads : les jobs d'audit tournent en threads partagés
CMD ["gunicorn", "app:app", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "1", \
     "--threads", "8", \
     "--timeout", "300"]
