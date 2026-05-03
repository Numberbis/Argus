FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir requests==2.32.3

COPY observatory-scan.py .

RUN useradd -u 1000 -m scanner
USER scanner

ENTRYPOINT ["python", "observatory-scan.py"]
