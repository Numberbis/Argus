FROM ghcr.io/zaproxy/zaproxy:stable

USER root
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY zap-scan.py /zap/zap-scan.py
RUN chmod +x /zap/zap-scan.py

USER zap
ENTRYPOINT ["python3", "/zap/zap-scan.py"]
