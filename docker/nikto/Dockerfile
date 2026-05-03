FROM perl:5.38-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl libnet-ssleay-perl libwhisker2-perl \
    && git clone --depth 1 https://github.com/sullo/nikto.git /nikto \
    && rm -rf /var/lib/apt/lists/*

COPY nikto-scan.sh /usr/local/bin/nikto-scan.sh
RUN chmod +x /usr/local/bin/nikto-scan.sh

RUN useradd -u 1000 -m scanner
USER scanner

ENTRYPOINT ["/usr/local/bin/nikto-scan.sh"]
