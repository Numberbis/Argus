FROM wpscanteam/wpscan:latest

USER root
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends curl python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

COPY wpscan-scan.sh /usr/local/bin/wpscan-scan.sh
RUN chmod +x /usr/local/bin/wpscan-scan.sh

ENTRYPOINT ["/usr/local/bin/wpscan-scan.sh"]
