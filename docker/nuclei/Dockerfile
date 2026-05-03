FROM projectdiscovery/nuclei:latest

USER root
RUN apk add --no-cache curl python3

RUN adduser -u 1000 -D scanner
COPY nuclei-scan.sh /usr/local/bin/nuclei-scan.sh
RUN chmod +x /usr/local/bin/nuclei-scan.sh

USER scanner
# Mise à jour des templates au build
RUN nuclei -update-templates -silent || true

ENTRYPOINT ["/usr/local/bin/nuclei-scan.sh"]
