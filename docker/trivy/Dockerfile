FROM aquasec/trivy:latest

USER root
RUN apk add --no-cache curl python3 bash

COPY trivy-scan.sh /usr/local/bin/trivy-scan.sh
RUN chmod +x /usr/local/bin/trivy-scan.sh

ENTRYPOINT ["/usr/local/bin/trivy-scan.sh"]
