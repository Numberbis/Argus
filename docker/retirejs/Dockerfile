FROM node:20-alpine

WORKDIR /app

# retire.js + curl pour télécharger les scripts JS
RUN apk add --no-cache curl python3 && \
    npm install -g retire@5 && \
    adduser -u 1000 -D scanner

COPY retirejs-scan.sh .
RUN chmod +x retirejs-scan.sh

USER scanner

ENTRYPOINT ["sh", "retirejs-scan.sh"]
