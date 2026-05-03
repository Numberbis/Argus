FROM instrumentisto/nmap:latest

RUN apk add --no-cache python3 curl

COPY nmap-scan.sh /usr/local/bin/nmap-scan.sh
RUN chmod +x /usr/local/bin/nmap-scan.sh

ENTRYPOINT ["/usr/local/bin/nmap-scan.sh"]
