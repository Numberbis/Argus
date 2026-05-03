FROM alpine:3.20

RUN apk add --no-cache bash curl openssl bind-tools drill coreutils

RUN curl -sL https://github.com/drwetter/testssl.sh/archive/refs/heads/3.2.tar.gz \
    | tar -xz -C /opt && mv /opt/testssl.sh-3.2 /opt/testssl

COPY testssl-scan.sh /usr/local/bin/testssl-scan.sh
RUN chmod +x /usr/local/bin/testssl-scan.sh

RUN adduser -u 1000 -D scanner
USER scanner

ENTRYPOINT ["/usr/local/bin/testssl-scan.sh"]
