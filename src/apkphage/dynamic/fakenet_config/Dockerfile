# Fakenet - fake internet sink for the APKPhage Android sandbox.
#
# Answers DNS + HTTP/HTTPS/proxy traffic with canned responses so the
# emulator "sees" a live internet without anything reaching the real one.
# The emulator is pointed here via -dns-server / -http-proxy.
#
# Build:  docker build -t apkphage-fakenet ./dynamic/fakenet_config
# Run:    docker run -d --rm --name apkphage-fakenet --network analysis_net apkphage-fakenet
FROM python:3.11-slim

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt

COPY fake_dns.py .
COPY fake_internet.py .
COPY start.sh /start.sh
RUN chmod +x /start.sh

# DNS (UDP+TCP), HTTP, HTTPS, HTTP proxy
EXPOSE 53/udp 53/tcp 80/tcp 443/tcp 8080/tcp
ENTRYPOINT ["/start.sh"]