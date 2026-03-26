## Stage 1: Build React UI
FROM node:20-slim AS ui-builder
WORKDIR /ui
COPY ui/package.json ui/package-lock.json* ./
RUN npm install
COPY ui/ ./
RUN npm run build

## Stage 2: Runtime
FROM ubuntu:24.04

LABEL org.opencontainers.image.title="UniFi Log Insight"
LABEL org.opencontainers.image.description="Real-time log analysis for UniFi routers — syslog, GeoIP, threat intelligence, and a live dashboard in a single container"
LABEL org.opencontainers.image.source="https://github.com/jmasarweh/unifi-log-insight"
LABEL org.opencontainers.image.url="https://github.com/jmasarweh/unifi-log-insight"
LABEL org.opencontainers.image.licenses="BSL-1.1"
LABEL org.opencontainers.image.vendor="jmasarweh"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PGDATA=/var/lib/postgresql/data

# Install PostgreSQL 16 + Python 3 + supervisor + cron
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    postgresql-16 \
    postgresql-client-16 \
    python3 \
    python3-pip \
    python3-venv \
    supervisor \
    cron \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Install geoipupdate from MaxMind
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && ARCH=$(dpkg --print-architecture) \
    && curl -sSL "https://github.com/maxmind/geoipupdate/releases/download/v7.1.1/geoipupdate_7.1.1_linux_${ARCH}.deb" -o /tmp/geoipupdate.deb \
    && dpkg -i /tmp/geoipupdate.deb \
    && rm /tmp/geoipupdate.deb \
    && apt-get remove -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Create Python venv to avoid system package conflicts
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install Python dependencies then remove pip (not needed at runtime)
COPY receiver/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt \
    && pip uninstall -y pip setuptools \
    && rm -rf /app/venv/lib/python*/ensurepip \
    && apt-get remove -y python3-pip \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Copy version file and application code
COPY VERSION /app/VERSION
COPY receiver/ /app/
COPY init.sql /app/init.sql
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY entrypoint.sh /app/entrypoint.sh
COPY geoip-update.sh /app/geoip-update.sh
RUN chmod +x /app/entrypoint.sh /app/geoip-update.sh

# Copy built UI
COPY --from=ui-builder /ui/dist /app/static

WORKDIR /app

EXPOSE 514/udp
EXPOSE 8000

CMD ["/app/entrypoint.sh"]
