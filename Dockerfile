# syntax=docker/dockerfile:1.7
# PCAP Network Visualizer v2: one image for laptop mode and team-server mode.
#   docker build -t pcapvis .
#   docker run -p 8080:8080 -v ./engagements:/data pcapvis

# ── 1. Build the React frontend ────────────────────────────────────────────────
FROM node:22-slim AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ── 2. Runtime: Python + tshark ────────────────────────────────────────────────
FROM python:3.12-slim AS runtime
COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /usr/local/bin/uv

# tshark without the setuid capture helper (we read files; live capture is a later feature).
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
 && rm -rf /var/lib/apt/lists/* \
 && tshark --version | head -1

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv PATH="/app/.venv/bin:$PATH"
WORKDIR /app
COPY VERSION /app/VERSION
COPY backend/pyproject.toml backend/uv.lock backend/README.md /app/backend/
RUN cd /app/backend && uv sync --frozen --no-dev --extra postgres --no-install-project
COPY backend/pcapvis /app/backend/pcapvis
RUN cd /app/backend && uv sync --frozen --no-dev --extra postgres
COPY --from=frontend /src/frontend/dist /app/frontend

RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin pcapvis \
 && mkdir -p /data && chown pcapvis /data
USER pcapvis

ENV PCAPVIS_HOST=0.0.0.0 PCAPVIS_PORT=8080 PCAPVIS_DATA_DIR=/data PCAPVIS_FRONTEND_DIST=/app/frontend PYTHONUNBUFFERED=1
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=4).status == 200 else 1)"

LABEL org.opencontainers.image.title="PCAP Network Visualizer" \
      org.opencontainers.image.source="https://github.com/esandeepchoudary/pcap-vis-anz" \
      org.opencontainers.image.licenses="MIT"
ENTRYPOINT ["pcapvis"]
CMD ["serve"]
