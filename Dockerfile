FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

COPY . .
RUN pip install --no-cache-dir --prefix=/install ".[all]"

FROM python:3.12-slim

LABEL maintainer="AegisDroid Contributors"
LABEL description="Advanced Android Security, Threat Hunting & Digital Forensics Framework"
LABEL org.opencontainers.image.source="https://github.com/0xhroot/aegisdroid"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    adb \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

RUN groupadd -r aegisdroid && useradd -r -g aegisdroid -d /app -s /bin/bash aegisdroid

WORKDIR /app
RUN mkdir -p /app/reports /app/rules/packs && \
    chown -R aegisdroid:aegisdroid /app

USER aegisdroid

ENTRYPOINT ["aegis"]
CMD ["--help"]
