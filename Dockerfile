# Embedded CLI copy stage (used only by the core service target below).
FROM docker:27-cli AS docker_cli_embed

# Shared app image: Python + system tools. No Docker CLI here — workers do not need it.
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MIBS=ALL

WORKDIR /app

# Runtime tools (ping/mtr/snmp/rsync/ssh). Docker packages omitted — saves size on 7 worker images.
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    traceroute \
    mtr-tiny \
    snmp \
    postgresql-client \
    rsync \
    openssh-client \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/share/snmp/mibs/ietf \
    && curl -fsSL https://codeload.github.com/net-snmp/net-snmp/tar.gz/v5.9.4 -o /tmp/ns.tar.gz \
    && tar -xzf /tmp/ns.tar.gz -C /tmp \
    && cp /tmp/net-snmp-5.9.4/mibs/*.txt /usr/share/snmp/mibs/ietf/ \
    && rm -rf /tmp/ns.tar.gz /tmp/net-snmp-5.9.4 \
    && sed -i 's/^mibs :/#mibs :/' /etc/snmp/snmp.conf \
    && test -f /usr/share/snmp/mibs/ietf/SNMPv2-MIB.txt

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

RUN mkdir -p /app/data /app/logs

EXPOSE 9000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9000"]

# Core: Docker CLI + Compose v2 plugin. Official docker/cli image has no plugin — clone preflight needs `docker compose`.
FROM runtime AS runtime_core
ARG DOCKER_COMPOSE_VERSION=2.32.4
COPY --from=docker_cli_embed /usr/local/bin/docker /usr/local/bin/docker
RUN set -eux \
 && chmod +x /usr/local/bin/docker \
 && /usr/local/bin/docker --version \
 && mkdir -p /usr/local/lib/docker/cli-plugins \
 && arch="$(uname -m)" \
 && case "$arch" in \
      x86_64) dc_arch=x86_64 ;; \
      aarch64|arm64) dc_arch=aarch64 ;; \
      armv7l|armhf) dc_arch=armv7 ;; \
      ppc64le) dc_arch=ppc64le ;; \
      s390x) dc_arch=s390x ;; \
      *) echo "Unsupported architecture for Compose plugin download: $arch (install compose manually)" >&2; exit 1 ;; \
    esac \
 && apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && curl -fsSL "https://github.com/docker/compose/releases/download/v${DOCKER_COMPOSE_VERSION}/docker-compose-linux-${dc_arch}" \
      -o /usr/local/lib/docker/cli-plugins/docker-compose \
 && chmod +x /usr/local/lib/docker/cli-plugins/docker-compose \
 && apt-get purge -y curl \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* \
 && docker compose version

# Default image target for `docker build` and most Compose services (slim, no docker binary).
FROM runtime
