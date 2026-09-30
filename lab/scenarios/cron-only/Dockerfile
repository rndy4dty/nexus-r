# syntax=docker/dockerfile:1.6
#
# NEXUS-R Lab - Cron-only scenario
#
# Only cron and PATH-related vulnerabilities. Other categories are
# cleaned up. This isolates NEXUS-CRON-001 and NEXUS-PATH-001.
#
# DO NOT deploy this image anywhere.

FROM ghcr.io/astral-sh/uv:python3.12-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        cron \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash vulnuser \
    && echo "vulnuser:vulnuser" | chpasswd

# 1. World-writable cron script in /etc/cron.daily (run by run-parts as root)
#    -> NEXUS-CRON-001
RUN printf '#!/bin/bash\necho nightly\n' > /etc/cron.daily/backup.sh \
    && chmod 0777 /etc/cron.daily/backup.sh

# 2. Group-writable directory placed first in PATH
#    -> NEXUS-PATH-001 (owned by root, writable by sharedbin)
RUN groupadd -r sharedbin \
    && usermod -aG sharedbin vulnuser \
    && mkdir -p /opt/shared-bin \
    && chown root:sharedbin /opt/shared-bin \
    && chmod 0775 /opt/shared-bin

# 3. Cron entry that calls a bare command (candidate for PATH hijack)
#    -> NEXUS-CRON-002 (hypothesis, low confidence)
RUN printf '17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n' > /etc/cron.d/hijack \
    && chmod 0644 /etc/cron.d/hijack

# Build NEXUS-R
WORKDIR /opt/nexus-r
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev

ENV PATH="/opt/shared-bin:/opt/nexus-r/.venv/bin:${PATH}"

USER vulnuser
WORKDIR /home/vulnuser

CMD ["sleep", "infinity"]
