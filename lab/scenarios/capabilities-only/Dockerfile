# syntax=docker/dockerfile:1.6
#
# NEXUS-R Lab - Capabilities-only scenario
#
# Only file capabilities are dangerous. Other categories are absent.
# Isolates NEXUS-CAP-001.
#
# DO NOT deploy this image anywhere.

FROM ghcr.io/astral-sh/uv:python3.12-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash vulnuser \
    && echo "vulnuser:vulnuser" | chpasswd

# 1. cap_setuid on a copy of python3 -> critical
RUN cp /usr/bin/python3 /usr/local/bin/py-setuid \
    && setcap cap_setuid+ep /usr/local/bin/py-setuid

# 2. cap_sys_admin on a small helper -> critical
RUN cp /usr/bin/id /usr/local/bin/id-sysadmin \
    && setcap cap_sys_admin+ep /usr/local/bin/id-sysadmin

# 3. cap_dac_read_search -> high, read any file
RUN cp /usr/bin/cat /usr/local/bin/cat-readall \
    && setcap cap_dac_read_search+ep /usr/local/bin/cat-readall

# Build NEXUS-R
WORKDIR /opt/nexus-r
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev

ENV PATH="/opt/nexus-r/.venv/bin:${PATH}"

USER vulnuser
WORKDIR /home/vulnuser

CMD ["sleep", "infinity"]
