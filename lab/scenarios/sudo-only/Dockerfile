# syntax=docker/dockerfile:1.6
#
# NEXUS-R Lab - Sudo-only scenario
#
# Only sudo misconfigurations are present. All other categories are
# cleaned up or absent. This isolates NEXUS-SUDO-001 and NEXUS-SUDO-002.
#
# DO NOT deploy this image anywhere.

FROM ghcr.io/astral-sh/uv:python3.12-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        sudo \
    && rm -rf /var/lib/apt/lists/*

# Create the vulnerable user with sudo group membership
RUN useradd -m -s /bin/bash vulnuser \
    && echo "vulnuser:vulnuser" | chpasswd \
    && usermod -aG sudo vulnuser

# 1. NOPASSWD entry with a dangerous binary (vi)
#    -> NEXUS-SUDO-001 (NOPASSWD), NEXUS-SUDO-002 (dangerous binary)
RUN printf 'vulnuser ALL=(ALL) NOPASSWD: /usr/bin/vi\n' > /etc/sudoers.d/10-vi \
    && chmod 0644 /etc/sudoers.d/10-vi

# 2. NOPASSWD entry with a wildcard
#    -> NEXUS-SUDO-002 (wildcard)
RUN printf 'vulnuser ALL=(ALL) NOPASSWD: /usr/bin/find /tmp/*\n' > /etc/sudoers.d/20-find \
    && chmod 0644 /etc/sudoers.d/20-find

# Build NEXUS-R inside the final image so venv paths are correct
WORKDIR /opt/nexus-r
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev

ENV PATH="/opt/nexus-r/.venv/bin:${PATH}"

USER vulnuser
WORKDIR /home/vulnuser

CMD ["sleep", "infinity"]
