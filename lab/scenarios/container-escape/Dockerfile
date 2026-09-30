# syntax=docker/dockerfile:1.6
#
# NEXUS-R Lab - Container-escape scenario
#
# Simulates a host where the user is in the docker group and the docker
# socket is present. The socket here is a regular file (not a real
# Docker daemon) so NEXUS-R detects it without needing Docker-in-Docker.
#
# DO NOT deploy this image anywhere.

FROM ghcr.io/astral-sh/uv:python3.12-bookworm

ENV DEBIAN_FRONTEND=noninteractive

# Create the vulnerable user
RUN useradd -m -s /bin/bash vulnuser \
    && echo "vulnuser:vulnuser" | chpasswd

# 1. docker group with vulnuser as a member
RUN groupadd -r docker \
    && usermod -aG docker vulnuser

# 2. Fake docker socket (regular file, world-readable enough to be detected)
RUN mkdir -p /run \
    && touch /run/docker.sock \
    && chown root:docker /run/docker.sock \
    && chmod 0660 /run/docker.sock \
    && ln -sf /run/docker.sock /var/run/docker.sock

# Build NEXUS-R
WORKDIR /opt/nexus-r
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev

ENV PATH="/opt/nexus-r/.venv/bin:${PATH}"

USER vulnuser
WORKDIR /home/vulnuser

CMD ["sleep", "infinity"]
