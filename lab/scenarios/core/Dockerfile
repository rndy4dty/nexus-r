# syntax=docker/dockerfile:1.6
#
# NEXUS-R Lab - Core Vulnerable Linux Scenario
#
# This image is INTENTIONALLY INSECURE. For local lab use only.
# NEXUS-R is built inside the same image so venv paths are valid.

FROM ghcr.io/astral-sh/uv:python3.12-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        sudo \
        libcap2-bin \
        openssh-client \
        openssl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash vulnuser \
    && echo "vulnuser:vulnuser" | chpasswd \
    && usermod -aG sudo vulnuser

RUN printf "vulnuser ALL=(ALL) NOPASSWD: /usr/bin/vi\n" > /etc/sudoers.d/vulnuser \
    && chmod 0644 /etc/sudoers.d/vulnuser

RUN mkdir -p /opt/backup \
    && cp /usr/bin/find /opt/backup/find \
    && chmod u+s /opt/backup/find

RUN printf "#!/bin/bash\necho nightly backup\n" > /etc/cron.daily/backup.sh \
    && chmod 0777 /etc/cron.daily/backup.sh

RUN cp /usr/bin/python3 /usr/local/bin/py-helper \
    && setcap cap_setuid+ep /usr/local/bin/py-helper

RUN mkdir -p /home/vulnuser/.ssh \
    && ssh-keygen -t ed25519 -N "" -f /home/vulnuser/.ssh/id_ed25519 > /dev/null 2>&1 \
    && chown -R vulnuser:vulnuser /home/vulnuser/.ssh \
    && chmod 600 /home/vulnuser/.ssh/id_ed25519

RUN groupadd -r sharedbin \
    && usermod -aG sharedbin vulnuser \
    && mkdir -p /opt/shared-bin \
    && chown root:sharedbin /opt/shared-bin \
    && chmod 0775 /opt/shared-bin

# Build NEXUS-R inside the final image so venv paths are correct
WORKDIR /opt/nexus-r
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev

ENV PATH="/opt/shared-bin:/home/vulnuser/.local/bin:/opt/nexus-r/.venv/bin:${PATH}"

USER vulnuser
WORKDIR /home/vulnuser

CMD ["sleep", "infinity"]
