# NEXUS-R

> Evidence-Driven Linux Security Research and Privilege-Escalation Analysis Engine

NEXUS-R adalah engine riset keamanan Linux yang berfokus pada **evidence-first**:
mengumpulkan fakta dari sistem, menormalisasi menjadi evidence terstruktur,
kemudian menganalisisnya untuk memahami kondisi keamanan dan jalur eskalasi privilese.

Lihat [`docs/adr/ADR-001-project-architecture.md`](docs/adr/ADR-001-project-architecture.md)
untuk arsitektur dan scope lengkap.

## Status

- **V0.1** — Linux Enumeration Core _(in progress)_

## Requirements

- Linux (target environment)
- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/) — package manager

## Instalasi

```bash
git clone <repo-url> nexus-r
cd nexus-r
uv sync


