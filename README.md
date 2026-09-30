# NEXUS-R

> Evidence-Driven Linux Security Research and Privilege-Escalation Analysis Engine

NEXUS-R adalah engine riset keamanan Linux yang berfokus pada pendekatan **evidence-first**: mengumpulkan fakta dari sistem, menormalisasi data menjadi evidence terstruktur, kemudian menganalisisnya menggunakan rule engine untuk menghasilkan security findings yang dilengkapi dengan severity, confidence, evidence, dan validation steps.

Lihat [`docs/adr/ADR-001-project-architecture.md`](docs/adr/ADR-001-project-architecture.md) untuk informasi mengenai arsitektur, scope, dan keputusan desain project.

## Status

- **V0.1** — Linux Enumeration Core ✅
- **V0.2** — Rules & Findings 🚧 In Progress
- **V0.3** — Evidence Correlation & Attack Path
- **V0.4** — Knowledge Engine
- **V0.5** — AI Research Engine
- **V0.6** — Container Security
- **V1.0** — Evidence-Driven Linux Security Research Engine

## Requirements

- Linux
- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/) — Python package manager

## Installation

Clone repository:

    git clone <repo-url> nexus-r
    cd nexus-r

Install dependencies:

    uv sync

Verify the Python environment:

    uv run python --version

## Development

Run the application:

    uv run nexus-r

If the CLI entry point is not available yet:

    uv run python -m nexus_r

Run tests:

    uv run pytest

## Architecture

NEXUS-R menggunakan arsitektur modular dengan alur:

    Target System
          |
          v
    Enumeration / Collectors
          |
          v
    Evidence Collection
          |
          v
    Evidence Normalization
          |
          v
    Rule Engine
          |
          v
    Security Findings
          |
          v
    Evidence Correlation
          |
          v
    Attack Path Analysis
          |
          v
    Knowledge / AI Research Engine

Setiap hasil analisis harus dapat ditelusuri kembali ke evidence yang menjadi dasar finding.

## Core Principles

### Evidence First

Setiap analisis harus berasal dari evidence yang dikumpulkan dari sistem.

### Traceable Findings

Setiap finding harus memiliki hubungan yang jelas dengan evidence dan rule yang menghasilkan finding tersebut.

### Deterministic Analysis

Rule-based analysis harus menghasilkan output yang konsisten terhadap evidence yang sama.

### Validation Before Conclusion

Finding harus menyediakan validation steps sehingga hasil analisis dapat diverifikasi.

### Modular Architecture

Setiap komponen dirancang secara modular agar dapat dikembangkan dan diuji secara independen.

### Research Oriented

NEXUS-R ditujukan untuk security research, authorized security assessment, penetration testing, dan defensive security analysis.

## Roadmap

### V0.1 — Linux Enumeration Core

Mengumpulkan informasi dasar dari Linux environment, termasuk:

- System information
- Kernel information
- User and group information
- Process information
- Network configuration
- Running services
- File permissions
- SUID/SGID files
- Scheduled tasks
- Environment information

**Status:** Completed

### V0.2 — Rules & Findings

Mengubah collected evidence menjadi security findings menggunakan rule engine.

Setiap finding dirancang memiliki:

    Finding
    |-- ID
    |-- Title
    |-- Severity
    |-- Confidence
    |-- Description
    |-- Evidence
    |-- Rule
    |-- Validation Steps
    `-- References

**Status:** In Progress

### V0.3 — Evidence Correlation & Attack Path

Menghubungkan beberapa evidence dan findings untuk mengidentifikasi hubungan antar-temuan dan kemungkinan attack paths.

**Status:** Planned

### V0.4 — Knowledge Engine

Menambahkan knowledge base untuk enrichment dan contextual analysis.

**Status:** Planned

### V0.5 — AI Research Engine

Menambahkan AI-assisted security research dengan tetap mempertahankan evidence traceability.

**Status:** Planned

### V0.6 — Container Security

Memperluas kemampuan analysis terhadap Linux container environments.

**Status:** Planned

### V1.0 — Evidence-Driven Linux Security Research Engine

Target akhir NEXUS-R adalah menyediakan workflow:

    Enumeration
         |
         v
    Evidence Collection
         |
         v
    Normalization
         |
         v
    Rule Analysis
         |
         v
    Findings
         |
         v
    Correlation
         |
         v
    Attack Path
         |
         v
    Knowledge Enrichment
         |
         v
    Research & Validation

## Security Scope

NEXUS-R dikembangkan untuk penggunaan pada environment yang memiliki otorisasi, seperti:

- Security research
- Lab environment
- CTF
- Authorized penetration testing
- Internal security assessment
- Defensive security research

NEXUS-R tidak ditujukan untuk melakukan pengujian terhadap sistem tanpa izin.

## Project Structure

    nexus-r/
    |-- docs/
    |   `-- adr/
    |       `-- ADR-001-project-architecture.md
    |-- src/
    |   `-- nexus_r/
    |-- tests/
    |-- pyproject.toml
    |-- uv.lock
    `-- README.md

Struktur project dapat berkembang mengikuti implementasi setiap versi.

## Documentation

Dokumentasi arsitektur dan keputusan desain tersedia pada:

    docs/adr/

## License

License information will be defined before the first public release.

## Project Status

NEXUS-R is currently under active development.

The project prioritizes:

- Correctness
- Evidence traceability
- Deterministic analysis
- Modular architecture
- Reproducibility
- Security research quality

## AI Hypothesis Layer (V0.5.5)

NEXUS-R mendukung lapisan AI hipotesis yang bersifat **opsional**.
Lapisan AI **tidak pernah** membuat finding baru - ia hanya memberi
hipotesis dan langkah validasi atas finding yang sudah ada. Setiap
hipotesis berstatus `needs_review`. Lihat
[ADR-004](docs/adr/ADR-004-ai-hypothesis-layer.md).

Tiga mode backend:

    # Template offline (default, deterministik, tanpa network)
    uv run nexus-r scan

    # Ollama lokal (butuh ollama serve + model)
    uv run nexus-r scan --ai --ai-backend ollama --ai-model llama3.2

    # OpenAI-compatible API (butuh OPENAI_API_KEY)
    uv run nexus-r scan --ai --ai-backend openai --ai-model gpt-4o-mini

Semua hipotesis selalu mereferensi finding yang ada, dan selalu
membutuhkan validasi manusia (ADR-001 paragraf 3.7).
