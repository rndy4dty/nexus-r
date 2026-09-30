# NEXUS-R Lab

Lab ini berisi container Linux yang sengaja dibuat rentan untuk memverifikasi bahwa NEXUS-R dapat mendeteksi vektor privilege escalation yang nyata.

> WARNING: Image dan konfigurasi lab ini sengaja mengandung vulnerability. Jangan pernah men-deploy image ini pada sistem production atau sistem yang tidak terisolasi.

## Vulnerabilities

| # | Vektor | Rule NEXUS-R |
|---|---|---|
| 1 | Sudo NOPASSWD dengan /usr/bin/vi | NEXUS-SUDO-001, NEXUS-SUDO-002 |
| 2 | SUID binary bernama find di /opt/backup/find | NEXUS-SUID-001 |
| 3 | Cron script world-writable di /etc/cron.daily/backup.sh | NEXUS-CRON-001 |
| 4 | File capability cap_setuid pada /usr/local/bin/py-helper | NEXUS-CAP-001 |
| 5 | SSH private key readable di /home/vulnuser/.ssh/id_ed25519 | NEXUS-SSH-001 |
| 6 | Group-writable directory di PATH: /opt/shared-bin | NEXUS-PATH-001 |

## Cara Menjalankan

### Build

Dari root project:

    cd lab
    docker compose build

### Start

    docker compose up -d

### Verifikasi Container

    docker compose ps

### Masuk ke Container

    docker compose exec vulnerable-lab bash

Jika nama service berbeda:

    docker compose config --services

## Verifikasi Vulnerability

### Sudo

    sudo -l

### SUID

    find /opt/backup -type f -perm -4000 -ls

### Cron

    ls -l /etc/cron.daily/backup.sh

### File Capability

    getcap /usr/local/bin/py-helper

### SSH Private Key

    ls -l /home/vulnuser/.ssh/id_ed25519

### PATH Directory

    echo "$PATH"
    ls -ld /opt/shared-bin

## Expected Findings

NEXUS-R diharapkan mendeteksi:

- NEXUS-SUDO-001
- NEXUS-SUDO-002
- NEXUS-SUID-001
- NEXUS-CRON-001
- NEXUS-CAP-001
- NEXUS-SSH-001
- NEXUS-PATH-001

## Cleanup

    docker compose down

Untuk menghapus image lokal:

    docker compose down --rmi local

## Security Notice

Lab ini dibuat khusus untuk pengujian keamanan terisolasi.

Jangan menjalankan image ini pada production, mengekspos container ke jaringan publik, menggunakan credential atau private key asli, atau memasukkan data sensitif ke dalam lab.

## Skenario

Lab ini berisi beberapa skenario terisolasi, masing-masing fokus pada
subset rule tertentu. Setiap skenario memiliki `expected.json` yang
mendefinisikan rule yang diharapkan terdeteksi.

| Skenario | Service | Fokus | Rules yang diharapkan |
|---|---|---|---|
| `core` | `nexus-lab-core` | Mixed vulnerabilities | SUDO-001, SUDO-002, SUID-001, CRON-001, CAP-001, PATH-001, SSH-001 |
| `sudo-only` | `nexus-lab-sudo` | Hanya sudo misconfiguration | SUDO-001, SUDO-002 |
| `cron-only` | `nexus-lab-cron` | Hanya cron + PATH | CRON-001, PATH-001 |
| `capabilities-only` | `nexus-lab-caps` | Hanya file capabilities | CAP-001 |
| `container-escape` | `nexus-lab-container` | Docker group + socket | GROUP-001, DOCKER-001, CORR-DOCKER-001 |

### Verifikasi semua skenario

Jalankan dari root project:

    cd lab
    ./verify-all.sh
