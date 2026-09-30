"""Curated subset of GTFOBins binaries.

Not exhaustive. Focused on binaries commonly abused for privilege
escalation when SUID or sudo-allowed.

Reference: https://gtfobins.github.io
"""

from __future__ import annotations

GTFOBINS: frozenset[str] = frozenset({
    # Shells / interpreters
    "bash", "sh", "dash", "zsh", "ksh", "csh", "fish", "env",
    # Editors / pagers
    "vim", "vi", "nano", "less", "more", "man", "pico", "ed",
    # Scripting
    "awk", "gawk", "nawk", "sed", "perl",
    "python", "python2", "python3", "ruby", "node", "php", "lua", "tclsh", "wish",
    # Search / filesystem
    "find", "fd", "locate", "updatedb",
    # Archive
    "tar", "zip", "unzip", "7z", "cpio", "rsync",
    # File ops
    "cp", "mv", "dd", "install", "tee", "chmod", "chown",
    # Network
    "nmap", "nc", "netcat", "socat", "curl", "wget",
    # VCS
    "git", "svn", "hg",
    # System
    "mount", "umount", "chroot", "nsenter", "unshare",
    "systemctl", "journalctl", "service",
    # Containers
    "docker", "podman",
    # Package managers
    "apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "pacman",
    # Crypto / encoding
    "openssl", "gpg", "base64", "xxd", "od",
    # Debuggers
    "gdb", "strace", "ltrace",
    # Build
    "make", "cmake", "gcc", "cc", "clang",
    # Session
    "expect", "screen", "tmux",
    # Remote
    "ssh", "scp", "sftp",
    # Auth
    "su", "sudo", "pkexec", "passwd", "chsh", "chfn", "newgrp",
    # Utilities
    "xargs", "timeout", "nice", "ionice", "stdbuf", "taskset",
    "ld.so", "ldconfig", "start-stop-daemon",
    # DBus
    "busctl", "dbus-send",
    # Misc
    "coredumpctl", "wall", "write", "logger", "checkpolicy",
    "ssh-keysign", "ssh-agent",
    "sqlite3", "mysql", "psql", "mongosh",
    "jq", "yq", "ftp", "tftp",
})
