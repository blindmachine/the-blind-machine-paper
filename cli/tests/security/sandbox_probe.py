"""Hostile application used only by the live container-isolation regression."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import resource
from pathlib import Path


def blocked(name, operation):
    try:
        operation()
    except Exception as exc:
        return {"probe": name, "blocked": True, "error": type(exc).__name__}
    return {"probe": name, "blocked": False}


def network_connect():
    with socket.create_connection(("1.1.1.1", 53), timeout=1):
        pass


def dns_resolve():
    socket.getaddrinfo("pypi.org", 443)


def tmp_exec():
    executable = Path("/tmp/blind-probe")
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    subprocess.run([str(executable)], check=True)


def fork_bomb():
    children = []
    try:
        for _ in range(300):
            pid = os.fork()
            if pid == 0:
                import time

                time.sleep(10)
                os._exit(0)
            children.append(pid)
    finally:
        for pid in children:
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass
        for pid in children:
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass


def raw_socket():
    socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)


def kernel_tuning_write():
    Path("/proc/sys/kernel/core_pattern").write_text("escape")


def security_state():
    status = Path("/proc/self/status").read_text()
    effective_caps = next(
        line.split(":", 1)[1].strip() for line in status.splitlines() if line.startswith("CapEff:")
    )
    nofile = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    file_size = resource.getrlimit(resource.RLIMIT_FSIZE)[0]
    return {
        "probe": "security_state",
        "blocked": os.getuid() != 0 and int(effective_caps, 16) == 0 and nofile <= 1024
        and file_size <= 1024 * 1024 * 1024,
    }


report = [
    blocked("network_connect", network_connect),
    blocked("dns_resolve", dns_resolve),
    blocked("bundle_write", lambda: Path("/bundle/escaped").write_text("escape")),
    blocked("root_write", lambda: Path("/escaped").write_text("escape")),
    blocked("tmp_exec", tmp_exec),
    blocked("fork_bomb", fork_bomb),
    blocked("raw_socket", raw_socket),
    blocked("kernel_tuning_write", kernel_tuning_write),
    blocked("undeclared_output", lambda: Path("/out/junk").write_text("junk")),
    security_state(),
    {
        "probe": "host_environment",
        "blocked": "BLIND_PROBE_HOST_SECRET" not in os.environ,
    },
]
Path("/out/report.json").write_text(json.dumps(report, sort_keys=True))
