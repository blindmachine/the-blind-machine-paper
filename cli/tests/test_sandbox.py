"""Structural regression tests for the local application container boundary."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from blind.errors import VerificationError
from blind.runtime.sandbox import (
    PINNED_RUNNER_IMAGE,
    ContainerSandbox,
    limits_for,
    unsafe_direct_enabled,
)
from blind.runtime import sandbox as sandbox_module


def _mount_source(argv: list[str], target: str) -> Path:
    specs = [argv[index + 1] for index, value in enumerate(argv[:-1]) if value == "--mount"]
    spec = next(
        value for value in specs if f"target={target}" in value.split(",")
    )
    source = next(part for part in spec.split(",") if part.startswith("source="))
    return Path(source.removeprefix("source="))


def test_direct_runner_requires_loud_opt_in(monkeypatch):
    monkeypatch.setenv("BLIND_STAGE_RUNNER", "direct")
    monkeypatch.delenv("BLIND_UNSAFE_ALLOW_DIRECT_STAGE_RUNNER", raising=False)
    with pytest.raises(VerificationError):
        unsafe_direct_enabled()


def test_runner_image_environment_override_is_rejected(monkeypatch):
    monkeypatch.setenv("BLIND_RUNNER_IMAGE", PINNED_RUNNER_IMAGE)
    with pytest.raises(VerificationError):
        ContainerSandbox(runtime="docker")


def test_manifest_limits_are_positive_and_clamped():
    limits = limits_for(
        {"resources": {"max_memory_mb": 999999, "max_wall_seconds": 999999}}, 999999
    )
    assert limits.memory_mb == 8192
    assert limits.wall_seconds == 3600


def test_data_stage_has_only_staged_io_and_hardened_flags(tmp_path, monkeypatch):
    bundle = tmp_path / "bundle"
    (bundle / "env" / ".venv").mkdir(parents=True)
    (bundle / "20_encrypt.py").write_text("# fixture\n")
    raw = tmp_path / "private-input"
    raw.write_text("PRIVATE")
    destination = tmp_path / "user-output" / "ciphertext.bin"

    sandbox = ContainerSandbox(runtime="docker", image=PINNED_RUNNER_IMAGE)
    monkeypatch.setattr(sandbox, "ensure_ready", lambda **_kwargs: None)
    captured: list[str] = []

    def execute(argv, *, name, timeout):
        captured.extend(argv)
        (_mount_source(argv, "/out") / "0").write_bytes(b"ciphertext")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(sandbox, "_execute", execute)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-enter-container")
    sandbox.run_stage(
        bundle_root=bundle,
        shim_dir=None,
        stage_name="20_encrypt.py",
        args=["--encoded", str(raw), "--out", str(destination)],
        input_paths=[raw],
        output_paths=[destination],
        output_dir_argument=None,
        limits=limits_for({}, 30),
    )

    command = " ".join(captured)
    assert destination.read_bytes() == b"ciphertext"
    assert "--network none" in command
    assert "--ipc none" in command
    assert "--read-only" in captured
    assert "--cap-drop ALL" in command
    assert "--security-opt no-new-privileges" in command
    assert "fsize=" in command
    assert "noexec,nosuid,nodev" in command
    assert "--pull never" in command
    assert "target=/out,readonly" in command
    assert "target=/out/0" in command
    assert "target=/out/0,readonly" not in command
    assert str(raw) not in command
    assert str(destination.parent) not in command
    assert os.environ["AWS_SECRET_ACCESS_KEY"] not in command
    assert "PYTHONNOUSERSITE=1" in command
    assert "--offline --no-sync" in command


def test_build_phase_mounts_no_user_data(tmp_path, monkeypatch):
    bundle = tmp_path / "bundle"
    (bundle / "env").mkdir(parents=True)
    cache = tmp_path / "cache"
    cache.mkdir(mode=0o700)
    sandbox = ContainerSandbox(runtime="docker", image=PINNED_RUNNER_IMAGE)
    monkeypatch.setattr(sandbox, "ensure_ready", lambda **_kwargs: None)
    captured: list[str] = []

    def execute(argv, *, name, timeout):
        captured.extend(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(sandbox, "_execute", execute)
    sandbox.build_environment(bundle, cache, timeout=30)
    command = " ".join(captured)
    assert "--network bridge" in command
    assert "target=/bundle,readonly" in command
    assert "target=/bundle/env/.venv" in command
    assert "target=/uv-cache" in command
    assert "--cap-drop ALL" in command
    assert "--security-opt no-new-privileges" in command
    assert "uv --project /bundle/env sync --frozen --no-dev" in command


def test_private_input_uses_anonymous_stdin_not_a_host_mount(tmp_path, monkeypatch):
    bundle = tmp_path / "bundle"
    (bundle / "env" / ".venv").mkdir(parents=True)
    (bundle / "40_decrypt.py").write_text("# fixture\n")
    encrypted = tmp_path / "result.ct"
    encrypted.write_bytes(b"ciphertext")
    destination = tmp_path / "plain.json"
    private_context = b"private-context-must-never-be-mounted"
    marker = "__private_context__"

    sandbox = ContainerSandbox(runtime="docker", image=PINNED_RUNNER_IMAGE)
    monkeypatch.setattr(sandbox, "ensure_ready", lambda **_kwargs: None)
    captured: dict[str, object] = {}

    def execute(argv, *, name, timeout, stdin_payload):
        captured["argv"] = argv
        captured["stdin"] = stdin_payload
        (_mount_source(argv, "/out") / "0").write_bytes(b"plain")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(sandbox, "_execute", execute)
    sandbox.run_stage(
        bundle_root=bundle,
        shim_dir=None,
        stage_name="40_decrypt.py",
        args=["--context", marker, "--result", str(encrypted), "--out", str(destination)],
        input_paths=[encrypted],
        output_paths=[destination],
        output_dir_argument=None,
        limits=limits_for({}, 30),
        private_input=(marker, private_context),
    )

    argv = captured["argv"]
    command = " ".join(argv)
    assert captured["stdin"] == private_context
    assert destination.read_bytes() == b"plain"
    assert "--interactive" in argv
    assert "/dev/stdin" in argv
    assert marker not in command
    assert private_context.decode() not in command
    assert all("private-context" not in str(value) for value in argv)


@pytest.mark.live_sandbox
def test_live_container_denies_every_escape(tmp_path, monkeypatch):
    if os.environ.get("BLIND_RUN_LIVE_SANDBOX_TESTS") != "1":
        pytest.skip("set BLIND_RUN_LIVE_SANDBOX_TESTS=1 to exercise the daemon/kernel boundary")

    probe_dir = Path(__file__).parent / "security"
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    report_file = out_dir / "report.json"
    report_file.touch(mode=0o600)
    sandbox = ContainerSandbox(image=PINNED_RUNNER_IMAGE)
    sandbox.ensure_ready(pull=True)
    monkeypatch.setenv("BLIND_PROBE_HOST_SECRET", "never-forward-this")
    name = sandbox_module._container_name("live-probe")
    limits = sandbox_module.SandboxLimits(memory_mb=512, wall_seconds=60, pids=256)
    argv = [
        *sandbox._base_argv(name=name, network="none", limits=limits),
        *sandbox_module._mount(probe_dir, "/bundle", readonly=True),
        *sandbox_module._mount(out_dir, "/out", readonly=True),
        *sandbox_module._mount(report_file, "/out/report.json", readonly=False),
        "-e", "HOME=/tmp", "-e", "PYTHONNOUSERSITE=1",
        "-w", "/bundle",
        sandbox.image,
        "python", "/bundle/sandbox_probe.py",
    ]
    proc = sandbox._execute(argv, name=name, timeout=90)
    assert proc.returncode == 0, "live sandbox probe did not complete"
    report = json.loads((out_dir / "report.json").read_text())
    assert {entry["probe"] for entry in report} == {
        "network_connect", "dns_resolve", "bundle_write", "root_write",
        "tmp_exec", "fork_bomb", "raw_socket", "kernel_tuning_write",
        "undeclared_output", "security_state", "host_environment",
    }
    assert all(entry["blocked"] for entry in report), report


@pytest.mark.live_sandbox
def test_live_container_receives_private_input_over_stdin(tmp_path):
    if os.environ.get("BLIND_RUN_LIVE_SANDBOX_TESTS") != "1":
        pytest.skip("set BLIND_RUN_LIVE_SANDBOX_TESTS=1 to exercise the daemon/kernel boundary")

    secret = os.urandom(4096)
    digest_file = tmp_path / "stdin.sha256"
    digest_file.touch(mode=0o600)
    sandbox = ContainerSandbox(image=PINNED_RUNNER_IMAGE)
    sandbox.ensure_ready(pull=True)
    name = sandbox_module._container_name("live-stdin")
    limits = sandbox_module.SandboxLimits(memory_mb=256, wall_seconds=30, pids=64)
    argv = [
        *sandbox._base_argv(name=name, network="none", limits=limits),
        "--interactive",
        *sandbox_module._mount(digest_file, "/out/stdin.sha256", readonly=False),
        sandbox.image,
        "python",
        "-c",
        (
            "import hashlib, pathlib, sys; "
            "pathlib.Path('/out/stdin.sha256').write_text("
            "hashlib.sha256(sys.stdin.buffer.read()).hexdigest())"
        ),
    ]
    proc = sandbox._execute(argv, name=name, timeout=60, stdin_payload=secret)
    assert proc.returncode == 0
    assert digest_file.read_text() == hashlib.sha256(secret).hexdigest()
