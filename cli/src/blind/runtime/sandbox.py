"""Fail-closed container sandbox for every application-controlled process.

The build phase has network access but no user data. The run phase has user data
but no network. Both phases use a digest-pinned image, a read-only root filesystem,
a non-root UID, dropped capabilities, no-new-privileges, and bounded resources.
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess  # nosec B404
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from blind.errors import UsageError, VerificationError
from blind.store import Store

PINNED_RUNNER_IMAGE = (
    "ghcr.io/astral-sh/uv@"
    "sha256:a353f5507610049c620893cfe3c91b6ce613abbd8292cddfcee2e05440956117"
)
_IMAGE_PATTERN = re.compile(r"^[a-zA-Z0-9._/:@-]+@sha256:[0-9a-f]{64}$")
_PLATFORM_PATTERN = re.compile(r"^linux/(?:amd64|arm64)$")
_UNSAFE_DIRECT_MODE = "direct"
_UNSAFE_DIRECT_OPT_IN = "BLIND_UNSAFE_ALLOW_DIRECT_STAGE_RUNNER"
_CONTAINER_TMP = PurePosixPath("/").joinpath("tmp").as_posix()
_PRIVATE_STDIN = PurePosixPath("/").joinpath("dev", "stdin").as_posix()
_MAX_PRIVATE_INPUT_BYTES = 64 * 1024 * 1024
# These paths exist only inside the bounded, noexec container tmpfs.
_SAFE_ENV = {
    "HOME": _CONTAINER_TMP,
    "PYTHONHASHSEED": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
    "LC_ALL": "C.UTF-8",
    "LANG": "C.UTF-8",
    "OMP_NUM_THREADS": "1",
    "OPENBLAS_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
    "NUMEXPR_NUM_THREADS": "1",
    "UV_CACHE_DIR": f"{_CONTAINER_TMP}/uv",
}


@dataclass(frozen=True)
class SandboxLimits:
    memory_mb: int
    wall_seconds: int
    cpus: str = "1"
    pids: int = 256
    nofile: int = 1024
    file_size_bytes: int = 1024 * 1024 * 1024


def unsafe_direct_enabled() -> bool:
    """True only for the explicit test/development escape hatch."""
    mode = os.environ.get("BLIND_STAGE_RUNNER", "sandbox").strip().lower()
    opted_in = os.environ.get(_UNSAFE_DIRECT_OPT_IN, "").strip() == "1"
    if mode == _UNSAFE_DIRECT_MODE and not opted_in:
        raise VerificationError(
            "Direct application execution is disabled. Use the container sandbox; "
            f"tests may explicitly set {_UNSAFE_DIRECT_OPT_IN}=1."
        )
    if mode not in {"", "auto", "sandbox", _UNSAFE_DIRECT_MODE}:
        raise UsageError("BLIND_STAGE_RUNNER must be 'sandbox' or the explicit unsafe 'direct' mode")
    return mode == _UNSAFE_DIRECT_MODE and opted_in


def scrubbed_direct_env(bundle_root: Path) -> dict[str, str]:
    """Minimal environment for the explicit unsandboxed test-only runner."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(bundle_root),
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": str(bundle_root),
        "LC_ALL": "C",
        "LANG": "C",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "NUMEXPR_NUM_THREADS": "1",
    }
    return env


def limits_for(manifest: dict, requested_timeout: int) -> SandboxLimits:
    resources = manifest.get("resources") or {}
    try:
        declared_memory = int(resources.get("max_memory_mb", 2048))
        declared_wall = int(resources.get("max_wall_seconds", requested_timeout))
    except (TypeError, ValueError) as exc:
        raise VerificationError("Application manifest has invalid resource limits") from exc
    if declared_memory <= 0 or declared_wall <= 0 or requested_timeout <= 0:
        raise VerificationError("Application resource limits must be positive")
    return SandboxLimits(
        memory_mb=min(declared_memory, 8192),
        wall_seconds=min(declared_wall, requested_timeout, 3600),
    )


class ContainerSandbox:
    """Digest-pinned Docker/Podman runner with separate build and run boundaries."""

    def __init__(
        self, runtime: str | None = None, image: str | None = None, platform: str | None = None
    ):
        self.runtime = self._resolve_runtime(runtime)
        if os.environ.get("BLIND_RUNNER_IMAGE"):
            raise VerificationError(
                "BLIND_RUNNER_IMAGE overrides are disabled; the runner is pinned by this CLI release"
            )
        self.image = image or PINNED_RUNNER_IMAGE
        if self.image != PINNED_RUNNER_IMAGE:
            raise VerificationError("Custom sandbox images are disabled in production")
        if not _IMAGE_PATTERN.fullmatch(self.image):
            raise VerificationError(
                "BLIND_RUNNER_IMAGE must be an OCI image pinned by a 64-hex @sha256 digest"
            )
        self.platform = platform or os.environ.get("BLIND_RUNNER_PLATFORM") or "linux/amd64"
        if not _PLATFORM_PATTERN.fullmatch(self.platform):
            raise VerificationError("BLIND_RUNNER_PLATFORM must be linux/amd64 or linux/arm64")

    @staticmethod
    def _resolve_runtime(runtime: str | None) -> str:
        requested = runtime or os.environ.get("BLIND_CONTAINER_RUNTIME")
        if requested:
            if requested not in {"docker", "podman"}:
                raise UsageError("BLIND_CONTAINER_RUNTIME must select docker or podman")
            path = shutil.which(requested)
            if not path:
                raise UsageError(f"Container runtime not found: {requested}")
            return path
        for name in ("podman", "docker"):
            path = shutil.which(name)
            if path:
                return path
        raise UsageError(
            "A container sandbox is required. Install rootless Podman or Docker before running applications."
        )

    @property
    def runtime_name(self) -> str:
        return Path(self.runtime).name

    def ensure_ready(self, *, pull: bool) -> None:
        probe = subprocess.run(  # nosec B603
            [self.runtime, "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=20,
        )
        if probe.returncode != 0:
            raise UsageError(f"{self.runtime_name} daemon is unavailable")
        inspect = subprocess.run(  # nosec B603
            [self.runtime, "image", "inspect", self.image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        if inspect.returncode == 0:
            return
        if not pull:
            raise VerificationError(
                "Pinned sandbox image is not present locally. Reinstall the application while online."
            )
        fetched = subprocess.run(  # nosec B603
            [self.runtime, "pull", "--platform", self.platform, self.image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=900,
        )
        if fetched.returncode != 0:
            raise UsageError(f"Could not pull the pinned sandbox image: {self.image}")

    def build_environment(self, bundle_root: Path, cache_dir: Path, *, timeout: int) -> None:
        """Materialize env/.venv with network access and no user-data mounts."""
        self.ensure_ready(pull=True)
        bundle_root = _safe_mount_source(bundle_root)
        env_dir = _safe_mount_source(bundle_root / "env")
        venv_dir = env_dir / ".venv"
        if venv_dir.is_symlink():
            raise VerificationError("Refusing a symlinked application virtual environment")
        if venv_dir.exists() and (not venv_dir.is_dir() or any(venv_dir.iterdir())):
            raise VerificationError("Application virtual environment must be created from empty state")
        venv_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        cache_dir = _safe_mount_source(cache_dir)
        if not cache_dir.is_dir():
            raise VerificationError("Application build cache must be a private directory")

        name = _container_name("build")
        argv = [
            *self._base_argv(name=name, network="bridge", limits=SandboxLimits(2048, timeout, "2", 512)),
            *_mount(bundle_root, "/bundle", readonly=True),
            *_mount(venv_dir, "/bundle/env/.venv", readonly=False),
            *_mount(cache_dir, "/uv-cache", readonly=False),
            "-e", "HOME=/tmp", "-e", "PYTHONNOUSERSITE=1",
            "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "UV_CACHE_DIR=/uv-cache",
            "-w", "/bundle",
            self.image,
            "uv", "--project", "/bundle/env", "sync", "--frozen", "--no-dev",
        ]
        proc = self._execute(argv, name=name, timeout=timeout + 60)
        if proc.returncode != 0:
            raise VerificationError(
                f"Sandboxed environment build failed with exit status {proc.returncode}"
            )

    def run_stage(
        self,
        *,
        bundle_root: Path,
        shim_dir: Path | None,
        stage_name: str,
        args: list[str],
        input_paths: list[Path],
        output_paths: list[Path],
        output_dir_argument: Path | None,
        limits: SandboxLimits,
        private_input: tuple[str, bytes] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run one stage with staged files and at most one pipe-only private input."""
        self.ensure_ready(pull=False)
        bundle_root = _safe_mount_source(bundle_root)
        if Path(stage_name).name != stage_name:
            raise VerificationError("Application stage name must be one file component")
        env_dir = bundle_root / "env"
        if not (env_dir / ".venv").is_dir():
            raise VerificationError("Application environment is not sealed; reinstall the application")

        tmp_root = _private_tmp_root()
        with tempfile.TemporaryDirectory(prefix="blind-sandbox-", dir=tmp_root) as tmp:
            root = Path(tmp)
            in_dir = root / "in"
            out_dir = root / "out"
            in_dir.mkdir(mode=0o700)
            out_dir.mkdir(mode=0o700)

            rewritten = list(args)
            stdin_payload: bytes | None = None
            if private_input is not None:
                marker, payload = private_input
                if not marker or marker.startswith("-") or rewritten.count(marker) != 1:
                    raise VerificationError(
                        "A private stage input must map to exactly one declared argument"
                    )
                if not isinstance(payload, bytes) or not payload:
                    raise VerificationError("A private stage input must be non-empty bytes")
                if len(payload) > _MAX_PRIVATE_INPUT_BYTES:
                    raise VerificationError("Private stage input exceeds the 64 MiB limit")
                rewritten = [_PRIVATE_STDIN if value == marker else value for value in rewritten]
                stdin_payload = payload

            for index, source in enumerate(input_paths):
                original = Path(source)
                source = _safe_input_file(original)
                staged = in_dir / str(index)
                _stage_input(source, staged)
                rewritten = _replace_exact(rewritten, original, f"/in/{index}")
                rewritten = _replace_exact(rewritten, source, f"/in/{index}")

            staged_outputs: list[Path] = []
            normalized_outputs = [Path(path).absolute() for path in output_paths]
            if len(normalized_outputs) != len(set(normalized_outputs)):
                raise VerificationError("Application stage declared duplicate output paths")
            for index, destination in enumerate(output_paths):
                original = Path(destination)
                destination = original.absolute()
                staged = out_dir / str(index)
                staged_outputs.append(staged)
                rewritten = _replace_exact(rewritten, original, f"/out/{index}")
                rewritten = _replace_exact(rewritten, destination, f"/out/{index}")

            if output_dir_argument is not None:
                output_dir_argument = Path(output_dir_argument)
                rewritten = _replace_exact(rewritten, output_dir_argument, "/out")
                rewritten = _replace_exact(rewritten, output_dir_argument.absolute(), "/out")
                staged_outputs = [out_dir / Path(path).name for path in output_paths]
                if len(staged_outputs) != len(set(staged_outputs)):
                    raise VerificationError("Application stage output names collide in staging")

            # Keep /out itself read-only and expose only the declared files as
            # writable nested bind mounts. Application code cannot create an
            # unbounded number of junk files on the host filesystem.
            for staged in staged_outputs:
                staged.touch(mode=0o600, exist_ok=False)
                if os.name == "posix":
                    os.chmod(staged, 0o600)

            name = _container_name("run")
            stage_path = f"/bundle/{stage_name}"
            mounts = [
                *_mount(bundle_root, "/bundle", readonly=True),
                *_mount(in_dir, "/in", readonly=True),
                *_mount(out_dir, "/out", readonly=True),
            ]
            for staged in staged_outputs:
                mounts.extend(_mount(staged, f"/out/{staged.name}", readonly=False))
            env = dict(_SAFE_ENV)
            if shim_dir is not None:
                shim_dir = _safe_mount_source(shim_dir)
                mounts.extend(_mount(shim_dir, "/shims", readonly=True))
                stage_path = f"/shims/{stage_name}"
                env["PYTHONPATH"] = "/bundle"

            env_argv = [item for key, value in env.items() for item in ("-e", f"{key}={value}")]
            argv = [
                *self._base_argv(name=name, network="none", limits=limits),
                *(["--interactive"] if stdin_payload is not None else []),
                *mounts,
                *env_argv,
                "-w", "/bundle",
                self.image,
                "timeout", "--signal=KILL", f"{limits.wall_seconds}s",
                "uv", "--project", "/bundle/env", "run", "--frozen", "--offline", "--no-sync",
                "python", stage_path, *rewritten,
            ]
            if stdin_payload is None:
                proc = self._execute(argv, name=name, timeout=limits.wall_seconds + 30)
            else:
                proc = self._execute(
                    argv,
                    name=name,
                    timeout=limits.wall_seconds + 30,
                    stdin_payload=stdin_payload,
                )
            if proc.returncode == 0:
                for staged, destination in zip(staged_outputs, output_paths, strict=True):
                    if not staged.is_file() or staged.is_symlink():
                        raise VerificationError(
                            f"Stage {stage_name} did not produce its declared output"
                        )
                    if staged.stat().st_size > limits.file_size_bytes:
                        raise VerificationError(
                            f"Stage {stage_name} output exceeds the sandbox file-size limit"
                        )
                    _atomic_copy(staged, Path(destination))
            return proc

    def _base_argv(self, *, name: str, network: str, limits: SandboxLimits) -> list[str]:
        uid, gid = _container_uid_gid()
        argv = [
            self.runtime, "run", "--rm", "--name", name,
            "--platform", self.platform, "--pull", "never", "--init",
            "--network", network, "--ipc", "none", "--read-only", "--user", f"{uid}:{gid}",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
            "--memory", f"{limits.memory_mb}m", "--memory-swap", f"{limits.memory_mb}m",
            "--cpus", limits.cpus, "--pids-limit", str(limits.pids),
            "--ulimit", f"nofile={limits.nofile}:{limits.nofile}",
            "--ulimit", f"fsize={limits.file_size_bytes}:{limits.file_size_bytes}",
            # This creates the private tmpfs described above, not a host temp path.
            "--tmpfs", f"{_CONTAINER_TMP}:rw,noexec,nosuid,nodev,size=64m",
            "--hostname", "blind-sandbox",
        ]
        if self.runtime_name == "podman" and hasattr(os, "getuid") and os.getuid() != 0:
            argv.extend(["--userns", "keep-id"])
        return argv

    def _execute(
        self, argv: list[str], *, name: str, timeout: int, stdin_payload: bytes | None = None
    ) -> subprocess.CompletedProcess[str]:
        try:
            io_args = (
                {"input": stdin_payload}
                if stdin_payload is not None
                else {"stdin": subprocess.DEVNULL}
            )
            result = subprocess.run(  # nosec B603
                argv,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                **io_args,
            )
            return subprocess.CompletedProcess(result.args, result.returncode, "", "")
        except subprocess.TimeoutExpired as exc:
            self._remove_container(name)
            raise VerificationError("Sandbox watchdog terminated an over-time application stage") from exc
        finally:
            self._remove_container(name)

    def _remove_container(self, name: str) -> None:
        subprocess.run(  # nosec B603
            [self.runtime, "rm", "--force", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=20,
            check=False,
        )


def _container_name(phase: str) -> str:
    return f"blind-{phase}-{secrets.token_hex(8)}"


def _container_uid_gid() -> tuple[int, int]:
    if hasattr(os, "getuid") and os.getuid() != 0:
        return os.getuid(), os.getgid()
    return 65534, 65534


def _private_tmp_root() -> str:
    return str(Store().temporary_root())


def _safe_mount_source(path: Path) -> Path:
    path = Path(path).absolute()
    if not path.exists():
        raise VerificationError(f"Sandbox mount source does not exist: {path}")
    # Resolve first (macOS mounts /var and /tmp as symlinks into /private —
    # the container runtime binds the resolved path anyway), then insist the
    # resolved path itself is symlink-free so a swapped link can't redirect
    # the mount between check and use.
    path = path.resolve(strict=True)
    for component in (path, *path.parents):
        if component.is_symlink():
            raise VerificationError(f"Refusing a symlinked sandbox mount path: {component}")
    if "," in str(path):
        raise VerificationError("Sandbox mount paths may not contain commas")
    return path


def _safe_input_file(path: Path) -> Path:
    path = _safe_mount_source(Path(path))
    if not path.is_file():
        raise UsageError(f"Application input is not a regular file: {path}")
    return path


def _mount(source: Path, target: str, *, readonly: bool) -> list[str]:
    source = _safe_mount_source(source)
    spec = f"type=bind,source={source},target={target}"
    if readonly:
        spec += ",readonly"
    return ["--mount", spec]


def _stage_input(source: Path, destination: Path) -> None:
    shutil.copyfile(source, destination)


def _replace_exact(args: list[str], source: Path, replacement: str) -> list[str]:
    forms = {str(source), str(source.absolute()), str(source.resolve())}
    return [replacement if value in forms else value for value in args]


def _atomic_copy(source: Path, destination: Path) -> None:
    destination = destination.absolute()
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    temp_path = Path(temporary)
    try:
        os.fchmod(fd, 0o600)
        with source.open("rb") as source_handle, os.fdopen(fd, "wb", closefd=True) as handle:
            fd = -1
            shutil.copyfileobj(source_handle, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, destination)
    finally:
        if fd >= 0:
            os.close(fd)
        temp_path.unlink(missing_ok=True)
