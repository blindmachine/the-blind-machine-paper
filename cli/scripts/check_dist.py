#!/usr/bin/env python3
"""Fail closed when a wheel or sdist leaks, diverges, or has unsafe structure."""

from __future__ import annotations

import base64
import csv
import email
import hashlib
import io
import re
import stat
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
PROJECT_NAME = PROJECT["name"]
PROJECT_VERSION = PROJECT["version"]
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024

SECRET_PATTERNS = {
    "private key": re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "AWS access key": re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    "GitHub token": re.compile(rb"gh[pousr]_[A-Za-z0-9_]{30,}"),
    "GitLab token": re.compile(rb"glpat-[A-Za-z0-9_-]{20,}"),
    "Google API key": re.compile(rb"AIza[0-9A-Za-z_-]{35}"),
    "PyPI token": re.compile(rb"pypi-[A-Za-z0-9_-]{40,}"),
    "Slack token": re.compile(rb"xox[baprs]-[A-Za-z0-9-]{20,}"),
    "Stripe live key": re.compile(rb"(?:sk|rk)_live_[A-Za-z0-9]{20,}"),
}
EMAIL_PATTERN = re.compile(rb"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
PUBLIC_EMAIL_DOMAINS = {b"blindmachine.org", b"example.com", b"example.test"}
SENSITIVE_NAMES = re.compile(
    r"(?:^|/)(?:"
    r"\.env(?:\..*)?|\.git-credentials|\.netrc|\.npmrc|\.pypirc|"
    r"credentials(?:\..*)?|master\.key|secrets?\.ya?ml|"
    r"id_rsa|id_ed25519|.*\.(?:key|pem|p12|pfx|sqlite3?|db)"
    r")$",
    re.IGNORECASE,
)
SDIST_TOP_FILES = {
    ".gitignore",
    "LICENSE",
    "PKG-INFO",
    "README.md",
    "SECURITY.md",
    "pyproject.toml",
    "uv.lock",
}


def fail(message: str) -> None:
    raise SystemExit(message)


def safe_archive_path(name: str) -> PurePosixPath:
    if "\\" in name:
        fail(f"archive member uses a backslash path: {name}")
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        fail(f"unsafe archive member path: {name}")
    return path


def scan(name: str, payload: bytes) -> None:
    if len(payload) > MAX_MEMBER_BYTES:
        fail(f"oversized distribution member: {name}")
    if SENSITIVE_NAMES.search(name):
        fail(f"sensitive filename included in distribution: {name}")
    for match in EMAIL_PATTERN.finditer(payload):
        if match.group(1).lower() not in PUBLIC_EMAIL_DOMAINS:
            fail(f"non-public email address included in distribution: {name}")
    for label, pattern in SECRET_PATTERNS.items():
        if pattern.search(payload):
            fail(f"possible {label} included in distribution: {name}")


def expected_sources() -> set[str]:
    source_root = ROOT / "src"
    return {
        path.relative_to(source_root).as_posix()
        for path in source_root.joinpath("blind").rglob("*.py")
        if path.is_file() and not path.is_symlink()
    }


def check_metadata(payload: bytes, *, source: str) -> email.message.Message:
    metadata = email.message_from_bytes(payload)
    if metadata.get("Name") != PROJECT_NAME:
        fail(f"{source} project name is not {PROJECT_NAME}")
    if metadata.get("Version") != PROJECT_VERSION:
        fail(f"{source} version does not match pyproject.toml")
    if metadata.get("Requires-Python") != ">=3.11":
        fail(f"{source} has an unexpected Python requirement")
    project_urls = metadata.get_all("Project-URL", [])
    if "Source, https://github.com/blindmachine/blind" not in project_urls:
        fail(f"{source} does not identify the reviewed source repository")
    for requirement in metadata.get_all("Requires-Dist", []):
        package_spec = requirement.split(";", 1)[0].strip()
        if "==" not in package_spec or any(operator in package_spec for operator in (">=", "<=", "~=", "!=")):
            fail(f"{source} contains a non-exact dependency: {requirement}")
    return metadata


def verify_wheel_record(archive: zipfile.ZipFile, record_name: str, files: set[str]) -> None:
    rows = list(csv.reader(io.StringIO(archive.read(record_name).decode("utf-8"))))
    records = {row[0]: row[1:] for row in rows}
    if set(records) != files:
        fail("wheel RECORD does not enumerate exactly every archive file")
    for name in sorted(files - {record_name}):
        digest, size = records[name]
        payload = archive.read(name)
        expected = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
        if digest != f"sha256={expected}" or size != str(len(payload)):
            fail(f"wheel RECORD hash/size mismatch: {name}")
    if records[record_name] != ["", ""]:
        fail("wheel RECORD must leave its own digest and size empty")


def check_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            fail("wheel contains duplicate member names")
        total_size = 0
        files: set[str] = set()
        for info in infos:
            safe_archive_path(info.filename.rstrip("/"))
            if info.is_dir():
                continue
            mode = info.external_attr >> 16
            if mode and stat.S_ISLNK(mode):
                fail(f"wheel contains a symbolic link: {info.filename}")
            total_size += info.file_size
            if total_size > MAX_ARCHIVE_BYTES:
                fail("wheel expands beyond the size limit")
            files.add(info.filename)
        dist_info_roots = {
            PurePosixPath(name).parts[0] for name in files if ".dist-info/" in name
        }
        if len(dist_info_roots) != 1:
            fail("wheel must contain exactly one dist-info directory")
        dist_info = dist_info_roots.pop()
        metadata_name = f"{dist_info}/METADATA"
        entry_name = f"{dist_info}/entry_points.txt"
        record_name = f"{dist_info}/RECORD"
        for required in (metadata_name, entry_name, record_name):
            if required not in files:
                fail(f"wheel is missing {required}")
        check_metadata(archive.read(metadata_name), source="wheel metadata")
        entries = archive.read(entry_name).decode("utf-8")
        for expected in ("blind = blind.__main__:main", "blindmachine = blind.__main__:main"):
            if expected not in entries:
                fail(f"wheel is missing entry point: {expected}")
        packaged_sources: set[str] = set()
        for name in sorted(files):
            if not (name.startswith("blind/") or name.startswith(f"{dist_info}/")):
                fail(f"unexpected wheel member: {name}")
            if name.startswith("blind/") and not name.endswith(".py"):
                fail(f"unexpected non-Python package data in wheel: {name}")
            payload = archive.read(name)
            scan(name, payload)
            if name.startswith("blind/") and name.endswith(".py"):
                packaged_sources.add(name)
                source_file = ROOT / "src" / name
                if not source_file.is_file() or source_file.is_symlink() or source_file.read_bytes() != payload:
                    fail(f"wheel source differs from reviewed repository file: {name}")
        if packaged_sources != expected_sources():
            fail("wheel source module set differs from reviewed repository")
        verify_wheel_record(archive, record_name, files)


def check_sdist(path: Path) -> None:
    with tarfile.open(path, "r:gz") as archive:
        all_members = archive.getmembers()
        names = [member.name for member in all_members]
        if len(names) != len(set(names)):
            fail("sdist contains duplicate member names")
        roots: set[str] = set()
        total_size = 0
        packaged_sources: set[str] = set()
        seen_top_files: set[str] = set()
        pkg_info: bytes | None = None
        for member in all_members:
            member_path = safe_archive_path(member.name.rstrip("/"))
            roots.add(member_path.parts[0])
            if member.isdir():
                continue
            if not member.isfile():
                fail(f"sdist contains a link or special file: {member.name}")
            total_size += member.size
            if member.size > MAX_MEMBER_BYTES or total_size > MAX_ARCHIVE_BYTES:
                fail(f"sdist member exceeds the size boundary: {member.name}")
        if len(roots) != 1:
            fail("sdist must contain exactly one root directory")
        root = roots.pop()
        if root != f"{PROJECT_NAME}-{PROJECT_VERSION}":
            fail("sdist root directory does not match project name and version")
        for member in all_members:
            if not member.isfile():
                continue
            relative = PurePosixPath(member.name).relative_to(root)
            name = relative.as_posix()
            top = relative.parts[0]
            allowed = name in SDIST_TOP_FILES or (
                top == "src" and name.startswith("src/blind/") and name.endswith(".py")
            )
            if not allowed:
                fail(f"unexpected file included in sdist: {name}")
            handle = archive.extractfile(member)
            payload = handle.read() if handle else b""
            scan(name, payload)
            if name in SDIST_TOP_FILES:
                seen_top_files.add(name)
                if name != "PKG-INFO" and (ROOT / name).read_bytes() != payload:
                    fail(f"sdist metadata differs from reviewed repository file: {name}")
            if name == "PKG-INFO":
                pkg_info = payload
            if name.startswith("src/blind/"):
                source_name = name.removeprefix("src/")
                packaged_sources.add(source_name)
                source_file = ROOT / name
                if not source_file.is_file() or source_file.is_symlink() or source_file.read_bytes() != payload:
                    fail(f"sdist source differs from reviewed repository file: {name}")
        if seen_top_files != SDIST_TOP_FILES:
            fail("sdist is missing required public metadata files")
        if packaged_sources != expected_sources():
            fail("sdist source module set differs from reviewed repository")
        if pkg_info is None:
            fail("sdist is missing PKG-INFO")
        check_metadata(pkg_info, source="sdist metadata")


def main() -> int:
    dist = ROOT / "dist"
    if dist.is_symlink() or not dist.is_dir():
        fail("dist must be a real directory inside the reviewed repository")
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        fail(f"expected one wheel and one sdist, found {len(wheels)} and {len(sdists)}")
    check_wheel(wheels[0])
    check_sdist(sdists[0])
    print(f"distribution boundary verified: {wheels[0].name}, {sdists[0].name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
