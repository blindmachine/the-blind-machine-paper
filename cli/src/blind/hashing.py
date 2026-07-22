"""Canonical SHA-256 hashing for The Blind Machine trust surface.

This module is the single source of truth for *how* every hash the CLI prints or
verifies is computed. SHA-256 throughout — never MD5 (COMMANDS.md hash vocabulary).

Hash vocabulary implemented here (COMMANDS.md):
  - application digest   = name@sha256(canonical bundle incl. manifest coordinate def)
  - public-context hash  = sha256(public context bytes)
  - cohort commitment    = sha256(sorted(contribution_hashes) + project_id + application_digest)
  - result digest        = sha256(result ciphertext bytes)
  - certificate hash     = sha256(canonical JSON of the bound fields, minus certificate_hash)
  - env_lock             = sha256(uv.lock + .python-version + runner metadata)

Because the CLI is the reference implementation of these hashes (the Rails side
tests against the *same* shared fixtures — COMMANDS.md "HTTP API contract"), the
canonicalization is defined precisely and covered by reproducibility tests.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from blind.errors import VerificationError

# Files that are NOT covered by the canonical bundle digest. `.blind-signature`
# is the signature over the digest; `.digest` and `env_lock` are derived
# artifacts the CLI writes at install time (README ~/.blind layout).
SIGNED_BUNDLE_DIR = "signed"
DERIVED_BUNDLE_FILES = frozenset({".blind-signature", ".digest", "env_lock", ".DS_Store"})

# Path *components* and file *suffixes* that are build outputs / virtualenvs / VCS
# metadata / tool caches — never application identity — and so are excluded from the
# canonical digest. Kept byte-for-byte in sync with applications/hash_bundle.py
# (the reference digest the Ruby twin + server + published vectors compute) so the
# CLI-recomputed digest is STABLE even after the bundle is sealed (`env/.venv`
# materialized) or any Python import writes `__pycache__/*.pyc` into the dir. Not
# excluding these made the recompute volatile — a fresh `.pyc` flipped the digest
# and broke the deterministic sim-run-hash / verify-by-recompute invariant.
EXCLUDED_BUNDLE_COMPONENTS = frozenset(
    {".venv", "__pycache__", ".git", ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules"}
)
EXCLUDED_BUNDLE_SUFFIXES = (".pyc", ".pyo")

# The six kit-owned stage shims (blind.runtime.shims.SHIM_NAMES) are materialized
# into a NEW-CONTRACT bundle (one shipping server.py) at RUN time and never signed
# into it — so after a stage runs (encode/encrypt during a contribution), the payload
# dir gains 00_keygen.py…50_decode.py and a naive recompute would diverge from the
# author-only signed digest. Drop these root-level shims, but ONLY for new-contract
# bundles; a legacy bundle's numbered files are the signed author code. Kept in
# lockstep with applications/hash_bundle.py::RUNTIME_SHIM_NAMES and the Ruby twin.
RUNTIME_SHIM_FILES = frozenset({
    "00_keygen.py", "10_encode.py", "20_encrypt.py",
    "30_compute_encrypted.py", "40_decrypt.py", "50_decode.py",
})

# Domain-separation header for the canonical bundle serialization. MUST stay
# byte-identical to applications/hash_bundle.py (the reference impl) and its Ruby
# twin BlindWorker::BundleHasher — the server pins bundles by the Ruby digest, so
# a CLI digest computed any other way can never equal the name suffix / server
# value and `applications install` fails closed. Covered by
# test_hashing.test_flagship_bundle_digest_matches_reference_vector.
CANONICAL_BUNDLE_HEADER = b"blind-bundle-v1\n"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_prefixed(data: bytes) -> str:
    """Return the canonical `sha256:<hex>` form used across the CLI."""
    return "sha256:" + sha256_hex(data)


def sha256_file(path: str | Path) -> str:
    """`sha256:<hex>` of a file's bytes, read in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def normalize_digest(digest: str | None) -> str:
    """Canonicalize a digest for comparison.

    Two legitimate encodings of the same SHA-256 value exist across the trust
    surface: the CLI's canonical `sha256:<hex>` form and the platform's bare
    64-hex form (the Rails side stores/serves bare hex — its certificate
    DIGEST_PATTERN forbids the prefix). Equality is decided on the hex value,
    case-insensitively. Returns '' for a missing digest.
    """
    if not digest:
        return ""
    d = str(digest).strip().lower()
    if d.startswith("sha256:"):
        d = d.split(":", 1)[1]
    return d


def digests_match(a: str | None, b: str | None) -> bool:
    """True when BOTH digests are present and encode the same SHA-256 value,
    regardless of `sha256:` prefixing. Missing digests never match — absence
    of evidence is not a verification."""
    na, nb = normalize_digest(a), normalize_digest(b)
    return bool(na) and na == nb


def require_result_digest(server_digest: str | None, data: bytes, *, what: str = "result") -> str:
    """Fail-closed integrity gate for bytes handed to us by the (untrusted) server.

    A hostile server can strip the integrity digest header (e.g. ``X-Result-Digest``)
    just as easily as it can tamper with the bytes, so an ABSENT digest is a
    verification FAILURE, not a pass — never write or decrypt bytes we could not
    check. Returns the local ``sha256:`` digest when the server's digest is present
    and matches; raises :class:`~blind.errors.VerificationError` (exit 6) otherwise.
    """
    local = sha256_prefixed(data)
    if digests_match(server_digest, local):
        return local
    if not normalize_digest(server_digest):
        raise VerificationError(
            f"Server supplied no {what} digest — refusing to trust unverified bytes",
            detail="missing integrity digest (a hostile server can strip it)",
        )
    raise VerificationError(f"{what.capitalize()} digest mismatch: {local} != {server_digest}")


def bundle_payload_root(root: str | Path) -> Path:
    """Preferred layout: hash <bundle>/signed. Legacy root bundles still work."""
    root = Path(root)
    signed = root / SIGNED_BUNDLE_DIR
    if signed.is_dir() and (signed / "manifest.yml").is_file():
        return signed
    return root


def _iter_bundle_files(
    root: Path, exclude: frozenset[str], *, exclude_shims: bool = False
) -> list[tuple[str, Path]]:
    """Every file under `root`, as (posix-relative-path, absolute-path), sorted,
    excluding any path whose *name* is in `exclude`, whose path traverses an
    excluded build/cache/VCS component (`.venv`, `__pycache__`, …), or whose
    suffix is compiled Python (`.pyc`/`.pyo`). When `exclude_shims` is set, also
    drops the run-time-materialized numbered stage shims at the payload root."""
    out: list[tuple[str, Path]] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        if p.name in exclude:
            continue
        rel_path = p.relative_to(root)
        rel_posix = rel_path.as_posix()
        if exclude_shims and rel_posix in RUNTIME_SHIM_FILES:
            continue
        if any(part in EXCLUDED_BUNDLE_COMPONENTS for part in rel_path.parts):
            continue
        if rel_path.suffix in EXCLUDED_BUNDLE_SUFFIXES:
            continue
        out.append((rel_posix, p))
    return sorted(out, key=lambda t: t[0])


def canonical_bundle_digest(
    root: str | Path, *, exclude: frozenset[str] = DERIVED_BUNDLE_FILES
) -> str:
    """Content-address an application bundle directory.

    Canonical serialization (blind-bundle-v1) — byte-identical to the reference
    ``applications/hash_bundle.py`` and its Ruby twin ``BlindWorker::BundleHasher``:

        sha256( b"blind-bundle-v1\\n"
                + for each covered file, ascending by relative path:
                      <relpath utf-8> b"\\x00" <sha256(content) hex ascii> b"\\n" )

    Hashing each file's *content digest* (not its raw bytes) keeps the framing
    injective without a length prefix and matches what the server pins the
    bundle by. Ordering makes the digest directory-order independent.
    Returns `sha256:<hex>`.
    """
    root = bundle_payload_root(root)
    # A new-contract bundle ships server.py; its numbered stage files are run-time
    # shims (excluded), whereas a legacy bundle's numbered files are author code.
    exclude_shims = (root / "server.py").is_file()
    h = hashlib.sha256()
    h.update(CANONICAL_BUNDLE_HEADER)
    for rel, abspath in _iter_bundle_files(root, exclude, exclude_shims=exclude_shims):
        data = abspath.read_bytes()
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(hashlib.sha256(data).hexdigest().encode("ascii"))
        h.update(b"\n")
    return "sha256:" + h.hexdigest()


def application_id(name: str, digest: str) -> str:
    """Compose the content-addressed application id `name@sha256:<hex>`."""
    if "@" in name:  # already an id
        return name
    return f"{name}@{digest}"


def split_application_id(application: str) -> tuple[str, str | None]:
    """`allele_frequency_count@sha256:ab..` -> ('allele_frequency_count', 'sha256:ab..')."""
    if "@" in application:
        name, digest = application.split("@", 1)
        return name, digest
    return application, None


def env_lock_digest(uv_lock: bytes, python_version: bytes, runner_meta: str = "") -> str:
    """`sha256:<hex>` over uv.lock + .python-version + pinned runner metadata."""
    h = hashlib.sha256()
    h.update(uv_lock)
    h.update(b"\0")
    h.update(python_version)
    h.update(b"\0")
    h.update(runner_meta.encode("utf-8"))
    return "sha256:" + h.hexdigest()


def cohort_commitment(
    contribution_hashes: list[str], project_id: str, application_digest: str
) -> str:
    """cohort commitment = sha256(sorted(contribution_hashes) + project_id + application_digest).

    The contribution hashes are sorted lexicographically and concatenated with no
    separator, then the project id and the pinned application digest are appended.
    Returns `sha256:<hex>`.
    """
    # project_id / application_digest may arrive as ints or non-str from JSON —
    # coerce so the concat matches the server's `... + project_id.to_s + digest`.
    joined = "".join(sorted(contribution_hashes)) + str(project_id) + str(application_digest)
    return "sha256:" + sha256_hex(joined.encode("utf-8"))


def canonical_json(obj: dict) -> bytes:
    """Deterministic JSON: sorted keys, no insignificant whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


# The EXACT fields a Computation Certificate binds (ComputationCertificate#
# canonical_payload). The certificate_hash is SHA256 over the canonical JSON of
# JUST these — the flat API response also carries `certificate_hash`/`issued_at`,
# which are NOT part of the hashed body. Mirror the set so an offline recompute
# equals the server's value.
CERTIFICATE_BOUND_FIELDS = frozenset({
    "cohort_commitment", "cohort_size", "computation_run_id", "min_contributors",
    "min_n_satisfied", "project_id", "application_digest", "public_context_digest",
    "release_policy", "result_digest", "run_count",
    # RFC 0003 §7 — the keyholder key that authorized the run's public context (or
    # null for an unsigned project). Old certificates (without this key) still verify
    # via certificate_hash()'s all-fields fallback; new ones bind it.
    "owner_signing_key_digest",
})


def certificate_hash(certificate_body: dict) -> str:
    """`sha256:<hex>` over the canonical JSON of a certificate's BOUND fields.

    For a real certificate (all bound fields present) we hash exactly those — so
    the result matches the server, ignoring transport-only extras like
    `issued_at`. For an arbitrary body (fixtures) we fall back to "everything but
    `certificate_hash`" (a certificate cannot hash itself)."""
    if CERTIFICATE_BOUND_FIELDS.issubset(certificate_body.keys()):
        body = {k: v for k, v in certificate_body.items() if k in CERTIFICATE_BOUND_FIELDS}
    else:
        body = {k: v for k, v in certificate_body.items() if k != "certificate_hash"}
    return "sha256:" + sha256_hex(canonical_json(body))


def short(digest: str, head: int = 4, tail: int = 2) -> str:
    """`sha256:4d1e…c0` short form for terminal display. A missing value (None /
    empty — e.g. an unfrozen project's cohort commitment) renders as an em dash."""
    if not digest:
        return "—"
    digest = str(digest)
    if ":" in digest:
        prefix, hexpart = digest.split(":", 1)
    else:
        prefix, hexpart = "", digest
    if len(hexpart) <= head + tail:
        return digest
    body = f"{hexpart[:head]}…{hexpart[-tail:]}"
    return f"{prefix}:{body}" if prefix else body
