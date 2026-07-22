"""Shared test fixtures.

Every test runs with:
  * the production home resolver injected with a temp dir (no real ~/.blind),
  * BLIND_SECRET_BACKEND=file (explicit deterministic test-only secret storage),
  * BLIND_STAGE_RUNNER=direct plus the named unsafe opt-in (fake stages run under
    the test interpreter, so the unit suite needs no container or TenSEAL),
and ZERO network calls (the API is exercised via httpx.MockTransport).
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

import blind.store as store_module
from blind.hashing import canonical_bundle_digest
from blind.runtime import bundle as bundle_mod
from blind.store import Store

# --- stub application stage scripts (the I/O convention; value-preserving crypto) ---

# Every stub stage speaks BOTH conventions (like _COMPUTE below): the CLI's local
# workdir/input.json runner (Convention A — what workspace.py/run_stage drive) AND
# the shipped bundles' argparse CLI (Convention B — --out-dir/--raw/--context/
# --encoded/--out/--result/--plain, what `blind bench`/simulate now drive through
# blind.runtime.compute's argparse invokers + the application_io adapter). The
# discriminator: Convention A passes a workdir path as argv[1]; Convention B passes
# a leading `--flag`.

_KEYGEN = '''\
import argparse, json, sys
from pathlib import Path
if sys.argv[1].startswith("--"):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    a, _ = ap.parse_known_args()
    d = Path(a.out_dir); d.mkdir(parents=True, exist_ok=True)
    (d/"public_context.tenseal").write_text(json.dumps({"scheme": "stub-additive", "public": True}))
    (d/"secret_context.tenseal").write_text(json.dumps({"scheme": "stub-additive", "secret": True}))
else:
    work = Path(sys.argv[1]); data = json.loads((work/"input.json").read_text())
    pub = data["out_public"]; sec = data["out_secret"]
    Path(pub).write_text(json.dumps({"scheme": "stub-additive", "public": True}))
    Path(sec).write_text(json.dumps({"scheme": "stub-additive", "secret": True}))
    (work/"output.json").write_text(json.dumps({"meta": {"public": pub, "secret": sec}}))
'''

# The encode stub also defines its stage-local transform. Production oracles never
# import this bundle code into the host interpreter; they reconstruct the signed
# manifest's declarative transform in trusted CLI code.
_ENCODE = '''\
import argparse, hashlib, json, sys
from pathlib import Path


def encode(vector, length):
    v = [int(x) for x in list(vector)[:length]]
    return v + [0] * (length - len(v))


def _vec(raw):
    return raw["vector"] if isinstance(raw, dict) and "vector" in raw else raw


if __name__ == "__main__":
    if sys.argv[1].startswith("--"):
        ap = argparse.ArgumentParser()
        ap.add_argument("--raw", required=True)
        ap.add_argument("--length", type=int, required=True)
        ap.add_argument("--out", required=True)
        a, _ = ap.parse_known_args()
        raw = json.loads(Path(a.raw).read_text())
        Path(a.out).write_text(json.dumps({"vector": encode(_vec(raw), a.length)}))
    else:
        work = Path(sys.argv[1]); data = json.loads((work/"input.json").read_text())
        raw = json.loads(Path(data["input"]).read_text())
        out = Path(data["out"]); out.write_text(json.dumps({"vector": _vec(raw)}))
        sha = "sha256:" + hashlib.sha256(out.read_bytes()).hexdigest()
        (work/"output.json").write_text(json.dumps({"artifact": str(out), "sha256": sha}))
'''

_ENCRYPT = '''\
import argparse, hashlib, json, sys
from pathlib import Path
if sys.argv[1].startswith("--"):
    ap = argparse.ArgumentParser()
    ap.add_argument("--context", required=True)
    ap.add_argument("--encoded", required=True)
    ap.add_argument("--out", required=True)
    a, _ = ap.parse_known_args()
    enc = json.loads(Path(a.encoded).read_text())
    Path(a.out).write_text(json.dumps({"vector": enc["vector"], "sentinel": 1}))
else:
    work = Path(sys.argv[1]); data = json.loads((work/"input.json").read_text())
    enc = json.loads(Path(data["input"]).read_text())
    out = Path(data["out"])
    out.write_text(json.dumps({"vector": enc["vector"], "sentinel": 1}))
    sha = "sha256:" + hashlib.sha256(out.read_bytes()).hexdigest()
    (work/"output.json").write_text(json.dumps({"artifact": str(out), "sha256": sha}))
'''

# The compute stub speaks BOTH conventions: the server/worker argparse contract
# (--context/--inputs/--out — what the real flagship 30_compute_encrypted.py
# implements and what the local simulate/compute path drives) AND the CLI's local
# workdir/input.json convention (what run_stage/simulate drive for stub bundles).
_COMPUTE = '''\
import json, sys, hashlib
from pathlib import Path

def _sum(paths):
    acc = None; sentinel = 0
    for p in paths:
        ct = json.loads(Path(p).read_text())
        v = ct["vector"]; sentinel += ct.get("sentinel", 0)
        acc = list(v) if acc is None else [a+b for a,b in zip(acc, v)]
    return {"vector": acc or [], "sentinel": sentinel}

if "--context" in sys.argv or "--inputs" in sys.argv:
    # Convention B — the server contract (argparse, named flags).
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--context", required=True)
    ap.add_argument("--inputs", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    Path(args.out).write_text(json.dumps(_sum(args.inputs)))
    sys.exit(0)

# Convention A — the CLI's local workdir/input.json runner.
work = Path(sys.argv[1]); data = json.loads((work/"input.json").read_text())
out = Path(data["out"])
out.write_text(json.dumps(_sum(data["inputs"])))
sha = "sha256:" + hashlib.sha256(out.read_bytes()).hexdigest()
(work/"output.json").write_text(json.dumps({"artifact": str(out), "sha256": sha}))
'''

# Multiplicative-BFV stub compute — the SECOND application shape used to exercise the
# crypto-axis / --crypto machinery (never all six applications). It models
# allele_frequency_with_variance, whose manifest `computation: multiplicative_bfv`
# selects application_io.VARIANCE_IO. That adapter checks EXACTNESS on the additive
# FIRST moment (sum_g = Σ encode(vec)), so this compute folds additively (the
# ct×ct second moment lives in the real bundle; the checked aggregate is the sum).
# Speaks BOTH conventions like _COMPUTE.
_COMPUTE_MUL = '''\
import argparse, hashlib, json, sys
from pathlib import Path

def _sum(paths):
    acc = None; sentinel = 0
    for p in paths:
        ct = json.loads(Path(p).read_text())
        v = ct["vector"]; sentinel += ct.get("sentinel", 0)
        acc = list(v) if acc is None else [a+b for a,b in zip(acc, v)]
    return {"vector": acc or [], "sentinel": sentinel}

if "--context" in sys.argv or "--inputs" in sys.argv:
    ap = argparse.ArgumentParser()
    ap.add_argument("--context", required=True)
    ap.add_argument("--inputs", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    Path(args.out).write_text(json.dumps(_sum(args.inputs)))
    sys.exit(0)

work = Path(sys.argv[1]); data = json.loads((work/"input.json").read_text())
out = Path(data["out"])
out.write_text(json.dumps(_sum(data["inputs"])))
sha = "sha256:" + hashlib.sha256(out.read_bytes()).hexdigest()
(work/"output.json").write_text(json.dumps({"artifact": str(out), "sha256": sha}))
'''

_DECRYPT = '''\
import argparse, hashlib, json, sys
from pathlib import Path
if sys.argv[1].startswith("--"):
    ap = argparse.ArgumentParser()
    ap.add_argument("--context", required=True)
    ap.add_argument("--result", required=True)
    ap.add_argument("--out", required=True)
    a, _ = ap.parse_known_args()
    ct = json.loads(Path(a.result).read_text())
    Path(a.out).write_text(json.dumps(ct))
else:
    work = Path(sys.argv[1]); data = json.loads((work/"input.json").read_text())
    ct = json.loads(Path(data["input"]).read_text())
    out = Path(data["out"]); out.write_text(json.dumps(ct))
    sha = "sha256:" + hashlib.sha256(out.read_bytes()).hexdigest()
    (work/"output.json").write_text(json.dumps({"artifact": str(out), "sha256": sha}))
'''

_DECODE = '''\
import argparse, hashlib, json, sys
from pathlib import Path
if sys.argv[1].startswith("--"):
    ap = argparse.ArgumentParser()
    ap.add_argument("--plain", required=True)
    ap.add_argument("--length", type=int, required=True)
    ap.add_argument("--out", required=True)
    a, _ = ap.parse_known_args()
    plain = json.loads(Path(a.plain).read_text())
    Path(a.out).write_text(json.dumps({"vector": plain["vector"], "sentinel_n": plain.get("sentinel")}))
else:
    work = Path(sys.argv[1]); data = json.loads((work/"input.json").read_text())
    plain = json.loads(Path(data["input"]).read_text())
    out = Path(data["out"])
    out.write_text(json.dumps({"vector": plain["vector"], "sentinel_n": plain.get("sentinel")}))
    sha = "sha256:" + hashlib.sha256(out.read_bytes()).hexdigest()
    (work/"output.json").write_text(json.dumps({"artifact": str(out), "sha256": sha}))
'''

_MANIFEST = """\
name: {name}
version: 1.0.0
builder:
  type: uv
  project: env
crypto: stub-additive
computation: {computation}
min_contributors: 3
input:
  type: integer_vector
  length: {length}
  value_domain: [0, 1, 2]
  coordinates:
    kind: synthetic_variants
    seed: blind-test
    fields: [chrom, pos, ref, alt]
output:
  shape: aggregate_count_vector
  exactness: exact
  tolerance: 0
release_policy:
  aggregate_only: true
  allowed_runs_per_project: 1
resources:
  max_memory_mb: 512
  max_wall_seconds: 60
stages:
  keygen:  {{ file: 00_keygen.py, runs: local }}
  encode:  {{ file: 10_encode.py, runs: local }}
  encrypt: {{ file: 20_encrypt.py, runs: local }}
  compute: {{ file: 30_compute_encrypted.py, runs: server }}
  decrypt: {{ file: 40_decrypt.py, runs: local }}
  decode:  {{ file: 50_decode.py, runs: local }}
"""


def _write_bundle_files(root: Path, name: str, length: int = 4,
                        computation: str = "additive_bfv", compute_src: str = _COMPUTE) -> None:
    root.mkdir(parents=True, exist_ok=True)
    signed = root / "signed"
    signed.mkdir(parents=True, exist_ok=True)
    (signed / "manifest.yml").write_text(
        _MANIFEST.format(name=name, length=length, computation=computation))
    (signed / "00_keygen.py").write_text(_KEYGEN)
    (signed / "10_encode.py").write_text(_ENCODE)
    (signed / "20_encrypt.py").write_text(_ENCRYPT)
    (signed / "30_compute_encrypted.py").write_text(compute_src)
    (signed / "40_decrypt.py").write_text(_DECRYPT)
    (signed / "50_decode.py").write_text(_DECODE)
    env = signed / "env"
    env.mkdir(exist_ok=True)
    (env / "pyproject.toml").write_text(
        '[project]\nname = "stub"\nversion = "1.0.0"\nrequires-python = ">=3.11"\n'
    )
    (env / "uv.lock").write_text("# stub lock\nversion = 1\n")
    (env / ".python-version").write_text("3.11\n")
    tests = root / "tests" / "vectors"
    tests.mkdir(parents=True, exist_ok=True)
    (tests / "v1.json").write_text('{"vector": [1, 0, 2, 1]}')
    exp = root / "tests" / "expected"
    exp.mkdir(parents=True, exist_ok=True)
    (exp / "v1.json").write_text('{"vector": [1, 0, 2, 1]}')
    (root / "README.md").write_text("# stub application\n")
    (root / "SECURITY.md").write_text("stub\n")


@pytest.fixture(autouse=True)
def blind_env(tmp_path, monkeypatch):
    home = tmp_path / "dot-blind"
    monkeypatch.setattr(store_module, "blind_home", lambda: home)
    monkeypatch.setenv("BLIND_SECRET_BACKEND", "file")
    monkeypatch.setenv("BLIND_STAGE_RUNNER", "direct")
    monkeypatch.setenv("BLIND_UNSAFE_ALLOW_DIRECT_STAGE_RUNNER", "1")
    monkeypatch.setenv("BLIND_UNSAFE_SKIP_SEAL", "1")
    monkeypatch.setenv("NO_COLOR", "1")
    # reset any leaked test transport between tests
    import blind.context as ctxmod
    ctxmod.set_test_transport(None)
    yield home


@pytest.fixture
def signing_keys(monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
    pub_hex = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()
    monkeypatch.setenv("BLIND_SIGNING_KEY", pub_hex)
    monkeypatch.setenv("BLIND_UNSAFE_ALLOW_CUSTOM_SIGNING_KEY", "1")
    # keep module-level cache in sync (bundle.py reads it at import)
    monkeypatch.setattr(bundle_mod, "_BUILTIN_SIGNING_KEY_HEX", pub_hex, raising=False)
    return {"private_hex": priv_hex, "public_hex": pub_hex}


@pytest.fixture
def make_bundle(tmp_path, signing_keys):
    """Materialize a signed stub bundle in a source dir. Returns (root, application_id)."""
    counter = {"n": 0}

    def _make(name: str = "allele_frequency_count", length: int = 4, sign: bool = True,
              computation: str = "additive_bfv", compute_src: str = _COMPUTE):
        counter["n"] += 1
        src = tmp_path / f"src-{name}-{counter['n']}"
        _write_bundle_files(src, name, length=length, computation=computation,
                            compute_src=compute_src)
        digest = canonical_bundle_digest(src)
        if sign:
            bundle_mod.sign_bundle(src, signing_keys["private_hex"])
        else:
            (src / ".blind-signature").write_text("00" * 8 + "\n")
        return src, f"{name}@{digest}"

    return _make


def _install_bundle(make_bundle, **make_kwargs):
    import shutil

    store = Store()
    store.ensure_layout()
    src, application_id = make_bundle(**make_kwargs)
    dest = store.application_dir(application_id)
    shutil.copytree(src, dest)
    from blind.runtime.bundle import load_bundle
    from blind.runtime.sealer import seal_env

    b = load_bundle(dest)
    seal_env(b, no_seal=True)  # records env_lock + .digest without uv
    return store, b, application_id


@pytest.fixture
def installed(make_bundle):
    """Install a stub bundle into the temp ~/.blind and return (store, bundle, application_id)."""
    return _install_bundle(make_bundle)


@pytest.fixture
def installed_mul(make_bundle):
    """Install a MULTIPLICATIVE-BFV stub (compute squares then sums) — the SECOND
    application shape used to exercise the crypto-axis machinery (never all six)."""
    return _install_bundle(
        make_bundle, name="allele_frequency_with_variance",
        computation="multiplicative_bfv", compute_src=_COMPUTE_MUL)


@pytest.fixture
def covariance_bundle(make_bundle, signing_keys):
    """Self-contained signed fixture with the covariance manifest shape."""
    import yaml

    src, _ = make_bundle(name="genotype_phenotype_covariance")
    manifest_path = src / "signed" / "manifest.yml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["input"] = {
        "genotype": {"type": "integer_vector", "length": 4, "value_domain": [0, 1, 2]},
        "phenotype": {"type": "integer_scalar", "value_domain": [0, 1]},
        "submitted_as": "one_packed_pair_ciphertext",
    }
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    bundle_mod.sign_bundle(src, signing_keys["private_hex"])
    return bundle_mod.load_bundle(src)


def json_out(result):
    """Parse the first JSON object out of a CliRunner result (rich may wrap it)."""
    import json as _json

    text = result.stdout
    start = text.index("{")
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return _json.loads(text[start:i + 1])
    raise AssertionError("no JSON object in output:\n" + text)


def mock_transport(routes: dict):
    """Build an httpx.MockTransport from {(method, path): response_dict|callable}.

    ``path`` matches the request path (e.g. '/api/v1/projects'). A callable
    receives the httpx.Request and returns an httpx.Response.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        key = (request.method, request.url.path)
        if key in routes:
            r = routes[key]
            if callable(r):
                return r(request)
            status, body = r if isinstance(r, tuple) else (200, r)
            return httpx.Response(status, json=body)
        # prefix match fallback
        for (m, p), r in routes.items():
            if m == request.method and request.url.path.startswith(p):
                status, body = r if isinstance(r, tuple) else (200, r)
                return httpx.Response(status, json=body)
        return httpx.Response(404, json={"error": f"no route for {key}"})

    return httpx.MockTransport(handler)
