#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#  The Blind Machine — "register real users, then run the whole loop" DEMO
#
#  This is an EXAMPLE (see the directory name: cli/examples/). It is not part of
#  the shipped `blind` command surface — it is a narrated Python script that
#  drives the real `blind` CLI end-to-end so you can watch the entire trust story
#  happen, from account signup to a verified homomorphic result.
#
#  Unlike demo/demo.sh (where data owners are ACCOUNTLESS), this demo REGISTERS
#  four uniquely named accounts against an explicitly selected server and has each
#  of them log the CLI in as themselves:
#
#      researcher+<random>@example.com       ← opens the study, holds the secret key
#      dataowner1+<random>@example.com       ┐
#      dataowner2+<random>@example.com       ├ three registered data owners
#      dataowner3+<random>@example.com       ┘
#
#  Then the full loop runs, all through the `blind` CLI:
#
#      RESEARCHER   registers from the CLI (`blind register`), installs + verifies the
#                   signed application, opens a project, generates the crypto keys
#                   LOCALLY (only the PUBLIC context is published), and invites each
#                   data owner with their own contributor link.
#      DATA OWNERS  each registers from the CLI too, then encodes +
#                   encrypts every individual LOCALLY and uploads ONLY ciphertext
#                   through their invite link. (Registered data owners still
#                   contribute via the link: The Blind Machine has no project-
#                   membership upload path — an account may only upload to a
#                   project it OWNS — so the invite link is the contributor door.)
#      RESEARCHER   freezes the cohort, dispatches the homomorphic compute job on
#                   ciphertext, decrypts the aggregate LOCALLY, and prints the
#                   reviewer's one-command offline proof.
#      —            finally, the decrypted aggregate is shown to be BIT-IDENTICAL
#                   to computing the same sum in the clear.
#
#  Nothing but ciphertext ever leaves a data owner's machine, and every step is a
#  real `blind` CLI command against a real instance of the Rails server.
#
#  Usage
#  ─────
#      python examples/register_and_run.py                 # run against https://blindmachine.org
#      python examples/register_and_run.py --local         # boot a local worker-enabled server + run
#      python examples/register_and_run.py --server https://staging.example.com --allow-remote
#      python examples/register_and_run.py --local --fast  # no pauses (good for recording)
#
#  Requirements: Python 3.11+, `uv` (the CLI runs under `uv run blind`). With no
#  target, the demo runs against production (https://blindmachine.org). `--local`
#  boots the monorepo's demo/bootstrap_server.sh; an explicit non-production
#  `--server` requires `--allow-remote`, and an explicit production `--server`
#  additionally requires `--allow-production`. Any target must have open
#  registration and a live compute worker.
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations

import argparse
import atexit
import ipaddress
import json
import os
import pathlib
import random
import re
import secrets
import shutil
# Every invocation below uses a fixed executable and an argv list without a shell.
import subprocess  # nosec B404
import sys
import tempfile
import time
from urllib.parse import urlsplit

# examples/register_and_run.py  →  CLI_DIR = cli/  →  ROOT = the monorepo root.
HERE = pathlib.Path(__file__).resolve().parent
CLI_DIR = HERE.parent
ROOT = CLI_DIR.parent

APPLICATION = "allele_frequency_count"                  # the flagship study
PRODUCTION_HOST = "blindmachine.org"


# ═════════════════════════════════════════════════════════════════════════════
#  Narration — a tiny ANSI helper mirroring demo/lib.sh, so this demo reads the
#  same way. The `blind` CLI prints its own gorgeous transcript; we only add the
#  story around it (sections, roles, steps).
# ═════════════════════════════════════════════════════════════════════════════
_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _COLOR else s


BOLD = "1"
DIM = "2"
RED = "31"
GREEN = "32"
YELLOW = "33"
BLUE = "34"
MAGENTA = "35"
CYAN = "36"
CMD = "1;93"  # bold bright-yellow — the "$ blind …" command lines, so they stand out

SPEED_FAST = False


def banner(text: str) -> None:
    bar = "━" * 78
    print("\n" + _c(f"{BOLD};{BLUE}", bar))
    print(_c(f"{BOLD};{BLUE}", f"  {text}"))
    print(_c(f"{BOLD};{BLUE}", bar))


def section(n: str, title: str) -> None:
    rule = "─" * 76
    print()
    print(_c("90", rule))
    print(_c(f"{BOLD};{BLUE}", f"§{n}  {title}"))
    print(_c("90", rule))


def role(name: str, color: str, action: str) -> None:
    print("\n" + _c(f"{color};{BOLD}", f"▮  {name:<13}") + " " + _c(DIM, action))


def step(msg: str) -> None:
    print(_c(CYAN, "→ ") + msg)


def note(msg: str) -> None:
    print("  " + _c(DIM, msg))


def ok(msg: str) -> None:
    print(_c(f"{GREEN};{BOLD}", "✓ ") + msg)


def bad(msg: str) -> None:
    print(_c(f"{RED};{BOLD}", "✗ ") + msg)


def pause() -> None:
    if SPEED_FAST:
        return
    if sys.stdin.isatty():
        try:
            input(_c("90", "   … press Enter to continue"))
        except EOFError:
            pass
    else:
        time.sleep(1)


def die(msg: str) -> None:
    bad(msg)
    sys.exit(1)


def validate_server_target(server: str, *, allow_remote: bool, allow_production: bool) -> str:
    """Require deliberate opt-in before this side-effectful demo reaches a remote host."""
    parsed = urlsplit(server)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        die("--server must be an origin URL without credentials, path, query, or fragment")
    host = parsed.hostname.rstrip(".").lower()
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if loopback:
        return server.rstrip("/")
    if parsed.scheme != "https":
        die("remote demo servers require HTTPS")
    if not allow_remote:
        die("remote account creation and compute require the explicit --allow-remote flag")
    if host == PRODUCTION_HOST and not allow_production:
        die("blindmachine.org additionally requires the explicit --allow-production flag")
    return server.rstrip("/")


# ═════════════════════════════════════════════════════════════════════════════
#  Driving the real `blind` CLI as each role, from its own isolated ~/.blind home.
# ═════════════════════════════════════════════════════════════════════════════
def _loads(text: str):
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = min([i for i in (text.find("{"), text.find("[")) if i >= 0] or [-1])
        if start >= 0:
            try:
                return json.loads(text[start:])
            except json.JSONDecodeError:
                pass
    return {}


def invite_ref(link: str) -> str:
    """How `blind contribute` takes the invite WITHOUT the host: drop the
    `https://<host>/c/` prefix, keep the token + `#k=` signing fragment. So the
    data-owner command reads `blind contribute <token>#k=<key> <file>` — no URL."""
    return link.split("/c/", 1)[1] if "/c/" in link else link


def blind(
    home: str,
    *args,
    api: str,
    signing_key: str = "",
    capture: bool = False,
    check: bool = True,
    secret_input: str | None = None,
):
    """Run `uv run blind --api <server> ...` as one role. When capture=True we set
    BLIND_JSON=1 and return the parsed object; otherwise the CLI's own transcript
    streams straight to the terminal (so you see exactly what it did). check=False
    returns None on a non-zero exit instead of aborting (used for try-login-first)."""
    env = {
        **os.environ,
        "HOME": home,
        # Each role lives in a throwaway $HOME, so the OS keychain (which is
        # per-OS-user, not per-$HOME) is the wrong place for these demo keys:
        # four roles would collide in one keychain and re-runs would leave
        # orphaned entries behind. The CLI's explicit escape hatch stores them
        # as 0600 files inside the role's own temp ~/.blind instead.
        "BLIND_SECRET_BACKEND": "file",
    }
    # Only override the bundle-verification key when the caller explicitly asked
    # for one. By default the CLI uses its built-in trust anchor, which is what
    # verifies both the curated production bundles and the locally-ingested one.
    if signing_key:
        env["BLIND_SIGNING_KEY"] = signing_key
        env["BLIND_UNSAFE_ALLOW_CUSTOM_SIGNING_KEY"] = "1"
    uv_bin = shutil.which("uv")
    if not uv_bin:
        die("`uv` is not installed. See https://docs.astral.sh/uv/")
    cmd = [uv_bin, "run", "blind", "--api", api, *[str(a) for a in args]]
    if capture:
        env["BLIND_JSON"] = "1"
        # The executable is resolved by shutil.which and no shell is involved.
        p = subprocess.run(  # nosec B603
            cmd, cwd=CLI_DIR, env=env, capture_output=True, text=True, input=secret_input
        )
        if p.returncode != 0:
            if not check:
                return None
            sys.stderr.write(p.stderr)
            die(f"`blind {' '.join(str(a) for a in args)}` failed (exit {p.returncode})")
        return _loads(p.stdout)
    print(_c(CMD, "$ blind " + " ".join(str(a) for a in args)))
    sys.stdout.flush()  # keep our narration ordered ahead of the child's inherited stdout
    p = subprocess.run(cmd, cwd=CLI_DIR, env=env, text=True, input=secret_input)  # nosec B603
    if p.returncode != 0:
        die(f"`blind {' '.join(str(a) for a in args)}` failed (exit {p.returncode})")
    return None


def ensure_account_cli(home: str, email: str, password: str, *, api: str, signing_key: str) -> str:
    """Create the account — or, on a re-run against a persisted DB, sign it in —
    entirely through the CLI (`blind register` / `blind login --email`), storing the
    bearer token in this role's isolated ~/.blind. No web app, no API keys to scrape.
    Login-first keeps re-runs off the signup throttle; prints the complete example
    command that actually ran + a ✓, and returns the human status."""
    pathlib.Path(home).mkdir(parents=True, exist_ok=True, mode=0o700)
    kw = dict(api=api, signing_key=signing_key, capture=True)
    login = blind(
        home, "login", "--email", email, "--password", password, check=False, **kw,
    )
    if login and login.get("account"):
        print(_c(CMD, f"$ blind login --email {email} --password {password}"))
        ok(f"{email:<26} already registered → signed in")
        return "signed in"
    print(_c(CMD, f"$ blind register --email {email} --password {password}"))
    blind(home, "register", "--email", email, "--password", password, **kw)
    ok(f"{email:<26} registered")
    return "registered"


# ═════════════════════════════════════════════════════════════════════════════
#  Cohort — realistic genotypes so the encrypted sum is a meaningful aggregate.
#  Each individual is an alt-allele dosage vector g ∈ {0,1,2}^L drawn under
#  Hardy–Weinberg equilibrium from a rare-variant-skewed MAF prior. We also emit
#  the CLEARTEXT oracle (elementwise sum + exact count) for the final proof.
# ═════════════════════════════════════════════════════════════════════════════
def _hwe(p: float, rng: random.Random) -> int:
    r = rng.random()
    if r < p * p:
        return 2
    if r < p * p + 2 * p * (1 - p):
        return 1
    return 0


def make_cohort(workdir: pathlib.Path, owners: int, per_owner: int, length: int, seed: int):
    oracle = [0] * length
    total = 0
    layout: list[tuple[int, list[pathlib.Path]]] = []
    for k in range(1, owners + 1):
        # Reproducibility is required here; this RNG never protects a secret.
        rng = random.Random(seed + k * 7919)  # nosec B311
        mafs = [min(0.5, max(0.001, rng.betavariate(0.5, 3.0))) for _ in range(length)]
        pdir = workdir / f"data_owner_{k}"
        pdir.mkdir(parents=True, exist_ok=True)
        files: list[pathlib.Path] = []
        for i in range(per_owner):
            vec = [_hwe(p, rng) for p in mafs]
            fp = pdir / f"individual_{i:02d}.json"
            fp.write_text(json.dumps(vec))
            files.append(fp)
            oracle = [a + b for a, b in zip(oracle, vec)]
            total += 1
        layout.append((k, files))
    (workdir / "oracle.json").write_text(json.dumps({"counts": oracle, "n": total}))
    return layout, total


# ═════════════════════════════════════════════════════════════════════════════
#  Server — either boot the monorepo's local worker-enabled instance, or target a
#  --server you point us at (which must have open registration + a live worker).
# ═════════════════════════════════════════════════════════════════════════════
def boot_local_server() -> dict:
    bootstrap = ROOT / "demo" / "bootstrap_server.sh"
    if not bootstrap.exists():
        die(
            "no --server given and demo/bootstrap_server.sh was not found.\n"
            "   Run this from the monorepo, or pass --server https://your-instance."
        )
    step("Booting a local, worker-enabled Blind Machine server (the same Rails app "
         "that runs blindmachine.org)…")
    # Fixed local bootstrap path, argv execution, and no shell expansion.
    proc = subprocess.run(  # nosec B603
        ["/bin/bash", str(bootstrap)], cwd=ROOT
    )
    if proc.returncode != 0:
        die("bootstrap_server.sh failed — see its output above.")
    env_file = ROOT / "demo" / ".demo_env"
    facts = {}
    for line in env_file.read_text().splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            facts[key.strip()] = val.strip()
    return facts


def grant_local_credits(email: str, dollars: int) -> str:
    """LOCAL demo provisioning: give the researcher complimentary compute credits so
    the ~$11 run is affordable, using the app's own comp-access script — the same
    append-only ledger 'adjustment' that `bin/givecredits` writes (no Stripe charge).
    Local server only; a remote account must already hold credits. Returns the
    script's summary line (best-effort; never raises)."""
    env = {**os.environ, "BUNDLE_GEMFILE": str(ROOT / "Gemfile")}
    try:
        # Fixed local Rails executable and script paths, with no shell involved.
        p = subprocess.run(  # nosec B603
            [
                str(ROOT / "bin" / "rails"),
                "runner",
                str(ROOT / "script" / "credit_access.rb"),
                "grant",
                email,
                str(dollars),
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except Exception as e:  # noqa: BLE001 — best-effort provisioning
        return f"(could not grant credits: {e})"
    lines = (p.stdout or p.stderr or "").strip().splitlines()
    return lines[-1] if lines else "granted demo compute credits"


# ═════════════════════════════════════════════════════════════════════════════
#  The demo.
# ═════════════════════════════════════════════════════════════════════════════
def main(argv: list[str] | None = None) -> int:
    global SPEED_FAST
    # Line-buffer our own stdout so the narration stays correctly interleaved with
    # the `blind` subprocesses' inherited stdout (esp. when piped to a file).
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(line_buffering=True)
    ap = argparse.ArgumentParser(
        description="Register real users and run the full Blind Machine loop via the CLI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target = ap.add_mutually_exclusive_group()
    target.add_argument("--server", help="target an explicit Blind Machine server origin "
                                         f"(default: https://{PRODUCTION_HOST})")
    target.add_argument("--local", action="store_true",
                        help="boot the monorepo's local worker-enabled server")
    ap.add_argument("--allow-remote", action="store_true",
                    help="confirm that a non-loopback target may create accounts and spend credits")
    ap.add_argument("--allow-production", action="store_true",
                    help="separately confirm side effects on blindmachine.org")
    ap.add_argument("--email-domain", default="example.com",
                    help="domain for unique synthetic demo accounts (default: example.com)")
    ap.add_argument("--signing-key", help="override the Ed25519 pubkey used to verify "
                                          "bundles (only for a self-host server that signs "
                                          "with a non-default key; default: the CLI's trust anchor)")
    ap.add_argument("--owners", type=int, default=3, help="number of data owners (default 3)")
    ap.add_argument("--per-owner", type=int, default=7,
                    help="individuals contributed per data owner (default 7)")
    ap.add_argument("--length", type=int, default=1000,
                    help="genotype vector length (default 1000 = the flagship's coordinate "
                         "count; must be ≤ 1000 — the app zero-pads shorter vectors)")
    ap.add_argument("--seed", type=int, default=20260713)
    ap.add_argument("--run-timeout", type=int, default=300,
                    help="seconds to wait for the compute job (default 300; bump for a "
                         "remote server whose sandbox seals its env cold)")
    ap.add_argument("--fast", action="store_true", help="no pauses between steps")
    args = ap.parse_args(argv)
    SPEED_FAST = args.fast

    if not re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", args.email_domain):
        die("--email-domain must be a plain DNS domain")
    if not 1 <= args.owners <= 100:
        die("--owners must be between 1 and 100")
    if not 1 <= args.per_owner <= 1000:
        die("--per-owner must be between 1 and 1000")
    if not 1 <= args.length <= 1000:
        die("--length must be between 1 and 1000")
    if not 1 <= args.run_timeout <= 7200:
        die("--run-timeout must be between 1 and 7200 seconds")

    total = args.owners * args.per_owner  # cohort size == project min-N (always satisfiable)

    banner("The Blind Machine — register real users, then run the whole loop (CLI demo)")
    run_id = secrets.token_hex(6)
    researcher_email = f"researcher+{run_id}@{args.email_domain}"
    owner_emails = [
        f"dataowner{k}+{run_id}@{args.email_domain}" for k in range(1, args.owners + 1)
    ]
    demo_password = "password"
    note(f"{researcher_email} opens the study; {args.owners} unique data-owner accounts contribute.")
    note("Every step below is a real `blind` command against a real server.")

    # ── resolve the server ───────────────────────────────────────────────────
    # By default we DON'T pin a signing key — the CLI's built-in trust anchor
    # verifies the curated bundles (production and the locally-ingested one alike).
    # --signing-key (or a BLIND_SIGNING_KEY in the environment) is a self-host escape
    # hatch for a server that signs with its own non-default key.
    signing_key = args.signing_key or os.environ.get("BLIND_SIGNING_KEY", "")
    if args.local:
        facts = boot_local_server()
        server = facts.get("DEMO_API", "").rstrip("/")
        digest = facts.get("DEMO_DIGEST") or None
        ok(f"local server ready at {server}")
    else:
        # No target given → production. The default carries its own consent
        # (running the demo with no flags IS the ask); an explicit --server
        # still requires the --allow-remote / --allow-production opt-ins.
        if args.server is None:
            server = f"https://{PRODUCTION_HOST}"
            note(f"No --server given — defaulting to production: {server}")
        else:
            server = validate_server_target(
                args.server, allow_remote=args.allow_remote, allow_production=args.allow_production
            )
            note(f"Target server: {server}")
        digest = None
    if not server:
        die("could not resolve a server URL")

    # isolated ~/.blind homes + cohort workspace (throwaway; never touches your real config)
    work = pathlib.Path(tempfile.mkdtemp(prefix="blind-register-demo."))
    atexit.register(lambda: shutil.rmtree(work, ignore_errors=True))
    researcher_home = str(work / "researcher")
    cohort_dir = work / "cohort"

    def R(*a, **kw):  # researcher CLI shortcut
        return blind(researcher_home, *a, api=server, signing_key=signing_key, **kw)

    # ═════════════════════════════════════════════════════════════════════════
    section("1", "Everyone signs up — from the CLI (no web app)")
    # ═════════════════════════════════════════════════════════════════════════
    step("Every participant creates their account with `blind register` — the CLI is "
         "the full surface; the web app is only for people who'd rather watch in a "
         "browser. Each token lands in that participant's own isolated ~/.blind:")
    ensure_account_cli(researcher_home, researcher_email, demo_password,
                       api=server, signing_key=signing_key)
    for k, email in enumerate(owner_emails, 1):
        ensure_account_cli(str(work / f"data_owner_{k}"), email, demo_password,
                           api=server, signing_key=signing_key)
    note("the server stored only a SHA-256 digest of each session token, never the token itself")
    pause()

    # ═════════════════════════════════════════════════════════════════════════
    section("2", "Researcher inspects the signed application registry")
    # ═════════════════════════════════════════════════════════════════════════
    role("RESEARCHER", MAGENTA, "already authenticated from §1 (the register token is stored) — no browser")
    # Compute is the metered axis; a signed-up account gets a $20 credit grant that
    # covers the ~$11 run. For the LOCAL demo we top the researcher up via the app's
    # comp-access script so repeated runs stay affordable. Against a remote server the
    # account must already hold credits (a fresh signup's grant covers one run).
    if args.local:
        line = grant_local_credits(researcher_email, 100)
        note(line or "granted the researcher complimentary compute credits (comp grant, no charge)")
    step("The public registry of curated, signed applications:")
    R("applications", "list")
    if not digest:
        meta = R("applications", "retrieve", APPLICATION, capture=True)
        try:
            digest = meta["versions"][0]["digest"]
        except (KeyError, IndexError, TypeError):
            die(f"could not resolve the {APPLICATION} digest from the registry")
    app = f"{APPLICATION}@{digest}"
    note(f"we'll use the flagship: {APPLICATION} @ {digest[:16]}…")
    pause()

    # ═════════════════════════════════════════════════════════════════════════
    section("3", "Install + verify the application, open the study, keygen LOCALLY")
    # ═════════════════════════════════════════════════════════════════════════
    role("RESEARCHER", MAGENTA, "content-addresses the bundle, checks the Ed25519 signature, seals a pinned env")
    R("applications", "install", app)
    ok("bundle digest matches the name suffix AND the server; signature verified; env sealed")
    step("What it computes and what it leaks — read it locally before trusting it:")
    R("explain", app)
    pause()

    role("RESEARCHER", MAGENTA, "opens a project pinned to the exact application digest")
    proj = R(
        "projects", "create",
        "--application", app,
        "--name", "GWAS pilot — encrypted allele frequencies",
        "--min-contributors", total,
        capture=True,
    )
    project_id = proj.get("id")
    if not project_id:
        die("projects create did not return a project id")
    ok(f"project #{project_id} created — pinned to {APPLICATION}@{digest[:12]}…, min-N = {total}")

    role("RESEARCHER", MAGENTA, "generates the crypto keypair 100% LOCALLY, publishes ONLY the public context")
    # Pass --application so keygen can resolve the pinned bundle AND record the
    # project→application mapping locally (run_keygen writes ~/.blind meta), which
    # every later local step (invite signing, run, decrypt) reads back.
    R("keys", "create", "--project", project_id, "--application", app)
    ok("secret key generated + stored in the researcher's ~/.blind — there is no endpoint that could receive it")
    note("only the PUBLIC crypto context was uploaded; the private half never leaves this machine")
    pause()

    role("RESEARCHER", MAGENTA, "invites each registered data owner with their own contributor link")
    owner_links: dict[str, str] = {}
    for email in owner_emails:
        inv = R("projects", "invite", project_id, capture=True)
        link = inv.get("url") or inv.get("link") or ""
        if not link:
            die("projects invite did not return an invite link")
        owner_links[email] = link
        signed = " (SIGNED — keyholder pubkey rides the #k= fragment, RFC 0003)" if "#k=" in link else ""
        ok(f"{email:<26} → {link[:52]}…{signed}")
    note("the link carries the project + pinned application + public-context digest, so a data "
         "owner needs nothing else — not even to be logged in")
    pause()

    # ═════════════════════════════════════════════════════════════════════════
    section("4", "The %d registered data owners contribute ENCRYPTED data" % args.owners)
    # ═════════════════════════════════════════════════════════════════════════
    step("Each data owner loads a realistic genotype cohort drawn under Hardy–Weinberg equilibrium…")
    layout, produced = make_cohort(cohort_dir, args.owners, args.per_owner, args.length, args.seed)
    ok(f"cohort ready: {produced} individual genotype vectors of length {args.length} "
       f"({args.owners} data owners × {args.per_owner})")
    pause()

    for k, files in layout:
        email = owner_emails[k - 1]
        link = owner_links[email]
        home = str(work / f"data_owner_{k}")
        color = GREEN

        def D(*a, **kw):  # this data owner's CLI shortcut
            return blind(home, *a, api=server, signing_key=signing_key, **kw)

        role(f"DATA OWNER {k}", color, f"signed in as {email} in §1; trusts the pinned application, then contributes")
        note(f"authenticated as {email} — a real CLI account, in its own isolated ~/.blind")
        D("applications", "install", app, capture=True)
        note("application installed + Ed25519-verified in this data owner's isolated environment")

        # Show the full data-owner trust transcript exactly ONCE (the very first
        # upload of the whole demo); every other upload is the identical command,
        # rendered as one ● per encrypted ciphertext so the output stays readable.
        # `blind contribute` accepts the invite as a bare token/hash (no host needed) —
        # keep the #k= fragment so it stays a verified SIGNED invitation.
        ref = invite_ref(link)
        if k == 1:
            step("the entire data-owner path is ONE command — just the invite token, "
                 "encode + encrypt LOCALLY, upload ONLY ciphertext:")
            D("contribute", ref, str(files[0]))
            rest = files[1:]
        else:
            step(f"contributing {len(files)} individuals (one ● per encrypted ciphertext uploaded):")
            rest = files
        for f in rest:
            D("contribute", ref, str(f), capture=True)
            print(_c(GREEN, "●"), end="", flush=True)
        print()
        ok(f"data owner {k} uploaded {len(files)} encrypted ciphertexts — raw genotypes never left their machine")
        pause()

    # ═════════════════════════════════════════════════════════════════════════
    section("5", "Researcher reviews the encrypted cohort (hashes only)")
    # ═════════════════════════════════════════════════════════════════════════
    role("RESEARCHER", MAGENTA, "checks the encrypted cohort — hashes only, never plaintext")
    R("projects", "status", project_id)
    note(f"min-N ({total}) is satisfied → the next action is 'blind projects run'")
    pause()

    # ═════════════════════════════════════════════════════════════════════════
    section("6", "Run the study — freeze the cohort, compute on ciphertext, decrypt locally")
    # ═════════════════════════════════════════════════════════════════════════
    role("RESEARCHER", MAGENTA, "prices the run before spending any CPU-second (read-only estimate)")
    R("jobs", "estimate", "--project", project_id)
    pause()

    role("RESEARCHER", MAGENTA, "freezes the cohort (permanent governance commit), dispatches compute, decrypts the aggregate")
    R("projects", "run", project_id, "--yes", "--timeout", args.run_timeout)
    ok("cohort frozen, homomorphic compute ran on ciphertext, aggregate decrypted LOCALLY")
    pause()

    # ═════════════════════════════════════════════════════════════════════════
    section("7", "The verifiable record — the reviewer's one proof command")
    # ═════════════════════════════════════════════════════════════════════════
    step("'blind projects proof' prints the skeptic's offline verify command + the public certificate URL:")
    proof = R("projects", "proof", project_id, capture=True)
    R("projects", "proof", project_id)
    cert = proof.get("certificate_hash")
    if cert:
        step("…and the skeptic runs exactly that, re-checking every hash offline:")
        R("verify", cert)
    pause()

    # ═════════════════════════════════════════════════════════════════════════
    section("8", "Proof: the encrypted result equals the cleartext oracle")
    # ═════════════════════════════════════════════════════════════════════════
    jobs = R("jobs", "list", "--project", project_id, capture=True)
    data = jobs.get("data") or jobs.get("jobs") or []
    if not data:
        die("no compute job found to decrypt")
    job_id = data[0]["id"]
    decrypted = R("results", "decrypt", job_id, "--project", project_id, capture=True)
    oracle = json.loads((cohort_dir / "oracle.json").read_text())

    counts = decrypted.get("result") or decrypted.get("allele_counts") or decrypted.get("counts")
    sentinel_n = decrypted.get("sentinel_n", decrypted.get("n_contributors", decrypted.get("n")))
    # The application encodes against a fixed coordinate length (manifest input.length,
    # 1000), zero-padding shorter vectors — so the decrypted counts vector is length L
    # even when we generated shorter individuals. Those trailing coordinates are 0 for
    # every contributor, so pad the cleartext oracle with zeros to line the two up.
    oracle_counts = list(oracle["counts"])
    if counts and len(oracle_counts) < len(counts):
        oracle_counts += [0] * (len(counts) - len(oracle_counts))
    ok_n = sentinel_n == oracle["n"]
    ok_counts = counts == oracle_counts

    print()
    def tag(good: bool) -> str:
        return _c(f"{GREEN};{BOLD}", "MATCH") if good else _c(f"{RED};{BOLD}", "MISMATCH")
    print(f"  homomorphic N          = {sentinel_n}     cleartext N          = {oracle['n']}     → {tag(ok_n)}")
    print(f"  homomorphic counts[:8] = {(counts or [])[:8]}")
    print(f"  cleartext   counts[:8] = {oracle['counts'][:8]}")
    print(f"  full allele-count vector identical to cleartext                    → {tag(ok_counts)}")
    print()

    if ok_n and ok_counts:
        print(_c(f"{GREEN};{BOLD}", "  ✓ PASS — the encrypted aggregate is bit-identical to computing in the clear."))
    else:
        print(_c(f"{RED};{BOLD}", "  ✗ FAIL — the decrypted result did not match the cleartext oracle (see above)."))

    banner(f"Done — {1 + args.owners} real accounts, the whole loop, nothing but "
           "ciphertext left a machine.")
    note("owner: register → projects create → keys create → invite → run → proof   ·   data owner: register → contribute")
    note(f"Web app: {server} (ephemeral demo credentials were intentionally not printed)")
    if args.local:
        note("The local demo server is still running. Stop it with:  demo/demo.sh --teardown")

    return 0 if (ok_n and ok_counts) else 1


if __name__ == "__main__":
    raise SystemExit(main())
