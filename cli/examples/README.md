# `blind` CLI — examples

Runnable, narrated examples that drive the real `blind` CLI end to end. These are
**demos**, not part of the shipped command surface — read them to learn the flow,
run them to watch it happen.

## `register_and_run.py` — register real users, then run the whole loop

Signs up **four real accounts** against a running Blind Machine server and runs
the entire governed-computation loop through the CLI, printing what happens at
each step:

| Actor | What it does (all via the CLI) |
|-------|--------------------------------|
| `researcher+<random>@example.com` | Registers, installs + **Ed25519-verifies** the signed application, opens a project, generates the crypto keys **100% locally** (only the *public* context is published), and invites each data owner with their own contributor link. |
| `dataowner1+<random>@example.com` … | Each registers, then encodes + encrypts every individual **locally** and uploads **only ciphertext** through their invite link. |
| Researcher | Freezes the cohort, runs the **homomorphic compute job** on ciphertext, decrypts the aggregate locally, and prints the reviewer's one-command offline proof. |
| — | Proves the decrypted aggregate is **bit-identical** to computing the same sum in the clear. |

The example uses real signups and real users. Even though the data owners are
registered accounts here, they still
contribute through the **invite link**: The Blind Machine has no project-membership
upload path (an account may only upload to a project it *owns*), so the link is the
contributor door — exactly as designed.

### Run it

```bash
# Boot a throwaway local worker-enabled server instead (no production side effects):
python examples/register_and_run.py --local

# Remote side effects must be explicit:
python examples/register_and_run.py --server https://staging.example.com --allow-remote

# Production requires a second, separate confirmation:
python examples/register_and_run.py --server https://blindmachine.org \
  --allow-remote --allow-production
```

Every run generates unique account addresses and a random in-memory password. The
password is passed through mode-`0600` temporary files, removed immediately, and
never printed. Use `--local` when possible; remote runs create accounts and may spend
credits.

### Options

| Flag | Meaning |
|------|---------|
| `--server URL` | Target an explicit Blind Machine server origin. Mutually exclusive with `--local`. |
| `--local` | Boot a throwaway local worker-enabled server (via `demo/bootstrap_server.sh`) and run against it instead of `--server`. |
| `--allow-remote` | Confirm account creation and compute side effects on a non-loopback server. |
| `--allow-production` | Additional confirmation required specifically for `blindmachine.org`. |
| `--email-domain DOMAIN` | Domain for unique synthetic demo accounts. Default: `example.com`. |
| `--run-timeout S` | Seconds to wait for the compute job (default 300; bump for a remote sandbox that seals its env cold). |
| `--signing-key HEX` | Override the Ed25519 pubkey used to verify bundles — only for a self-host server that signs with a non-default key. Default: the CLI's built-in trust anchor (verifies the curated bundles). |
| `--owners N` | Number of data owners (default 3 → `dataowner1..N@example.com`). |
| `--per-owner M` | Individuals contributed per data owner (default 7 → 21 total, above the flagship's min-N of 20). |
| `--length L` | Genotype vector length (default 1000 = the flagship's coordinate count; must be ≤ 1000). |
| `--fast` | Skip the pauses between steps. |

### Requirements

- **Python 3.11+** (the demo itself is pure standard library — no pip installs).
- **[`uv`](https://docs.astral.sh/uv/)** — the CLI runs under `uv run blind`, and `uv`
  builds the application's sealed TenSEAL env.
- A remote target must have **open registration** and a **live compute worker**.
  **`--local`** instead needs the monorepo's
  `demo/bootstrap_server.sh`, which boots a worker-enabled Rails instance, seeds the
  registry, and ingests the flagship bundle (no Docker — process-runtime worker).

The first run installs TenSEAL into each participant's sealed env (cached afterward),
so it takes a few minutes. Every account's crypto lives in its own isolated,
throwaway `~/.blind` — your real CLI config is never touched.

### How it works (under the hood)

- **Everything is a real `blind` subprocess call** — one isolated `~/.blind` per
  role — so the demo shows genuine CLI commands, not a reimplementation.
- **Registration and login happen from the CLI**: this example deliberately gives
  every participant the password `password` and shows it explicitly in
  `blind register --email … --password password` (or `blind login --email …
  --password password` on a re-run),
  which hits `POST /api/v1/auth/{registration,token}` and stores the bearer token in
  that role's `~/.blind`. These are throwaway demo credentials, kept visible so
  every printed command is easy to copy and run. The CLI is the full surface — no
  web app, no API keys to mint or scrape. The web app is only there for people who
  want to *watch* the same study in a browser.
