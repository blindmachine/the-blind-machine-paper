# blind — The Blind Machine CLI

> The machine can compute, but it cannot see.

Many scientific questions go unanswered because the data needed to answer them
cannot be pooled. The records exist — five hospitals each hold a slice of a
rare-disease cohort — and the answer is usually a plain summary over many
individuals: how often a variant occurs, how many people carry it, the shape of a
distribution. But the underlying data is sensitive and lives under separate
private custody, so it never becomes one dataset, and the summary never gets
computed.

`blind` is the command-line client for [The Blind Machine](https://blindmachine.org),
a platform that answers those questions without ever pooling the plaintext. Each
data owner encrypts their slice **on their own machine** with homomorphic
encryption; the server computes on **ciphertext only** and never learns the
plaintext; the researcher decrypts just the one approved aggregate locally. Every
application, cohort, and result is independently verifiable by hash, and every run
emits a certificate a skeptic can re-check offline.

![The Blind Machine at a glance — a trust boundary splits a LOCAL side (data owners encode and encrypt; the researcher holds the secret key and decrypts) from the SERVER side, which sees only the public key and ciphertext and computes without ever decrypting.](docs/overview.png)

**Every operation that touches plaintext or a secret key happens on your
machine, in this CLI.** The server never runs keygen, encoding, encryption, or
decryption. It sees ciphertext plus a public context, and nothing else. That is
the whole point of shipping the trust surface as an auditable, open-source
program you can read before you run — Kerckhoffs's principle as a product: no
guarantee rests on the secrecy or the honesty of the server.

The design, threat model, and ten reproducible experiments are written up in the
paper, archived on Zenodo with a citable DOI:
**[https://doi.org/10.5281/zenodo.21421426](https://doi.org/10.5281/zenodo.21421426)**.

- v1 demo: `allele_frequency_count` — sum encrypted variant-presence vectors
  across ≥20 contributors, decrypt only the per-variant count.
- **Crypto is a application dependency, not a platform backend.** A application is a
  self-contained, sandboxed uv-native Python bundle that brings its own crypto library via
  `env/pyproject.toml` + `env/uv.lock`. v1's curated applications standardize on
  [TenSEAL](https://github.com/OpenMined/TenSEAL) (Apache-2.0) — BFV with minimal
  additive-only params for exact-integer counts, depth-supporting BFV where a
  multiply is unavoidable, and CKKS only as a fast-follow approximate-real branch.
  `blind` never chooses crypto params by hand. The signed manifest, code, and
  `env/uv.lock` are the application trust boundary.

---

## The trust surface: what stays local vs. what is uploadable

`blind` classifies every artifact into one of five trust classes and prints the
class, loudly, at every boundary crossing. The classification is not cosmetic —
the local storage layout, the upload code paths, and the printed banners all key
off it.

| Artifact | Trust class | Produced by | Leaves your machine? |
|---|---|---|---|
| Raw data (your CSV / VCF / vectors) | **Raw** | you | **NEVER** — not even cached by default |
| Encoded data (`10_encode.py` output, still plaintext) | **Encoded** | local `blind data encode` | **NEVER** |
| Private Crypto Context / secret key | **Private** | local `blind keys create` | **NEVER** — OS keychain |
| Public Crypto Context (public key + params) | **Public** | local `blind keys create` | **shareable / uploaded once** |
| Encrypted data (ciphertext) | **Encrypted** | local `blind contributions create` (encode+encrypt), or the `blind data encrypt` primitive | **uploadable** |
| Encrypted result (ciphertext) | **Encrypted** | server compute worker | arrives **from** server |
| Decrypted result (the aggregate) | **Raw (local)** | local `blind results decrypt` | stays local unless you publish it |

The only things that ever go up: **Encrypted** ciphertext and the **Public**
Crypto Context. Keygen / encode / encrypt / decode / decrypt are 100% local.
The server is *structurally* unable to store a Private Crypto Context — it has no
column for it (see requirements: hard invariants).

---

## Why this is a separate, open-source project

1. **It is the security boundary, so it must be auditable.** If the program that
   holds your secret key and encrypts your data is closed or bundled inside a web
   app, "the server never sees plaintext" is a promise, not a property you can
   check. Open source + reproducible builds let you verify it.
2. **It runs on the data owner's machine, not ours.** A hospital contributor
   installs `blind`, drops ciphertext, and never needs a The Blind Machine account.
   That client can't be a hosted service.
3. **It has its own release cadence, deps, and tests.** The heavy native deps
   (a sandbox/container runtime plus whatever crypto a application pins in its
   uv lock — TenSEAL/SEAL for the curated set) have their own versioning;
   the Rails platform should not carry them.

The CLI is maintained in its own public repository,
[`blindmachine/blind`](https://github.com/blindmachine/blind), with its own
release workflow, tests, security policy, and MIT license. Nothing here imports from the Rails app;
it talks to the platform exclusively over the documented HTTP API
(see [`COMMANDS.md` → HTTP API contract](./COMMANDS.md#http-api-contract)).

---

## No platform backends — a application brings its own crypto

There is **no platform "backend" abstraction.** A application is a self-contained,
sandboxed Python bundle whose signed payload lives under `signed/`
(`manifest.yml`, author files, `env/pyproject.toml`, `env/uv.lock`,
`env/.python-version`). Root `README.md`, `SECURITY.md`, optional
`BENCHMARK.md`, and tests live beside `signed/` and are not part of the
digest/signature. Its crypto library is a *locked
application dependency*, not a capability `blind` provides. You never choose
crypto params by hand. The bundle declares what it needs, and a data-free,
digest-pinned container build runs `uv sync --frozen --no-dev`. The signed tree
is mounted read-only and reverified afterward.

v1's curated core applications all standardize on **TenSEAL BFV** (Apache-2.0);
TenSEAL CKKS is reserved for the fast-follow approximate-real application.
The `crypto:` field in `manifest.yml` is a **display hint** only — the real
crypto lives in the code + pinned deps:

| Crypto hint | Library | Class | Exactness | Used by (v1) |
|---|---|---|---|---|
| `tenseal-bfv` · additive | [TenSEAL](https://github.com/OpenMined/TenSEAL) | minimal-params add-only | exact integer (mod `t`) | allele/carrier/histogram/PGS counts |
| `tenseal-bfv` · depth-1 | TenSEAL | one homomorphic multiply | exact integer (mod `t`) | variance, covariance |
| `tenseal-ckks` (fast-follow) | TenSEAL | bounded-depth multiply | tolerance-bounded real | real-valued mean/variance |

Rule of thumb `blind` follows: **use the least-powerful configuration that
works.** Reach for a multiply only when two values *no single party can see in
plaintext* must be combined after encryption — the paper's thesis is the *cost of
multiplicative depth within one library* (additive-only BFV vs multiply-capable
BFV, with CKKS as a fast-follow branch). If a future application wants a different library (e.g. Paillier), that
license and dependency are isolated to that bundle through its uv-locked environment.

---

## Install

Requires **Python ≥ 3.11** and a **sandbox/container runtime** (`podman` or
`docker`) — `blind` runs every application stage inside a pinned, network-isolated
sealed environment with a read-only output directory and only its declared,
size-bounded output files writable, so a runtime must be present. Application crypto (TenSEAL for
the curated set) is **not** a `blind` dependency; each application's `env/uv.lock`
fetches its own pinned deps at install time.

Install the CLI as the `blind` command:

```bash
uv tool install blindmachine
```

`uv tool install` downloads the `blindmachine` package from PyPI, installs its
exactly pinned runtime closure into an isolated environment, and puts two
equivalent executables on your PATH: `blind` (the name every example in these
docs uses) and `blindmachine`.

To try it once without installing anything, run it in an ephemeral, cached
environment instead — note that `uvx` alone puts nothing on your PATH:

```bash
uvx blindmachine
```

Nothing separate is published to "uvx": publishing `blindmachine` on PyPI makes
both commands available.

Then check your toolchain:

```bash
blind doctor          # verifies python, the sandbox runtime, the uv env-sealer,
                      # keychain, Ed25519 verify, ~/.blind perms, sealed-env
                      # self-test, and API reachability
```

### Runtime dependencies

The runtime uses Typer/Rich for its command surface, HTTPX/Pydantic for the API
contract, keyring for OS-backed secrets, and cryptography for pinned Ed25519
verification. Every direct and transitive Python dependency is exact-pinned in
wheel metadata because `uv tool install`/`uvx` do not consume this repository's `uv.lock`; the
release gate proves that metadata and the lock export have the same runtime
closure. A container runtime (`podman`/`docker`) is required but external.
Application crypto is isolated per application and installed only from its
signed `env/uv.lock`. See the
[output design](https://github.com/blindmachine/blind/blob/main/UX.md).

---

## Quickstart

Two roles. The **researcher** runs the study; **data owners** contribute
ciphertext with no account via a 7-day link.

### Researcher

```bash
blind login                                              # REMOTE: get an API token (device/browser code)
blind applications install allele_frequency_count           # BOTH: fetch, verify sig + digest
blind projects create --application allele_frequency_count@<digest> --name "Rare disease cohort"
blind keys create --project <project-id>                 # LOCAL: keygen; secret → keychain, only the public half published
blind projects invite <project-id> --expires 7d --qr     # REMOTE: mint accountless bearer link (+QR) for contributors
# ... contributors contribute (below) ...
blind projects retrieve <project-id>                     # REMOTE: cohort size, min-N satisfied?
blind projects freeze <project-id>                       # REMOTE: commit cohort → prints cohort hash
blind jobs estimate --project <project-id>               # REMOTE: marked-up CPU-second cost, no dispatch
blind jobs create --project <project-id>                 # REMOTE: confirm the estimate, then dispatch
blind jobs watch <job-id>                                # REMOTE: stream stages
blind results decrypt <job-id>                           # REMOTE download + LOCAL decrypt → aggregate
blind certificates verify <cert-hash>                    # LOCAL: recompute + check all hashes offline
```

### Data owner (no account)

```bash
blind contributions create \
  --link https://blindmachine.org/c/AbC123... \
  --data ./my_vector.csv
# encode → encrypt happen LOCALLY; only ciphertext is uploaded.
# raw + encoded stay local; no secret key is generated here (uses the project's public context).
# one-off, nothing installed: `uvx blindmachine contributions create ...` works too.
```

Simulate feasibility before any real contributor exists (`simulate` is an alias
for `simulations create`). Installed applications are addressed by their pinned
`<name@digest>` (install prints the digest; `blind applications list` shows what
is installed), so install the curated bundle first, then simulate it:

```bash
blind applications install allele_frequency_count          # verifies signature + digest, prints <name@digest>
blind simulate allele_frequency_count@<digest> --synthetic --n 20,100,1000 --emit methods,table
```

---

## Local storage: `~/.blind`

`blind` keeps all local state under `~/.blind`. **Secret keys live in the OS
keychain** (macOS Keychain / GNOME Keyring / Windows Credential Manager); the
on-disk tree holds only a *reference* to the keychain entry. Raw data is never
cached. Every file below is either Public/Encrypted (safe to share) or is a
Private/Encoded/Raw local-only artifact, and the layout keeps the two physically
separate.

```
~/.blind/
├── config.yml                       # api base URL, active profile, output prefs (json/color)
├── auth/
│   └── <profile>.token              # API bearer token for the Rails platform  (chmod 600)
├── keys/
│   └── projects/
│       └── <project-id>/
│           ├── public.context       # Public Crypto Context — SHAREABLE, uploaded to server
│           ├── private.ref          # pointer to the OS-keychain entry (NOT the key itself)
│           ├── private.key          # explicit insecure file backend only (chmod 600)
│           └── meta.yml             # crypto hint, params, pinned application name@digest, env_lock
├── applications/
│   └── <name>@<sha256-digest>/      # content-addressed install; digest re-checked on every load
│       ├── signed/                  # digest/signature payload
│       │   ├── manifest.yml         # declarations + fixed coordinate definitions
│       │   ├── server.py            # SERVER compute(inputs, public_context)
│       │   ├── local_project_owner.py
│       │   ├── local_data_owner.py
│       │   ├── env/
│       │   │   ├── pyproject.toml
│       │   │   ├── uv.lock
│       │   │   └── .python-version
│       │   ├── .digest              # recomputed SHA-256, must equal <sha256-digest>
│       │   └── env_lock             # sha256 of uv.lock + python version + runner metadata
│       ├── README.md                # support docs; not signed
│       ├── SECURITY.md              # review notes; not signed
│       ├── BENCHMARK.md             # optional benchmark notes; not signed
│       ├── tests/                   # review/support fixtures; not signed
│       └── .blind-signature         # Ed25519 signature over signed/** digest
├── cache/
│   ├── encoded/  <sha>.enc-in       # Encoded Data — LOCAL ONLY (plaintext-derived), never uploaded
│   └── encrypted/<sha>.ct           # Encrypted Data — the ONLY input class that is uploadable
├── results/
│   └── <project-id>/<job-id>/
│       ├── result.ct                # Encrypted result (downloaded ciphertext)
│       ├── result.json              # Decrypted aggregate — LOCAL ONLY unless you publish
│       └── certificate.json         # Computation Certificate (application/cohort/data/result hashes)
├── simulations/
│   └── <sim-run-hash>/              # NON-authoritative SimulationRun: config.yml, equivalence.json,
│                                    #   benchmark.{csv,md,tex}, plots/, methods.md, threat_model.md,
│                                    #   provenance.json
└── logs/
    └── blind.log                    # command + hash audit trail (no plaintext, no secrets)
```

Raw data (`my_vector.csv`, a VCF, …) is **not** copied into `~/.blind`. It stays
wherever you point `--input`. `blind` reads it, encodes/encrypts, and forgets it.

---

## The loud trust statements `blind` prints

Every command that crosses a trust boundary prints a banner naming the trust
class of what it produced and whether it left the machine. Two examples:

```
$ blind data encrypt --project <project-id> --input ./my_vector.csv

  Raw        ./my_vector.csv                 LOCAL ONLY — never uploaded
  Encoded    cache/encoded/9f3a…e1.enc-in    LOCAL ONLY — never uploaded
  Encrypted  cache/encrypted/2c8b…7a.ct      UPLOADABLE — ciphertext only

  application        allele_frequency_count@sha256:4d1e…c0
  public context  sha256:7b22…9f   (matches project)   Public — shareable
  private key     kept in OS keychain               Private — never leaves this machine

  Nothing has been uploaded. Run `blind contributions create` to upload the Encrypted artifact.
```

```
$ blind projects freeze <project-id>

  Cohort frozen. No contributor can be added, removed, or re-run.
  cohort commitment  sha256:1a90…44   (= sha256 of sorted contribution hashes + project + application)
  contributors        23
  minimum contributors satisfied   ✔  (min 20)
```

Result and certificate commands print the same way:

```
$ blind results decrypt <job-id>

  application         allele_frequency_count@sha256:4d1e…c0     ✔ digest verified
  cohort           sha256:1a90…44                            ✔ matches frozen commitment
  result (cipher)  sha256:8f0c…2d                            ✔ matches server result digest
  result (plain)   results/<project>/<job>/result.json       Raw (local) — not uploaded
  sentinel N       23                                        ✔ (append-1 integrity check, not a MAC)
  minimum contributors satisfied   ✔
```

Hashes printed/verified across the CLI: **application digest**, **public-context
hash**, **cohort commitment**, **result ciphertext digest**, and the
**certificate** binding all of them. The design intent — Raw/Encoded/Private are
local-only; Encrypted/Public are the only uploadable classes — is stated at every
step so a data owner can *see* the boundary, not just trust it.

Honest scoping the CLI never overstates: the append-1 sentinel is an integrity
check, **not** a MAC; FHE hides contributor inputs from the server, **not**
zero-knowledge; cohort-freeze + min-N mitigate but do not fully solve K-vs-K+1
differencing.

---

## Command overview

Full Stripe-CLI-style resource/verb surface (CRUD verbs `create` · `retrieve` ·
`update` · `list` · `delete` plus resource actions), per-command flags,
LOCAL/REMOTE classification, `--json` output, and the HTTP API contract are in
the [command reference](https://github.com/blindmachine/blind/blob/main/COMMANDS.md). Groups:

- Top-level: `login` · `logout` · `config` · `doctor` · `version` ·
  `resources` · `get`/`post` (raw API)
- Resources: `applications` · `projects` · `keys` · `contributions` · `data` ·
  `jobs` · `results` · `certificates` · `simulations` (alias `simulate`) · `dev`

(The old `auth` group is now the top-level `login`/`logout`; the append-only
event log moved to `projects events`; encrypted-data upload is `contributions
create`.)

---

## Implementation stack

`blind` is a Python ≥ 3.11 package. Output is designed to be **beautiful and very
informative, inspired by the Rails command line** — aligned colored action
labels, `rails routes`-grade tables, trees, timed progress bars, and the loud
trust banners as panels. The full output design and the stack evaluation
(including a serious look at `google/python-fire`) live in the
[output design](https://github.com/blindmachine/blind/blob/main/UX.md).

Recommended stack: **typer** (typed dispatch; resource sub-apps map 1:1 to the
Stripe surface; clean global `--json`) · **rich** (all tables,
trees, panels, progress, themed help) · **httpx** (HTTP) · **pydantic** v2
(models + the `--json` schema the desktop GUI consumes) · **uv** (seals each
application's pinned env) · a **container runtime** (podman/docker) for the
network-isolated sandbox · **keyring** · **cryptography** (Ed25519) ·
**platformdirs** · **pyyaml**. We keep `python-fire`'s object model (resource
classes *are* the CLI) but use Typer to dispatch, for typed input validation and
a stable machine contract. `--json` is wired
at the framework level, so it is guaranteed on **every** command.

---

## Development

```bash
uv sync --locked                # install the reviewed runtime + dev closure
uv run pytest                   # unit + golden-vector tests
uv run ruff check src tests     # lint
uv run python scripts/check_runtime_lock.py
```

Key test suites: manifest/coordinate digest reproducibility, uv env-seal +
`env_lock` reproducibility, byte-exact artifact contract against the platform
fixtures, keychain round-trip, and the `dev compare` plaintext-vs-encrypted
equivalence harness (bit-exact for BFV integer results, tolerance-bounded for
CKKS reals).

## License

MIT. See [LICENSE](https://github.com/blindmachine/blind/blob/main/LICENSE).

## Source and security

- Source: [github.com/blindmachine/blind](https://github.com/blindmachine/blind)
- Command contract: [COMMANDS.md](https://github.com/blindmachine/blind/blob/main/COMMANDS.md)
- Vulnerability reporting and trust boundaries: [SECURITY.md](https://github.com/blindmachine/blind/blob/main/SECURITY.md)

PyPI releases are built from tags by GitHub Actions, published through PyPI
Trusted Publishing, and include attestations. The build job has no OIDC publish
permission; the isolated publish job only receives already-verified artifacts.
