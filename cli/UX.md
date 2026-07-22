# `blind` — Output Aesthetic & Python Stack

> The command line is the trust surface. It should be **beautiful and very
> informative** — you should be able to *see* the security boundary in the
> output, not merely trust it.
>
> North star: the Rails command line. Aligned, colored action labels
> (`create` / `identical` / `run`), `rails routes` tables, migrations that print
> what they did and how long it took, clear final status. `blind` translates that
> grammar to a cryptographic trust CLI. This file owns the **output design** and
> the **implementation stack**. It does not restate `COMMANDS.md` (what the
> commands mean) or `README.md` (the trust surface) — links only.

---

## Part A — The visual language

Everything `blind` prints is built from **five primitives**, each with a fixed
job and a fixed style. Nothing is ad-hoc: a command computes a typed result
model, and one renderer turns that model into these primitives (see Part D).

| Primitive | Rails analogue | Used for |
|---|---|---|
| **Aligned action line** | migration/generator output (`create`, `identical`) | one step of a pipeline: verb + object + detail + trust tag |
| **Table** | `rails routes` | any `list`, any benchmark sweep, `doctor` |
| **Tree** | — | hierarchy: project → contributions → jobs → result/certificate |
| **Panel** | the boxed banners | the loud trust statements + final summaries |
| **Progress + spinner** | migration timing | long ops: encrypt, upload, compute, sweeps — always with elapsed time |

### Two orthogonal color channels

The Rails insight is that color carries *meaning*, not decoration. `blind` runs
**two independent color channels** so a data owner can read safety and
trust-class at a glance:

**Channel 1 — the action verb = is this step safe, local, or dangerous?**
(right-justified in a fixed gutter, exactly like `create`/`identical` in Rails)

| Verb | Color | Meaning |
|---|---|---|
| `create` `encrypt` `upload` `decrypt` `install` `verify`✔ | **green** | created / encrypted / sanctioned / verified — a good step |
| `compute` `seal` | **magenta** | server-side or build-phase work (distinct accent) |
| `freeze` | **bold blue** | governance commit |
| `encode` `skip` | **yellow** | stays local / nothing to do — caution, not error |
| `identical` | **dim blue** | content-addressed artifact already present (Rails' `identical`) |
| `error` `verify`✗ | **bold red** | failure |
| `local` | **dim** | marker: this stayed on your machine |

**Channel 2 — the trailing trust tag = what class is the artifact, and did it
leave?** (the five trust classes from `README.md`)

| Tag | Color | Leaves the machine? |
|---|---|---|
| `Raw · LOCAL ONLY` | **red** | never |
| `Private · NEVER LEAVES` (secret key) | **red** | never |
| `Encoded · LOCAL ONLY` | **yellow** | never |
| `Encrypted · UPLOADABLE` / `· uploaded` | **green** | the only input class that goes up |
| `Public · SHAREABLE` | **blue** | published once |

**Atoms** (used everywhere): **hashes are always `cyan`**, always shown, always
verifiable — short form `sha256:2c8b…7a` inline, full form in `--json`. Metadata
is **dim**. `✔` is bold green, `✗` bold red, `~`/estimates yellow.

This is the whole semantic contract the user asked for — *green = created/
verified, yellow = local-only/caution, red = error/never-upload, cyan = hashes,
dim = metadata* — with `blue` added for the one shareable class (Public), kept
distinct from cyan so a hash never reads as a trust tag.

### The aligned action line (the core primitive)

Rails right-justifies a colored verb in a gutter, then the path. `blind` does the
same, then adds an optional trust tag on the right. One helper renders it so the
gutter width and colors can never drift:

```
   <verb, right-justified & colored>  <object>   <dim detail>        <trust tag>
```

Gutter width = the longest verb in the current block + 2, so a pipeline's verbs
form a clean right edge — the Rails look. Example block:

```
      create  project   proj_7Ka9F2                      Rare disease cohort
     encode  local     9f3a…e1     coordinates 7c04…    Encoded · LOCAL ONLY
     encrypt  encrypted  2c8b…7a    128 ciphertexts      Encrypted · UPLOADABLE
```

### One theme, one Console

All of this lives in a single `rich.Theme`, applied to a single `Console`
singleton. No command ever calls `print()` or hard-codes a color; they emit view
models and the renderer looks styles up by name (Part D). The theme *is* the
visual language:

```python
# blind/console.py
from rich.theme import Theme

BLIND_THEME = Theme({
    # Channel 1 — action verbs (step safety)
    "verb.create":  "bold green",   "verb.encrypt": "bold green",
    "verb.upload":  "bold green",   "verb.decrypt": "bold green",
    "verb.install": "bold green",   "verb.verify":  "bold green",
    "verb.compute": "bold magenta", "verb.seal":    "bold magenta",
    "verb.freeze":  "bold blue",    "verb.identical": "dim blue",
    "verb.encode":  "yellow",       "verb.skip":    "yellow",
    "verb.error":   "bold red",     "verb.local":   "dim",
    # Channel 2 — trust classes (artifact tags)
    "trust.raw":       "bold red",  "trust.private":   "bold red",
    "trust.encoded":   "yellow",    "trust.encrypted": "green",
    "trust.public":    "blue",
    # Atoms
    "hash": "cyan", "meta": "dim", "ok": "bold green",
    "warn": "yellow", "bad": "bold red", "est": "yellow",
    "panel.trust": "bold red",       # the loud "never leaves" banner border
    "panel.done":  "green",          # completion summaries
})
```

`--no-color` / `--color off` / a non-TTY / `NO_COLOR` all resolve to a
no-style Console (rich handles this natively); the *layout* (gutters, tables,
trees) survives without color, so piped output stays readable.

---

## Part B — Mockups

Fenced blocks below show layout; the intended styling is annotated beneath each
(rich renders the color — markdown can't). Hashes are truncated for the page;
`--json` always carries the full digest.

### 1. `blind projects create`

```
$ blind projects create \
    --application allele_frequency_count@sha256:4d1e…c0 \
    --name "Rare disease cohort" --min-contributors 20

      verify  application  allele_frequency_count@sha256:4d1e…c0   ✔ digest · signature ok
      create  project   proj_7Ka9F2                             Rare disease cohort

  ╭─ Project created ─────────────────────────────────────────────────╮
  │  project id        proj_7Ka9F2                                     │
  │  application          allele_frequency_count@sha256:4d1e…c0  (pinned) │
  │  min contributors  20                                              │
  │  state             active · cohort 0 · min-N not yet satisfied     │
  ╰───────────────────────────────────────────────────────────────────╯

  Next  blind keys create --project proj_7Ka9F2
```
*Styling:* `verify`/`create` green (right-justified gutter); `proj_7Ka9F2` and
the digest cyan; the `✔` bold green; panel border green (`panel.done`); the
`Next` hint dim with the command in default weight — Rails' "here's the obvious
next move" affordance.

### 2. `blind contributions create` — the data-owner flow (the star)

```
$ blind contributions create \
    --link https://blindmachine.org/c/AbC123 --data ./my_vector.csv

  ╭─ You are contributing encrypted data ─────────────────────────────────────╮
  │  Raw data and any secret key NEVER leave this machine.                  │
  │  Only Encrypted ciphertext is uploaded. No account is created.         │
  ╰─────────────────────────────────────────────────────────────────────────╯

      read  ./my_vector.csv          128 variants              Raw · LOCAL ONLY
    encode  local  9f3a…e1           coordinates 7c04…         Encoded · LOCAL ONLY
   encrypt  ⠹ encrypting ━━━━━━━━━━━━━━━━━━━━━━━━  100%  128/128  0:00:02   Encrypted
    append  sentinel +1              integrity, not a MAC      Encrypted
    upload  ⠹ POST …/contributions  ━━━━━━━━━━━━  100%  0:00:01  2c8b…7a   → server

  ╭─ Contributed ──────────────────────────────────────────────────────────╮
  │  ciphertext        sha256:2c8b…7a        Encrypted · uploaded           │
  │  public context    sha256:7b22…9f        ✔ matches project              │
  │  private key       —                     none generated on this path    │
  │  cohort size       21                    ✔ minimum contributors met (20)│
  ╰─────────────────────────────────────────────────────────────────────────╯

  Raw stayed at ./my_vector.csv · Encoded stayed in cache · nothing else left.
```
*Styling:* the opening panel is the **loud trust banner** — bold-red border
(`panel.trust`), the word `NEVER` bold red. `encode` yellow, `encrypt`/`upload`
green. The two progress bars are `rich.progress` with a spinner + bar + percent +
elapsed column; they render in place and collapse to a single completed line.
Trust tags right-aligned: `Raw`/red, `Encoded`/yellow, `Encrypted`/green. Cohort
line `✔` bold green when min-N is satisfied (yellow `✗ 19/20` when not). Closing
one-liner dim — the reassurance restated in plain words.

### 3. `blind jobs create` + `blind jobs watch`

```
$ blind jobs create --project proj_7Ka9F2

    estimate  compute  allele_frequency_count   ~ 42 CPU-seconds   ~ $0.11
   ╭─ Cost estimate ──────────────────────────────────────────╮
   │  cohort            sha256:1a90…44   (frozen)              │
   │  est. CPU-seconds  42               pinned VM  c-4 / 8 GB │
   │  est. cost         ~ $0.11          billed on completion  │
   ╰──────────────────────────────────────────────────────────╯
   Run this compute for ~ $0.11?  [y/N]: y

      create  job  job_Q3z8   dispatched → sandbox (network: none)
```
```
$ blind jobs watch job_Q3z8

     compute  job queued     2026-07-05T10:00:00Z
     compute  job running    2026-07-05T10:00:01Z

     ✔ verify_contexts     40 ms · 21 ciphertexts
     ✔ seal_env            3010 ms · env_lock sha256:5e7d…10 · cache hit
     ✔ compute             31000 ms · 21 ciphertexts
     ✔ store_result        sha256:8f0c…2d   90 ms
     ✔ completed           sha256:8f0c…2d

  ╭─ Job complete ───────────────────────────────────────────────────╮
  │  job              job_Q3z8            state  succeeded           │
  │  result (cipher)  sha256:8f0c…2d      Encrypted · from server    │
  │  cost             $0.11               42 CPU-seconds             │
  ╰───────────────────────────────────────────────────────────────────╯

  Next  blind results decrypt job_Q3z8
```
*Styling:* `estimate` magenta, the `~$0.11` yellow (`est`) — cost estimates are
always yellow, never green, so "this will bill you" is visually distinct from
"this succeeded". The confirm prompt is a `rich.Confirm`; `--yes` skips it.
`watch` polls `GET /jobs/:id/events` (every 2 s, `--interval`) and renders each
stage transition exactly once as it lands — a migration log accreting lines.
The fine worker stages (`verify_contexts` → `seal_env` → `compute` →
`store_result`) print a bold-green `✔` (or red `✗` with the `error` code) plus
their `elapsed_ms` and selected detail (`env_lock`, `cache`, ciphertext count,
`result_digest`). A `failed` terminal line prints its `failure_reason` and
exits nonzero. In `--json`, the final `job_watch` view carries the full
`stages` array so the desktop GUI drives a real progress surface. (A
`rich.live.Live` spinner region is a pretty-mode refinement on top of the same
polled stream.)

### 4. `blind simulate` — sweep + emitted artifacts

```
$ blind simulate allele_frequency_count@sha256:4d1e…c0 \
    --synthetic --n 20,100,1000 --sweep crypto=bfv-add,bfv-mul \
    --emit methods,table,plots

    simulate  allele_frequency_count@sha256:4d1e…c0   coordinates 7c04…   seed 42
    sweeping cohorts  ━━━━━━━━━━━━━━━━━━━━━━━━━━━  6/6 cells   0:00:44

   ┏━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┓
   ┃     N ┃ crypto   ┃ runtime  ┃ ct size ┃ memory  ┃ exact?  ┃
   ┡━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━┩
   │    20 │ bfv-add  │  0.4 s   │ 1.2 MB  │ 120 MB  │ ✔ exact │
   │    20 │ bfv-mul  │  1.1 s   │ 3.8 MB  │ 260 MB  │ ✔ exact │
   │   100 │ bfv-add  │  1.9 s   │ 1.2 MB  │ 140 MB  │ ✔ exact │
   │   100 │ bfv-mul  │  5.6 s   │ 3.8 MB  │ 300 MB  │ ✔ exact │
   │  1000 │ bfv-add  │ 18.7 s   │ 1.2 MB  │ 180 MB  │ ✔ exact │
   │  1000 │ bfv-mul  │ 54.0 s   │ 3.8 MB  │ 520 MB  │ ✔ exact │
   └───────┴──────────┴──────────┴─────────┴─────────┴─────────┘

      verify  cleartext oracle == encrypted run   ✔ exact  (max err 0)

     emitted  ~/.blind/simulations/simrun_b8e1…/
              ├── methods.md          Methods paragraph (paper-ready)
              ├── benchmark.csv        6 rows
              ├── benchmark.tex        LaTeX table
              ├── plots/runtime.svg
              └── provenance.json      seed 42 · coordinates 7c04… · digest 4d1e…

  ╭─ Simulation (non-authoritative) ─────────────────────────────────────────╮
  │  sim run     simrun_b8e1…    NOT a certificate · no cohort commitment     │
  │  synthetic   seeded (42)     no real data · nothing uploaded              │
  ╰───────────────────────────────────────────────────────────────────────────╯
```
*Styling:* the sweep is a `rich.progress` bar over the grid cells. The result is a
`rich.table.Table` in the `rails routes` idiom — bold header rule, right-aligned
numerics, `✔ exact` green per row (a `~ tol 1e-3` row would be yellow for CKKS).
The emitted-artifacts block is a `rich.tree.Tree` rooted at the sim-run dir. The
`crypto` column encodes the paper's thesis — additive-only `bfv-add` (minimal
params) vs multiplication-supporting `bfv-mul` — the cost of multiplicative depth
*within one library*. Closing panel is deliberately un-loud (blue/dim, not the
red trust border): a simulation is explicitly **not** a certificate.

`blind bench <name@digest> [--sweep …]` renders this exact matrix — it is a thin
alias for `simulations create --sweep …` (defaulting to
`--emit methods,table,plots,threat_model`). Each sweep writes ONE aggregated
`benchmark.{csv,md,tex}` (canonical row order N → L → crypto → security) plus a
`plots/` dir shipping each figure's SVG **beside its source CSV slice + the
`plot.py` script**. matplotlib is an optional extra: absent it, the CSV/MD/TeX
still land and only the SVGs are skipped (with a `plots/README.md` note). A cell
whose crypto params overflow / exhaust noise budget comes back
`infeasible-at-params` — a first-class publishable result, never a crash.

### 5. `blind doctor`

```
$ blind doctor

     blind doctor   v0.1.0

     ✔ python            3.11.9           ≥ 3.11 ok
     ✔ sandbox runtime   podman 5.1.0     rootless · --network none ok
     ✔ uv (env sealer)   0.5.7            --require-hashes ok
     ✔ OS keychain       macOS Keychain   read/write round-trip ok
     ✔ cryptography      43.0.1           Ed25519 verify ok
     ✔ ~/.blind          perms 700        auth/ 600 · keys not world-readable
     ✔ sealed env        allele…@4d1e     env_lock 5e7d…10 · self-test ok
     ✔ API               blindmachine.org reachable · 41 ms · authenticated

     ✔ all systems go
```
A failing check reads (red), Rails-style, with a fix hint:
```
     ✗ sandbox runtime   not found        needs podman or docker on PATH
       fix                brew install podman && podman machine init
```
*Styling:* a right-justified `✔`/`✗` column (green/red), then the check name,
then version, then a dim detail. This is `doctor` as a `rich.table.Table` with
hidden borders — dense, scannable. Failures add an indented `fix` row in yellow.
Note the **new** `sandbox runtime` and `sealed env` checks (see Part 2 of the
application-model reconciliation): `doctor` now proves the network-isolated runner
exists and that the most-recently installed application's sealed env imports its own
(application-supplied) crypto — `tenseal` is no longer a global CLI dependency.

### 6. A `list` as a table — `blind applications list` (`rails routes` grade)

```
$ blind applications list

   ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━┓
   ┃ application                       ┃ crypto     ┃ min-N ┃ latest digest  ┃
   ┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━┩
   │ allele_frequency_count         │ bfv-add    │  20   │ sha256:4d1e…c0 │
   │ carrier_count                  │ bfv-add    │  20   │ sha256:9a02…7f │
   │ cohort_histogram               │ bfv-add    │  20   │ sha256:3c55…12 │
   │ polygenic_score_aggregate      │ bfv-add    │  20   │ sha256:7e88…be │
   │ allele_frequency_with_variance │ bfv-mul    │  20   │ sha256:1b44…09 │
   │ genotype_phenotype_covariance  │ bfv-mul    │  20   │ sha256:6f21…dd │
   └────────────────────────────────┴────────────┴───────┴────────────────┘

   6 curated applications · registry blindmachine.org · digests verified on install
```
*Styling:* `rich.table.Table` with the box-heavy header rule; `crypto` is a
display hint (tenseal BFV, additive vs multiplicative); digests cyan; the footer
line dim. Every `list` command uses this same table renderer.

### 7. A tree — `blind projects retrieve <id> --tree`

The hierarchy the user asked to see (project → contributions → jobs →
result/certificate) renders as a `rich.tree.Tree`:

```
$ blind projects retrieve proj_7Ka9F2 --tree

   proj_7Ka9F2  Rare disease cohort   frozen · min-N ✔ (21/20)
   ├── application      allele_frequency_count@sha256:4d1e…c0   ✔ pinned
   ├── public ctx    sha256:7b22…9f                          Public · published
   ├── cohort        sha256:1a90…44   21 contributions       frozen
   │   ├── contr_a1  sha256:2c8b…7a                          Encrypted
   │   ├── contr_a2  sha256:5d09…3e                          Encrypted
   │   └── … 19 more
   └── jobs
       └── job_Q3z8  succeeded
           ├── result       sha256:8f0c…2d   Encrypted · decrypted locally
           └── certificate  cert_11ff…      ✔ binds application·cohort·result
```
*Styling:* branch labels default weight, hashes cyan, trust tags in their class
color, state markers green/yellow. The tree is the project's event-sourced state
made visible in one screen.

### The `--json` twin (the machine contract)

Every command above has a byte-stable JSON form. The desktop GUI shells out and
parses this — it is a hard contract, not a debug aid:

```
$ blind contributions create --link … --data ./my_vector.csv --json
{
  "object": "contribution",
  "id": "contr_a1b2c3",
  "ciphertext_sha256": "2c8b…7a",
  "public_context_sha256": "7b22…9f",
  "public_context_matches_project": true,
  "cohort_size": 21,
  "min_contributors": 20,
  "min_contributors_satisfied": true,
  "uploaded": true,
  "local_artifacts": { "raw": "./my_vector.csv", "encoded_cached": true },
  "trust": { "raw": "local_only", "encoded": "local_only", "encrypted": "uploaded" },
  "timing_ms": { "encode": 210, "encrypt": 2040, "upload": 980 },
  "warnings": []
}
```
Streaming commands (`jobs watch`, `simulate`, long `encrypt`) emit **NDJSON** —
one JSON object per line — so progress is consumable incrementally:
```
$ blind get jobs/job_Q3z8/events   # the server's stage stream (what watch polls)
{"stage":"queued","at":"2026-07-05T10:00:00Z"}
{"stage":"running","at":"2026-07-05T10:00:01Z"}
{"stage":"verify_contexts","at":"…","status":"ok","elapsed_ms":40,"ciphertext_count":21}
{"stage":"seal_env","at":"…","status":"ok","elapsed_ms":3010,"env_lock":"sha256:5e7d…","cache":"hit"}
{"stage":"compute","at":"…","status":"ok","elapsed_ms":31000,"ciphertext_count":21,"exit_status":0}
{"stage":"store_result","at":"…","status":"ok","elapsed_ms":90,"result_digest":"sha256:8f0c…"}
{"stage":"completed","at":"…","result_digest":"sha256:8f0c…"}
```
Every line keeps `stage` + `at`; detail keys are additive and consumers must
tolerate unknown keys (COMMANDS.md "The job stage stream"). `jobs watch --json`
emits the final aggregated `job_watch` object over this same vocabulary.

---

## Part C — The Python stack

### The dispatch decision: `google/python-fire` vs `typer`

The user named **python-fire**, and its central idea is genuinely the right one
for a Stripe-shaped surface: **your resource classes *are* your CLI.** A class
per resource with verb-named methods maps, with zero glue, onto
`blind <resource> <verb>`:

```python
# The fire model — beautiful, exactly our resource/verb grammar
class Projects:
    def create(self, application, name, min_contributors=20): ...
    def list(self, state=None): ...
    def retrieve(self, id): ...
    def freeze(self, id, yes=False): ...

class Blind:
    def __init__(self):
        self.projects = Projects()
        self.applications = Applications()
        self.contributions = Contributions()
        # …

fire.Fire(Blind)   # → blind projects create --application … --name … --min-contributors 20
```

That is the cleanest possible expression of `COMMANDS.md`'s surface — nesting,
verbs, and `--field value` flags fall out of Python's object model for free. We
**keep this model** (Part D organizes the code exactly this way). But we do
**not** let fire *parse*, for four reasons that matter specifically for a
security CLI whose output is also a machine contract:

1. **Type coercion is heuristic.** Fire infers types from argument strings:
   `--name 2024` becomes the int `2024`, `--data 001` can become `1`, a bare
   value may parse as a bool or a dict. For a tool that passes **file paths,
   project IDs, and hex digests**, silent coercion is a poka-yoke violation — the
   boundary must reject malformed input loudly, not guess.
2. **The machine contract needs stable flags.** The desktop GUI depends on an
   exact, documented flag set and `--json` shape per command. Fire derives flags
   from signatures at runtime and mixes in its own control tokens (`--`, `-i`
   REPL, `--trace`); that surface is too fluid to be a contract.
3. **We override help anyway.** Fire's main free benefit is its auto-generated
   help/inspection — which we'd replace wholesale with a rich-themed help, losing
   the payoff.
4. **Maintenance cadence.** Fire is effectively feature-complete and low-activity
   (Google-owned). By the "judge a dependency by its present maintainer" rule, a
   foundational parser in the trust surface should sit on an actively maintained
   base.

**Recommendation: `Typer` for dispatch, keeping fire's resource-class model.**
Typer gives typed, validated, poka-yoke flags; sub-apps map 1:1 to the resource
groups; the global `--json/--quiet/--color/--api/--profile` live in one root
callback; and it's actively maintained with first-class rich integration. The
resource classes still exist — a thin registrar reflects their verb methods into
Typer commands, so we get **fire's ergonomics with Typer's control**:

```python
# The typer wiring — same classes, typed dispatch, one global callback
projects = typer.Typer(help="Studies + governance")
app.add_typer(projects, name="projects")

@projects.command("create")
def _create(
    ctx: typer.Context,
    application: str = typer.Option(..., help="name@digest (required)"),
    name: str = typer.Option(...),
    min_contributors: int = typer.Option(20, "--min-contributors", min=1),
):
    view = Projects(ctx.obj).create(application, name, min_contributors)
    emit(ctx, view)          # pretty or --json, decided centrally
```

> If the ~40-command surface makes the per-command boilerplate itch, a ~30-line
> `registrar.py` can introspect each resource class's public methods + type hints
> and register them as Typer commands automatically — fire's zero-boilerplate feel
> without fire's parser. Ship the explicit form first (boring, debuggable); reach
> for the registrar once the third near-identical command block proves the
> abstraction (three callers, not one anticipated).

### `rich` — the renderer (non-negotiable)

`rich` is the reason the output can be Rails-grade. One `Console` + one `Theme`
drives **all five primitives**:

- `rich.table.Table` → every `list` and the benchmark sweep (`rails routes` look).
- `rich.tree.Tree` → the project → contributions → jobs → result hierarchy.
- `rich.progress.Progress` (spinner + bar + `TimeElapsedColumn`) → encrypt,
  upload, compute, sweeps — timing for free.
- `rich.panel.Panel` → the loud trust banners and completion summaries.
- `rich.text.Text` with theme styles → the aligned colored action lines.
- `console.print_json()` / `Live` → the `--json` and streaming twins.

It also handles the un-fun parts natively: TTY detection, `NO_COLOR`, width, and
piping — so `--no-color` and non-interactive output are one Console flag, not a
special code path.

### The recommended stack (one line each)

| Package | Role | Why (one line) |
|---|---|---|
| **typer** | CLI dispatch | Typed, poka-yoke flags; resource sub-apps map 1:1 to the Stripe surface; clean global `--json`; actively maintained. |
| **rich** | Rendering | One themed Console drives every table, tree, panel, progress bar, and the aligned colored action labels. |
| **httpx** | HTTP | Modern sync client with timeouts, HTTP/2, pooling; talks to `/api/v1`; present maintainer (Encode). |
| **pydantic v2** | Models / validation | Validates `manifest.yml` + API responses **and** defines the typed `--json` output schema the GUI consumes. |
| **uv** | Env sealer + packaging | Builds the application's `env/uv.lock` environment → `env_lock`; also the project's own lock/dev tool. Astral, fast, active. |
| **container runtime (podman/docker) via `subprocess`** | Sandbox | Runs every build and data-bearing stage in a digest-pinned runner; run phases have no network, a read-only root, no capabilities, and bounded resources. |
| **keyring** | Secrets | Stores private key material in the OS keychain (macOS Keychain / GNOME Keyring / Windows Credential Manager) and fails closed if it is unavailable. |
| **cryptography** (PyCA) | Signature verify | Verifies The Blind Machine's Ed25519 signature over each application bundle. |
| **platformdirs** | Paths | OS-correct fallback locations for cache/logs around the spec-fixed `~/.blind`. |
| **PyYAML** | Config / manifests | Reads `manifest.yml` and `config.yml` (swap to `ruamel.yaml` only if `config --set` must preserve comments). |
| **pytest · pytest-cov · ruff · mypy** | Dev | Golden-vector + keychain + equivalence tests; lint; types. |

### Evaluated and deliberately not adopted

- **google/python-fire** — keep its *model* (resource classes as the CLI), reject
  its *parser* (heuristic coercion breaks the machine contract; fluid flag surface;
  low cadence). Covered above.
- **textual** (a full TUI, same authors as rich) — **defer.** `rich.live.Live`
  covers `jobs watch` and `doctor` without a full-screen app; a Textual dashboard
  is a great post-v1 feature, not a v1 dependency. (Operational density over
  decorative polish; YAGNI until the third caller.)
- **questionary / prompt_toolkit** — **not needed in v1.** The only interactions
  are confirm-a-paid-run and device-code login; `rich.Confirm`/`rich.Prompt`
  handle both. Add questionary only if a real selection menu appears (e.g.
  choosing among application versions).
- **click directly** — used transitively *under* Typer; no reason to drop to it.

---

## Part D — Wiring

### 1. The code maps to the resource model (fire's insight, Typer's dispatch)

```
blind/
├── __main__.py            # entrypoint → build_app().  `blind` console-script target
├── cli/
│   ├── app.py             # root Typer + global callback → OutputCtx in ctx.obj
│   ├── registrar.py       # (optional) reflect resource-class verbs → Typer commands
│   └── groups/            # ONE module per resource — the fire model
│       ├── projects.py    #   class Projects: create / list / retrieve / freeze / …
│       ├── applications.py   #   class Applications: list / retrieve / install / verify / …
│       ├── contributions.py
│       ├── keys.py  jobs.py  results.py  certificates.py
│       ├── simulations.py  data.py  dev.py
├── views/
│   ├── models.py          # pydantic result models: ProjectCreated, ContributionCreated,
│   │                      #   JobStatus, SimRun, DoctorReport, ApplicationList, …
│   ├── pretty.py          # rich renderers dispatched by model type
│   └── ndjson.py          # streaming-event emitters
├── console.py             # the ONE Console + BLIND_THEME + line()/panel()/step()
├── api.py                 # httpx client, bearer/invite auth, retries, error mapping
├── store.py               # ~/.blind layout, keyring, config.yml
├── applications/
│   ├── bundle.py          # load, recompute digest, verify Ed25519 signature
│   ├── sandbox.py         # seal env (uv/container) + `--network none` runner  (NEW)
│   └── env_lock.py        # hash the resolved lock → env_lock
└── errors.py              # typed errors → exit codes + JSON error envelope
```

Each resource module is a plain class whose methods **return a view model** and
never print. This keeps the Model (`api.py` + `store.py`), the View (`views/`),
and the Controller (the resource classes) cleanly split — vanilla, testable, no
service-object sprawl.

### 2. One Console, one Theme, centralized

`console.py` owns the single `Console(theme=BLIND_THEME)` and the three helpers
every command uses instead of `print`:

```python
console = Console(theme=BLIND_THEME)

def line(verb, obj, detail="", trust=None):
    "Render one aligned action line (Channel 1 verb + Channel 2 trust tag)."

def panel(title, rows, kind="done"):        # kind in {"trust","done","info"}
    "Render a boxed summary; kind picks the border style."

@contextmanager
def step(verb, total=None):
    "A timed unit of work: spinner+bar in pretty mode; silent+timed otherwise."
```

No color literals anywhere else. Changing the palette = editing `BLIND_THEME`.

### 3. Global `--json` / `--quiet` / `--no-color`: one switch, two renderers

The root Typer callback parses the global flags once and stashes an `OutputCtx`
in `ctx.obj`. Every command ends the same way — build a view model, call
`emit(ctx, view)` — and `emit` is the *single* place pretty-vs-machine is decided:

```python
@app.callback()
def main(ctx, json: bool = False, quiet: bool = False,
         color: ColorMode = ColorMode.auto, api: str = None, profile: str = "default"):
    console.no_color = (color == ColorMode.off) or (color == ColorMode.auto and not console.is_terminal)
    ctx.obj = OutputCtx(json=json, quiet=quiet, api=api, profile=profile)

def emit(ctx, view: BaseModel) -> None:
    if ctx.obj.json:
        console.print_json(view.model_dump_json())     # machine: full digests, stable schema
    elif ctx.obj.quiet:
        console.print(view.id_line())                  # just the id/hash, for scripts
    else:
        render_pretty(view, console)                   # rich: tables/trees/panels/labels
    raise SystemExit(view.exit_code)                    # 0, or a typed non-zero
```

- `--json` → the machine renderer (`print_json`), guaranteed on **every** command
  because it is wired at the framework level, not per-command. The GUI never gets
  a command with no JSON.
- `--quiet` → suppress banners/pipelines, print only the id/hash line (still
  greppable).
- `--no-color` / non-TTY / `NO_COLOR` → the Console drops styles; layout survives.

Errors take the same path: `errors.py` maps each typed error to an exit code
(0 ok · 2 usage · 3 auth · 4 network · 5 precondition e.g. cohort-not-frozen · 6
verify-mismatch) and, under `--json`, to a `{"object":"error","code":…,"message":…}`
envelope — so the GUI branches on codes, not on scraped text.

### 4. Progress + timing for long ops

`step()` is the one place elapsed time is captured, and it behaves differently by
render mode without the command knowing:

```python
with step("encrypt", total=n) as s:
    for ct in encrypt_all(...):
        s.advance(1)                      # pretty: moves the bar; json: emits an NDJSON progress line
    s.set_hash(ct_hash)
# s.elapsed_ms is folded into view.timing_ms — always recorded, shown only in pretty/quiet-off
```

- **Pretty mode:** a `rich.progress.Progress` with a spinner, bar, count, and
  `TimeElapsedColumn`; `jobs watch`/`doctor` wrap several `step`s in a
  `rich.live.Live` so stages accrete like a migration log and each flips to
  `✔ … 0:00:36` on completion.
- **JSON mode:** each `advance`/stage transition prints one NDJSON event; the
  final view carries `timing_ms` per stage. No spinner bytes ever contaminate the
  machine stream (progress goes to stderr in pretty mode; stdout stays clean for
  `--json`).

The result: timing is **always** measured (it lands in `timing_ms` in the JSON
and in the benchmark artifacts), and *rendered* only when a human is watching —
one code path, two audiences.

---

## Source of truth

- Command semantics + HTTP contract: [`COMMANDS.md`](./COMMANDS.md).
- Trust surface + `~/.blind` layout: [`README.md`](./README.md).
- Application bundle + two-phase sandbox model: [`README.md`](./README.md).

This file owns *how the CLI looks and what it's built from*; it does not restate
what the commands mean. When they disagree, the docs above win.
