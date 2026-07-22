"""The ONE Console + BLIND_THEME + the primitive renderers (UX.md Part A/D).

No other module hard-codes a color or calls print(); they emit through `line`,
`panel`, `table`, `tree`, and `step`. Changing the palette = editing BLIND_THEME.
"""

from __future__ import annotations

import os
import time
from contextlib import contextmanager

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich.tree import Tree

BLIND_THEME = Theme(
    {
        # Channel 1 — action verbs (step safety)
        "verb.create": "bold green",
        "verb.encrypt": "bold green",
        "verb.upload": "bold green",
        "verb.decrypt": "bold green",
        "verb.install": "bold green",
        "verb.verify": "bold green",
        "verb.read": "green",
        "verb.compute": "bold magenta",
        "verb.seal": "bold magenta",
        "verb.simulate": "bold magenta",
        "verb.estimate": "magenta",
        "verb.freeze": "bold blue",
        "verb.identical": "dim blue",
        "verb.encode": "yellow",
        "verb.skip": "yellow",
        "verb.append": "yellow",
        "verb.emitted": "green",
        "verb.error": "bold red",
        "verb.local": "dim",
        # Channel 2 — trust classes (artifact tags). LOCAL-ONLY = caution (yellow/
        # amber "hold"), NOT danger — red is reserved for a real ✗ mismatch/error.
        "trust.raw": "yellow",
        "trust.private": "yellow",
        "trust.encoded": "yellow",
        "trust.encrypted": "green",
        "trust.public": "blue",
        # Atoms
        "hash": "cyan",
        "meta": "dim",
        "ok": "bold green",
        "warn": "yellow",
        "bad": "bold red",
        "est": "yellow",
        "panel.trust": "yellow",
        "panel.done": "green",
        "panel.info": "blue",
    }
)

_TRUST_TAGS = {
    "raw": ("Raw · LOCAL ONLY", "trust.raw"),
    "private": ("Private · NEVER LEAVES", "trust.private"),
    "encoded": ("Encoded · LOCAL ONLY", "trust.encoded"),
    "encrypted": ("Encrypted · UPLOADABLE", "trust.encrypted"),
    "encrypted_uploaded": ("Encrypted · uploaded", "trust.encrypted"),
    "public": ("Public · SHAREABLE", "trust.public"),
}


def _make_console(*, stderr: bool = False) -> Console:
    no_color = bool(os.environ.get("NO_COLOR"))
    return Console(
        theme=BLIND_THEME, no_color=no_color, highlight=False, soft_wrap=False, stderr=stderr
    )


console = _make_console()
# Notices/warnings go here so they never pollute stdout — `--json` consumers pipe
# stdout to a parser, and a diagnostic line on stdout would corrupt it.
err_console = _make_console(stderr=True)


_LATTICE_POSITIONS = (0, 1, 2, 5, 8, 7, 6, 3)


def revolving_ascii_art(*, cycles: int = 10, delay: float = 0.04) -> None:
    """Render the startup lattice for a bare `blind` invocation."""
    if console.is_terminal:
        with Live(
            _lattice_frame(0),
            console=console,
            refresh_per_second=24,
            transient=True,
        ) as live:
            for index in range(cycles):
                live.update(_lattice_frame(index))
                time.sleep(delay)

    console.print(_lattice_frame(None))
    console.print("")


def _lattice_frame(active_index: int | None) -> Text:
    cells = ["#"] * 9
    cells[4] = "B"
    if active_index is not None:
        cells = ["."] * 9
        cells[4] = "B"
        cells[_LATTICE_POSITIONS[active_index % len(_LATTICE_POSITIONS)]] = "*"

    art = (
        f"        [{cells[0]}]---[{cells[1]}]---[{cells[2]}]\n"
        "         | \\   |   / |\n"
        f"        [{cells[3]}]---[{cells[4]}]---[{cells[5]}]   blind\n"
        "         | /   |   \\ |\n"
        f"        [{cells[6]}]---[{cells[7]}]---[{cells[8]}]\n"
        "      governed computation on encrypted data"
    )
    return Text(art, style="panel.info")


def notice(verb: str, obj: str = "", detail: str = "") -> None:
    """A single aligned diagnostic line on STDERR (server notices, soft warnings).
    Kept off stdout so machine-readable (`--json`) output stays clean."""
    style = f"verb.{verb}" if f"verb.{verb}" in BLIND_THEME.styles else "verb.local"
    text = Text()
    text.append(f"{verb:>{_VERB_GUTTER}}", style=style)
    text.append("  ")
    if obj:
        text.append(str(obj))
    if detail:
        text.append("   ")
        text.append(str(detail), style="meta")
    err_console.print(text)


def set_color_mode(mode: str) -> None:
    """mode in {'auto','on','off'} — resolve to a no-color Console when appropriate."""
    if mode == "off":
        console.no_color = True
    elif mode == "on":
        console.no_color = False
    else:  # auto
        console.no_color = bool(os.environ.get("NO_COLOR")) or not console.is_terminal


# ---------------------------------------------------------------------------
# Primitive 1 — the aligned action line
# ---------------------------------------------------------------------------

_VERB_GUTTER = 10  # right-justify verbs in a fixed gutter (Rails look)


def line(verb: str, obj: str = "", detail: str = "", trust: str | None = None) -> None:
    """One aligned action line: colored verb + object + dim detail + trust tag."""
    style = f"verb.{verb}" if f"verb.{verb}" in BLIND_THEME.styles else "verb.local"
    text = Text()
    text.append(f"{verb:>{_VERB_GUTTER}}", style=style)
    text.append("  ")
    # Callers routinely pass ints (ids, counts) as obj/detail — coerce so a raw
    # int can never crash the renderer (rich's Text.append is str-only).
    if obj:
        text.append(str(obj))
    if detail:
        text.append("   ")
        text.append(str(detail), style="meta")
    if trust:
        label, tstyle = _TRUST_TAGS.get(trust, (trust, "meta"))
        text.append("   ")
        text.append(label, style=tstyle)
    console.print(text)


def status_line(ok: bool, name: str, value: str = "", detail: str = "") -> None:
    """A right-marked ✔/✗ status row (doctor / verify checks)."""
    mark = Text("✔", style="ok") if ok else Text("✗", style="bad")
    text = Text()
    text.append("     ")
    text.append(mark)
    text.append("  ")
    text.append(f"{name:<18}")
    if value:
        text.append("  ")
        text.append(str(value))
    if detail:
        text.append("   ")
        text.append(str(detail), style="meta")
    console.print(text)


# ---------------------------------------------------------------------------
# Primitive 4 — panels (the loud trust banners + summaries)
# ---------------------------------------------------------------------------


def panel(title: str, rows: list[tuple[str, str]] | str, kind: str = "done") -> None:
    """Boxed summary. kind in {'trust','done','info'} picks the border style."""
    border = {"trust": "panel.trust", "done": "panel.done", "info": "panel.info"}.get(
        kind, "panel.done"
    )
    if isinstance(rows, str):
        body: Text | Table = Text(rows)
    else:
        body = Table.grid(padding=(0, 2))
        body.add_column(style="meta")
        body.add_column()
        for k, v in rows:
            body.add_row(str(k), str(v))
    console.print(Panel(body, title=title, title_align="left", border_style=border))


def trust_banner(title: str, message: str) -> None:
    """The yellow (caution/hold) 'never leaves this machine' banner."""
    console.print(
        Panel(Text(message, style="panel.trust"), title=title, title_align="left",
              border_style="panel.trust")
    )


# ---------------------------------------------------------------------------
# Primitive 2 — tables (rails routes grade)
# ---------------------------------------------------------------------------


def table(columns: list[str], rows: list[list[str]], footer: str | None = None) -> None:
    t = Table(show_header=True, header_style="bold")
    for c in columns:
        t.add_column(c)
    for r in rows:
        t.add_row(*[str(x) for x in r])
    console.print(t)
    if footer:
        console.print(Text(footer, style="meta"))


# ---------------------------------------------------------------------------
# Primitive 3 — tree
# ---------------------------------------------------------------------------


def render_tree(root_label: str, children: list) -> None:
    tree = Tree(root_label)
    _add_tree_children(tree, children)
    console.print(tree)


def _add_tree_children(node, children) -> None:
    for child in children:
        if isinstance(child, tuple):
            label, sub = child
            branch = node.add(label)
            _add_tree_children(branch, sub)
        else:
            node.add(str(child))


# ---------------------------------------------------------------------------
# Primitive 5 — timed step (spinner+bar in pretty; silent+timed otherwise)
# ---------------------------------------------------------------------------


class _Step:
    def __init__(self, verb: str):
        self.verb = verb
        self.start = time.monotonic()
        self.hash: str | None = None
        self.done = 0
        self.total = 0

    def advance(self, n: int = 1) -> None:
        self.done += n

    def set_hash(self, h: str) -> None:
        self.hash = h

    @property
    def elapsed_ms(self) -> int:
        return int((time.monotonic() - self.start) * 1000)


@contextmanager
def step(verb: str, total: int | None = None, quiet: bool = False):
    """A timed unit of work. Always records elapsed_ms; renders only when a human
    is watching. (Full rich.progress live bars are a pretty-mode refinement; the
    timing contract is what matters for the machine stream + benchmark artifacts.)"""
    s = _Step(verb)
    s.total = total or 0
    try:
        yield s
    finally:
        if not quiet:
            detail = f"{s.elapsed_ms} ms"
            if s.total:
                detail = f"{s.done}/{s.total} · {detail}"
            line(verb, s.hash or "", detail=detail)
