"""Trust-class vocabulary + the loud boundary banners (README "trust surface").

Five trust classes. Raw / Encoded / Private are LOCAL-ONLY and never uploaded;
Encrypted and Public are the only uploadable classes. The banners here are the
"see the boundary, don't just trust it" affordance the whole CLI is built around.
"""

from __future__ import annotations

from blind import console

# LOCAL-ONLY classes — printing one of these next to an "uploaded" verb is a bug.
LOCAL_ONLY = frozenset({"raw", "encoded", "private"})
UPLOADABLE = frozenset({"encrypted", "public"})


def contribution_banner() -> None:
    console.trust_banner(
        "You are contributing encrypted data",
        "Raw data and any secret key NEVER leave this machine.\n"
        "Only Encrypted ciphertext is uploaded. No account is created.",
    )


def local_crypto_banner(what: str) -> None:
    console.trust_banner(
        "Local-only crypto",
        f"{what} runs entirely on this machine.\n"
        "The secret key stays in your OS keychain — there is no endpoint that could receive it.",
    )


def nothing_uploaded_footer(raw_path: str) -> None:
    console.console.print(
        console.Text(
            f"Raw stayed at {raw_path} · Encoded stayed in cache · nothing else left.",
            style="meta",
        )
    )
