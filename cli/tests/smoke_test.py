"""Installed-artifact smoke test used for both wheel and sdist release candidates."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from importlib.metadata import entry_points, version

assert version("blindmachine") == "0.1.0"
scripts = {entry.name: entry.value for entry in entry_points(group="console_scripts")}
assert scripts["blind"] == "blind.__main__:main"
assert scripts["blindmachine"] == "blind.__main__:main"

with tempfile.TemporaryDirectory(prefix="blind-smoke-") as home:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": home,
        "BLIND_JSON": "1",
        "NO_COLOR": "1",
    }
    result = subprocess.run(
        [sys.executable, "-m", "blind", "version"],
        capture_output=True,
        text=True,
        timeout=20,
        env=env,
        check=True,
    )
    payload = json.loads(result.stdout)
    assert payload["object"] == "version"
    assert payload["version"] == "0.1.0"

print("installed artifact smoke test passed")
