"""Cálculo de archivos y líneas cambiadas en un pull request."""
from __future__ import annotations

import re
import subprocess

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def git_diff(base: str, head: str, repo: str = ".", context: int = 3) -> str:
    return subprocess.run(
        ["git", "diff", f"--unified={context}", "--no-color", f"{base}...{head}"],
        cwd=repo, capture_output=True, text=True, check=True,
    ).stdout


def parse_diff(diff_text: str):
    """Devuelve {ruta: {"added": set(lineas), "commentable": set(lineas)}}.

    `added` son las líneas nuevas (+). `commentable` son todas las líneas del
    lado derecho que aparecen en algún hunk: GitHub solo acepta comentarios y
    sugerencias sobre esas líneas.
    """
    files, current, new_line = {}, None, 0
    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            path = raw[4:].strip()
            if path == "/dev/null":
                current = None
                continue
            current = path[2:] if path.startswith("b/") else path
            files[current] = {"added": set(), "commentable": set()}
            continue
        if raw.startswith("--- ") or current is None:
            continue
        m = HUNK.match(raw)
        if m:
            new_line = int(m.group(1))
            continue
        if raw.startswith("+"):
            files[current]["added"].add(new_line)
            files[current]["commentable"].add(new_line)
            new_line += 1
        elif raw.startswith("-"):
            continue
        elif raw.startswith(" "):
            files[current]["commentable"].add(new_line)
            new_line += 1
    return {p: v for p, v in files.items() if v["added"]}
