"""Ejecución y normalización de Semgrep CE."""
from __future__ import annotations

import json
import pathlib
import subprocess

from secfix.context import enclosing_block
from secfix.models import Finding


def run_semgrep(paths, rules: str, cwd: str | None = None, timeout: int = 300):
    if not paths:
        return []
    cmd = ["semgrep", "scan", "--config", rules, "--json", "--metrics=off",
           "--disable-version-check", "--quiet", "--dataflow-traces", *paths]
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"Semgrep falló ({proc.returncode}): {proc.stderr[-1500:]}")
    data = json.loads(proc.stdout or "{}")
    findings = [_to_finding(r) for r in data.get("results", [])]
    for f in findings:
        _enrich(f, cwd)
    return findings


def _enrich(f: Finding, cwd: str | None):
    """Semgrep CE sin sesión no devuelve el código ni la traza: se reconstruyen localmente."""
    try:
        src = (pathlib.Path(cwd or ".") / f.path).read_text(encoding="utf-8")
    except OSError:
        return
    lines = src.splitlines()
    f.code = "\n".join(lines[f.line - 1:f.end_line])
    if not f.trace:
        start, end = enclosing_block(src, f.line)
        sources = [f"línea {i} `{lines[i - 1].strip()}`" for i in range(start, end + 1)
                   if "request." in lines[i - 1]]
        if sources:
            f.trace = "entrada del usuario en " + "; ".join(sources[:4]) + f"; sumidero en línea {f.line}"


def _trace_text(extra) -> str:
    tr = extra.get("dataflow_trace") or {}
    parts = []
    src = tr.get("taint_source")
    if isinstance(src, list) and len(src) > 1 and isinstance(src[1], list):
        loc = src[1][0] if src[1] else None
        if isinstance(loc, dict):
            parts.append(f"fuente: línea {loc.get('start', {}).get('line')} `{loc.get('content', '')}`")
    for step in tr.get("intermediate_vars", []) or []:
        parts.append(f"pasa por: línea {step.get('location', {}).get('start', {}).get('line')} "
                     f"`{step.get('content', '')}`")
    return "; ".join(parts)


def _to_finding(r) -> Finding:
    extra = r.get("extra", {})
    meta = extra.get("metadata", {})
    return Finding(
        rule_id=r["check_id"],
        path=r["path"],
        line=r["start"]["line"],
        end_line=r["end"]["line"],
        message=" ".join(extra.get("message", "").split()),
        cwe=meta.get("secfix_cwe") or str(meta.get("cwe", "")).split(":")[0],
        severity=extra.get("severity", ""),
        code=extra.get("lines", ""),
        trace=_trace_text(extra),
    )
