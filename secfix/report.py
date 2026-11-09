"""Etapa 6: presentación de resultados (Markdown, GitHub PR review, métricas)."""
from __future__ import annotations

import json
import os
from dataclasses import asdict

import requests

SUMMARY_MARKER = "<!-- secfix-summary -->"
API = os.environ.get("GITHUB_API_URL", "https://api.github.com")


def mark(v):
    return {True: "✅", False: "❌", None: "➖"}[v]


def validation_line(val) -> str:
    if val is None:
        return ""
    return (f"{mark(val.v1_compiles)} V1 compila · {mark(val.v2_sast_clean)} V2 Semgrep limpio · "
            f"{mark(val.v3_tests)} V3 tests · {mark(val.v4_exploit_blocked)} V4 exploit bloqueado")


def comment_body(group, as_suggestion: bool) -> str:
    head = "\n".join(
        f"**{f.cwe}** · `{f.short_rule}` (línea {f.line}) — veredicto del LLM: **verdadero positivo**"
        f" (confianza {f.confidence:.2f}). {f.justification}" for f in group.findings)
    body = [f"<!-- secfix:{group.group_id} -->", "### 🔒 secfix: vulnerabilidad confirmada", head, ""]
    if group.accepted:
        body += [f"**Corrección propuesta:** {group.explanation}", "",
                 f"Validación automática: {validation_line(group.validation)}", ""]
        if as_suggestion:
            body += ["Puedes aplicarla con **Commit suggestion**:", "```suggestion", group.fixed_code, "```"]
        else:
            body += ["El bloque corregido no cabe completo en el diff; aplica este parche manualmente:",
                     "```python", group.fixed_code, "```"]
    else:
        last = group.validation.details if group.validation else []
        body += ["**No se encontró un parche que pase la validación**; requiere corrección manual.", "",
                 "<details><summary>Detalle del último intento</summary>", "", "```",
                 "\n".join(last)[-1500:], "```", "</details>"]
    return "\n".join(body)


def summary_markdown(result: dict, mode: str) -> str:
    findings, groups = result["findings"], result["groups"]
    tp = [f for f in findings if f.verdict == "TP"]
    fp = [f for f in findings if f.verdict == "FP"]
    accepted = [g for g in groups if g.accepted]
    lines = [SUMMARY_MARKER, "## 🔒 secfix — análisis de seguridad del PR", ""]
    if not findings:
        lines.append("Semgrep no encontró vulnerabilidades (SQLi, XSS, carga de archivos) en las líneas cambiadas. ✅")
        return "\n".join(lines)
    if mode == "sast-only":
        lines.append(f"Semgrep reportó **{len(findings)}** hallazgo(s) (modo solo SAST, sin LLM).")
    else:
        lines.append(f"Semgrep reportó **{len(findings)}** hallazgo(s). El LLM confirmó **{len(tp)}** y "
                     f"descartó **{len(fp)}** como falsos positivos. Parches validados: "
                     f"**{len(accepted)}/{len(groups)}**.")
    lines += ["", "| Archivo:línea | CWE | Regla | Veredicto | Parche |", "|---|---|---|---|---|"]
    gmap = {g.group_id: g for g in groups}
    for f in findings:
        g = gmap.get(f.group_id)
        patch = "—" if f.verdict != "TP" else ("validado ✅" if g and g.accepted else "manual ❌")
        verdict = f.verdict or "sin triage"
        lines.append(f"| `{f.path}:{f.line}` | {f.cwe} | `{f.short_rule}` | {verdict} | {patch} |")
    if fp:
        lines += ["", "<details><summary>Hallazgos descartados como falsos positivos</summary>", ""]
        lines += [f"- `{f.path}:{f.line}` `{f.short_rule}` (confianza {f.confidence:.2f}): {f.justification}"
                  for f in fp]
        lines += ["", "</details>"]
    if tp or mode == "sast-only":
        lines += ["", "> El merge queda bloqueado hasta corregir los verdaderos positivos."]
    return "\n".join(lines)


def metrics(result: dict, extra: dict | None = None) -> dict:
    return {
        **(extra or {}),
        "timings": result["timings"],
        "findings": [{**{k: v for k, v in asdict(f).items() if k != "code"}, "fingerprint": f.fingerprint()}
                     for f in result["findings"]],
        "groups": [g.to_dict() for g in result["groups"]],
        "summary": {
            "findings": len(result["findings"]),
            "tp": sum(f.verdict == "TP" for f in result["findings"]),
            "fp": sum(f.verdict == "FP" for f in result["findings"]),
            "groups": len(result["groups"]),
            "patches_validated": sum(g.accepted for g in result["groups"]),
        },
    }


class GitHubReporter:
    def __init__(self, repo: str, pr: int, token: str, head_sha: str):
        self.repo, self.pr, self.head_sha = repo, pr, head_sha
        self.s = requests.Session()
        self.s.headers.update({"Authorization": f"Bearer {token}",
                               "Accept": "application/vnd.github+json",
                               "X-GitHub-Api-Version": "2022-11-28"})

    def _paginate(self, url):
        out, page = [], 1
        while True:
            r = self.s.get(url, params={"per_page": 100, "page": page}, timeout=30)
            r.raise_for_status()
            batch = r.json()
            out += batch
            if len(batch) < 100:
                return out
            page += 1

    def existing_markers(self) -> set:
        comments = self._paginate(f"{API}/repos/{self.repo}/pulls/{self.pr}/comments")
        return {c["body"].split("-->")[0].split("secfix:")[1].strip()
                for c in comments if "<!-- secfix:" in c.get("body", "")}

    def post_review(self, groups, commentable: dict, log=print):
        seen = self.existing_markers()
        comments = []
        for g in groups:
            if g.group_id in seen:
                log(f"[secfix] el comentario de {g.group_id} ya existe; no se repite")
                continue
            ok_lines = commentable.get(g.path, set())
            whole = all(l in ok_lines for l in range(g.start, g.end + 1))
            anchor = g.findings[0].line
            if whole and g.accepted:
                c = {"path": g.path, "line": g.end, "side": "RIGHT", "body": comment_body(g, True)}
                if g.start != g.end:
                    c.update(start_line=g.start, start_side="RIGHT")
            elif anchor in ok_lines:
                c = {"path": g.path, "line": anchor, "side": "RIGHT", "body": comment_body(g, False)}
            else:
                continue
            comments.append(c)
        if not comments:
            return
        r = self.s.post(f"{API}/repos/{self.repo}/pulls/{self.pr}/reviews", timeout=30,
                        json={"commit_id": self.head_sha, "event": "COMMENT",
                              "body": "secfix encontró vulnerabilidades confirmadas en este PR. "
                                      "Revisa las sugerencias en línea.", "comments": comments})
        if r.status_code >= 300:
            log(f"[secfix] no se pudo crear la review ({r.status_code}): {r.text[:500]}")

    def upsert_summary(self, markdown: str):
        url = f"{API}/repos/{self.repo}/issues/{self.pr}/comments"
        for c in self._paginate(url):
            if SUMMARY_MARKER in c.get("body", ""):
                self.s.patch(f"{API}/repos/{self.repo}/issues/comments/{c['id']}",
                             json={"body": markdown}, timeout=30).raise_for_status()
                return
        self.s.post(url, json={"body": markdown}, timeout=30).raise_for_status()


def write_json(path: str, data: dict):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2, default=str)
