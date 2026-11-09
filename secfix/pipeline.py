"""Orquestación: SAST -> triage LLM -> reparación LLM -> validación."""
from __future__ import annotations

import hashlib
import pathlib
import time
from collections import defaultdict

from secfix.context import apply_replacement, enclosing_block, get_lines
from secfix.models import RepairGroup
from secfix.repair import propose_fix
from secfix.sast import run_semgrep
from secfix.triage import triage


class Pipeline:
    def __init__(self, rules: str, repo_root: str = ".", llm=None, validator=None,
                 mode: str = "full", max_attempts: int = 2, log=print):
        assert mode in ("sast-only", "full")
        self.rules, self.repo_root, self.llm = rules, repo_root, llm
        self.validator, self.mode, self.max_attempts, self.log = validator, mode, max_attempts, log

    def run(self, targets: dict) -> dict:
        """targets: {ruta_relativa: set(lineas_cambiadas) o None (= archivo completo)}."""
        t0 = time.monotonic()
        timings = {}
        paths = [p for p in targets if p.endswith(".py") and pathlib.Path(self.repo_root, p).exists()]
        sources = {p: pathlib.Path(self.repo_root, p).read_text(encoding="utf-8") for p in paths}

        # Etapa 2: Semgrep
        all_findings = run_semgrep(paths, self.rules, cwd=self.repo_root) if paths else []
        totals = defaultdict(int)
        for f in all_findings:
            totals[f.path] += 1
        findings = [f for f in all_findings if self._in_scope(f, targets, sources)]
        timings["sast_s"] = round(time.monotonic() - t0, 2)
        self.log(f"[secfix] Semgrep: {len(all_findings)} hallazgos, {len(findings)} dentro del diff")

        groups: list[RepairGroup] = []
        if self.mode == "full" and findings:
            t1 = time.monotonic()
            for f in findings:  # Etapa 3: triage
                triage(f, sources[f.path], self.llm)
                self.log(f"[secfix] triage {f.path}:{f.line} {f.short_rule} -> {f.verdict} ({f.confidence})")
            timings["triage_s"] = round(time.monotonic() - t1, 2)

            t2 = time.monotonic()
            groups = self._group([f for f in findings if f.verdict == "TP"], sources)
            for g in groups:  # Etapas 4 y 5: reparación + validación con 1 reintento
                feedback = None
                while g.attempts < self.max_attempts:
                    propose_fix(g, sources[g.path], self.llm, feedback)
                    g.validation = self.validator.validate(sources[g.path], g, totals[g.path])
                    g.history.append({"attempt": g.attempts, "details": g.validation.details,
                                      "passed": g.validation.passed})
                    self.log(f"[secfix] parche {g.group_id} intento {g.attempts}: "
                             f"{'VALIDADO' if g.validation.passed else 'rechazado'}")
                    if g.validation.passed:
                        g.accepted = True
                        break
                    feedback = "\n".join(g.validation.details)
            timings["repair_validate_s"] = round(time.monotonic() - t2, 2)

        timings["total_s"] = round(time.monotonic() - t0, 2)
        return {"findings": findings, "groups": groups, "sources": sources,
                "timings": timings, "totals": dict(totals)}

    @staticmethod
    def _in_scope(f, targets, sources):
        lines = targets.get(f.path)
        if lines is None:
            return True
        start, end = enclosing_block(sources[f.path], f.line)
        return any(start <= l <= end for l in lines)

    @staticmethod
    def _group(tp_findings, sources):
        buckets = defaultdict(list)
        for f in tp_findings:
            buckets[(f.path, *enclosing_block(sources[f.path], f.line))].append(f)
        groups = []
        for (path, start, end), fs in sorted(buckets.items()):
            code = get_lines(sources[path], start, end)
            gid = hashlib.sha1(f"{path}|{code}".encode()).hexdigest()[:10]
            for f in fs:
                f.group_id = gid
            groups.append(RepairGroup(group_id=gid, path=path, start=start, end=end,
                                      original_code=code, findings=fs))
        return groups


def apply_accepted(source: str, groups) -> str:
    """Aplica todos los parches aceptados de un archivo (de abajo hacia arriba)."""
    for g in sorted([g for g in groups if g.accepted], key=lambda g: g.start, reverse=True):
        source = apply_replacement(source, g.start, g.end, g.fixed_code)
    return source
