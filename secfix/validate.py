"""Etapa 5: validación determinista de un parche (V1–V4).

V1  el archivo parcheado compila.
V2  Semgrep vuelve a escanear: ningún hallazgo de las reglas reparadas queda
    dentro del bloque corregido y el total de hallazgos del archivo no aumenta.
V3  pruebas funcionales (comando del repo o especificación del caso).
V4  prueba de explotación: el ataque ya no funciona.
Un valor None significa "no configurado" y no bloquea; False bloquea.
"""
from __future__ import annotations

import json
import os
import pathlib
import py_compile
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

from secfix.context import apply_replacement
from secfix.models import RepairGroup, Validation
from secfix.sast import run_semgrep

ROOT = pathlib.Path(__file__).resolve().parents[1]


class Validator:
    def __init__(self, rules: str, repo_root: str = ".", test_cmd: str | None = None,
                 exploit_cmd: str | None = None, harness_spec: dict | None = None,
                 timeout: int = 300):
        self.rules = os.path.abspath(rules)
        self.repo_root = os.path.abspath(repo_root)
        self.test_cmd = test_cmd
        self.exploit_cmd = exploit_cmd
        self.harness_spec = harness_spec      # modo experimento: {functional, exploit}
        self.timeout = timeout
        self._baseline = {}   # (ruta, comando) -> fallas sin parche

    # -- V1 -----------------------------------------------------------------
    @staticmethod
    def compiles(path: str):
        if not path.endswith(".py"):
            return None, "V1 no aplica (no es Python)"
        try:
            py_compile.compile(path, doraise=True)
            return True, "V1 compila"
        except py_compile.PyCompileError as e:
            return False, f"V1 error de sintaxis: {str(e)[-400:]}"

    # -- V2 -----------------------------------------------------------------
    def sast_clean(self, patched_path, group: RepairGroup, before_total: int, new_end: int):
        after = run_semgrep([patched_path], self.rules)
        rules = {f.short_rule for f in group.findings}
        remaining = [f for f in after if f.short_rule in rules and group.start <= f.line <= new_end]
        if remaining:
            return False, "V2 Semgrep sigue reportando: " + "; ".join(
                f"{f.short_rule} en la línea {f.line}" for f in remaining)
        if len(after) > before_total:
            return False, f"V2 el parche introduce hallazgos nuevos ({before_total} -> {len(after)})"
        return True, f"V2 Semgrep limpio en el bloque ({before_total} -> {len(after)} hallazgos en el archivo)"

    # -- V3/V4 con el harness del laboratorio (modo experimento) --------------
    def run_harness(self, patched_path):
        proc = subprocess.run(
            [sys.executable, "-m", "lab.harness", "--module", patched_path,
             "--spec", json.dumps(self.harness_spec)],
            cwd=str(ROOT), capture_output=True, text=True, timeout=self.timeout)
        try:
            return json.loads(proc.stdout.strip().splitlines()[-1])
        except Exception:
            return {"functional": False, "exploitable": None,
                    "details": [f"harness falló: {proc.stderr[-400:]}"]}

    # -- V3/V4 con comandos del repositorio (modo PR) ---------------------------
    def run_cmd_in_copy(self, rel_path, patched_text, cmd):
        """Ejecuta `cmd` en una copia del repo. Devuelve (ok, salida, fallas).

        Si el comando es pytest, `fallas` es el conjunto de tests que fallan
        (leído de un reporte JUnit); si no, es None y solo cuenta el código de salida.
        """
        with tempfile.TemporaryDirectory() as tmp:
            dst = os.path.join(tmp, "repo")
            shutil.copytree(self.repo_root, dst, ignore=shutil.ignore_patterns(".git", "__pycache__", ".venv"))
            if patched_text is not None:
                pathlib.Path(dst, rel_path).write_text(patched_text, encoding="utf-8")
            junit = os.path.join(tmp, "junit.xml")
            full = f"{cmd} --junitxml={junit}" if "pytest" in cmd else cmd
            proc = subprocess.run(full, shell=True, cwd=dst, capture_output=True, text=True,
                                  timeout=self.timeout)
            tail = (proc.stdout + proc.stderr)[-800:]
            failures = None
            if os.path.exists(junit):
                failures = set()
                for tc in ET.parse(junit).getroot().iter("testcase"):
                    if tc.find("failure") is not None or tc.find("error") is not None:
                        failures.add(f"{tc.get('classname')}::{tc.get('name')}")
            return proc.returncode == 0, tail, failures

    def baseline_failures(self, rel_path, source, cmd):
        key = (rel_path, cmd)
        if key not in self._baseline:
            self._baseline[key] = self.run_cmd_in_copy(rel_path, source, cmd)
        return self._baseline[key]

    def compare_tests(self, rel_path, source, patched, cmd):
        """V3: el parche no rompe tests que pasaban. V4: algún test de explotación que
        fallaba ahora pasa (y ninguno nuevo falla)."""
        ok, tail, after = self.run_cmd_in_copy(rel_path, patched, cmd)
        if after is None:  # comando sin reporte JUnit: solo código de salida
            return ok, None, ("V3 tests ok" if ok else f"V3 tests fallan:\n{tail}")
        _, _, before = self.baseline_failures(rel_path, source, cmd)
        before = before or set()
        new = after - before
        v3 = not new
        exp_before = {t for t in before if "exploit" in t}
        exp_after = {t for t in after if "exploit" in t}
        v4 = None if not exp_before else (exp_after < exp_before)
        msg = (f"V3 {'sin regresiones' if v3 else 'REGRESIONES: ' + ', '.join(sorted(new))}"
               f" (fallas {len(before)} -> {len(after)})")
        if exp_before:
            msg += (f"; V4 tests de explotación que fallaban: {len(exp_before)} -> {len(exp_after)}")
        return v3, v4, msg

    def validate(self, source: str, group: RepairGroup, before_total: int) -> Validation:
        v = Validation()
        if not group.fixed_code:
            v.v1_compiles = False
            v.details.append("El LLM no devolvió código.")
            return v
        patched = apply_replacement(source, group.start, group.end, group.fixed_code)
        new_end = group.start + len(group.fixed_code.splitlines()) - 1
        suffix = pathlib.Path(group.path).suffix or ".py"
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "patched" + suffix)
            pathlib.Path(p).write_text(patched, encoding="utf-8")

            v.v1_compiles, msg = self.compiles(p)
            v.details.append(msg)
            if v.v1_compiles is False:
                return v
            v.v2_sast_clean, msg = self.sast_clean(p, group, before_total, new_end)
            v.details.append(msg)
            if not v.v2_sast_clean:
                return v

            if self.harness_spec:
                h = self.run_harness(p)
                v.v3_tests = bool(h.get("functional"))
                v.v4_exploit_blocked = (None if "exploit" not in self.harness_spec
                                        else h.get("exploitable") is False)
                v.details.append(f"V3 funcional={'ok' if v.v3_tests else 'FALLA'}; "
                                 f"V4 exploit={'bloqueado' if v.v4_exploit_blocked else 'SIGUE FUNCIONANDO'}"
                                 f" ({'; '.join(h.get('details', []))[-300:]})")
                return v

        if self.test_cmd:
            v.v3_tests, v4, msg = self.compare_tests(group.path, source, patched, self.test_cmd)
            v.details.append(msg)
            if v4 is not None:
                v.v4_exploit_blocked = v4
        if self.exploit_cmd and v.v3_tests is not False:
            ok, tail, _ = self.run_cmd_in_copy(group.path, patched, self.exploit_cmd)
            v.v4_exploit_blocked = ok
            v.details.append("V4 exploit bloqueado" if ok else f"V4 el exploit sigue funcionando:\n{tail}")
        return v
