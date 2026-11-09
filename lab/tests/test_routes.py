"""Pruebas del laboratorio: cada ruta debe funcionar (V3) y resistir su ataque (V4).

secfix ejecuta este archivo sobre una copia del repositorio con el parche aplicado.
"""
import json
import pathlib
import subprocess
import sys

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
ROUTES = ROOT / "lab" / "routes"
SPECS = yaml.safe_load((ROOT / "lab" / "specs.yaml").read_text(encoding="utf-8")) or {}

PARAMS = [
    pytest.param(mod, spec, id=f"{mod}-{i}")
    for mod, entries in SPECS.items() for i, spec in enumerate(entries)
]


def run_harness(module, spec):
    proc = subprocess.run(
        [sys.executable, "-m", "lab.harness", "--module", str(ROUTES / f"{module}.py"),
         "--spec", json.dumps(spec)], cwd=ROOT, capture_output=True, text=True, timeout=120)
    return json.loads(proc.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("module,spec", PARAMS)
def test_functional(module, spec):
    r = run_harness(module, {"functional": spec["functional"]})
    assert r["functional"], r["details"]


@pytest.mark.parametrize("module,spec", PARAMS)
def test_exploit_blocked(module, spec):
    r = run_harness(module, {"exploit": spec["exploit"]})
    assert r["exploitable"] is False, r["details"]


def test_every_route_module_imports():
    from lab.app import create_app
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        create_app(f"{tmp}/db.sqlite", f"{tmp}/up")
