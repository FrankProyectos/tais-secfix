"""Aplicación Flask de laboratorio.

Cada módulo de `lab/routes/` define un Blueprint llamado `bp`; la app los
registra automáticamente. Así, un pull request de demostración solo tiene
que agregar un archivo nuevo en `lab/routes/`.
"""
import importlib.util
import os
import pathlib
import sys

from flask import Flask

from lab.db import close_db, init_db

ROUTES_DIR = pathlib.Path(__file__).parent / "routes"


def load_module(path: str):
    path = os.path.abspath(path)
    name = "labmod_" + str(abs(hash(path)))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def create_app(db_path: str, upload_dir: str, modules=None) -> Flask:
    app = Flask(__name__)
    app.config.update(DB_PATH=db_path, UPLOAD_DIR=upload_dir, TESTING=True,
                      MAX_CONTENT_LENGTH=2 * 1024 * 1024)
    os.makedirs(upload_dir, exist_ok=True)
    init_db(db_path)
    app.teardown_appcontext(close_db)

    if modules is None:
        modules = sorted(str(p) for p in ROUTES_DIR.glob("*.py") if p.name != "__init__.py")
    for path in modules:
        mod = load_module(path)
        app.register_blueprint(mod.bp, name=pathlib.Path(path).stem + "_" + str(abs(hash(path))))
    return app


if __name__ == "__main__":
    base = os.environ.get("LAB_DATA", "/tmp/lab")
    os.makedirs(base, exist_ok=True)
    create_app(os.path.join(base, "lab.db"), os.path.join(base, "uploads")).run(debug=False)
