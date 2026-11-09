"""Pruebas del motor con un LLM simulado (no requieren red ni token)."""
import pathlib
import textwrap

import yaml

from secfix.diff import parse_diff
from secfix.pipeline import Pipeline, apply_accepted
from secfix.validate import Validator

ROOT = pathlib.Path(__file__).resolve().parents[1]
CASES = {c["id"]: c for c in yaml.safe_load((ROOT / "experiment/cases.yaml").read_text())["cases"]}

FIXES = {
    "s01_sqli_fstring": '''
        @bp.route("/users/by-name")
        def users_by_name():
            name = request.args.get("name", "")
            cur = get_db().cursor()
            cur.execute("SELECT name, email, notes FROM users WHERE role = 'user' AND name = ?", (name,))
            return jsonify(rows_to_dicts(cur.fetchall()))
    ''',
    "x01_xss_fstring": '''
        @bp.route("/hello")
        def hello():
            from markupsafe import escape
            name = request.args.get("name", "visitante")
            return f"<h1>Hola, {escape(name)}</h1>"
    ''',
    "u01_upload_raw": '''
        @bp.route("/upload", methods=["POST"])
        def upload():
            from flask import abort
            from werkzeug.utils import secure_filename
            f = request.files["file"]
            nombre = secure_filename(f.filename)
            ext = os.path.splitext(nombre)[1].lower()
            if ext not in {".png", ".jpg", ".jpeg", ".gif"}:
                abort(400)
            f.save(os.path.join(current_app.config["UPLOAD_DIR"], nombre))
            return jsonify({"ok": True})
    ''',
    # Parche INCORRECTO a propósito: limpia Semgrep (V2) pero el exploit sigue (V4)
    "u05_upload_substring_check": '''
        @bp.route("/imagenes", methods=["POST"])
        def imagenes():
            from werkzeug.utils import secure_filename
            f = request.files["file"]
            if "png" not in f.filename and "jpg" not in f.filename:
                abort(400)
            f.save(os.path.join(current_app.config["UPLOAD_DIR"], secure_filename(f.filename)))
            return jsonify({"ok": True})
    ''',
}


class FakeLLM:
    def __init__(self, case_id):
        self.case_id, self.calls = case_id, 0

    def chat_json(self, system, user):
        self.calls += 1
        if "auditor" in system:
            return {"verdict": "TP", "confidence": 0.9, "justification": "simulado"}
        return {"fixed_code": textwrap.dedent(FIXES[self.case_id]).strip(), "explanation": "simulado"}

    def usage(self):
        return {"calls": self.calls}


def run_case(case_id):
    c = CASES[case_id]
    rel = f"experiment/cases/{case_id}.py"
    v = Validator(str(ROOT / "rules"), str(ROOT),
                  harness_spec={"functional": c["functional"], "exploit": c["exploit"]})
    pipe = Pipeline(str(ROOT / "rules"), str(ROOT), llm=FakeLLM(case_id), validator=v,
                    log=lambda m: None)
    return pipe.run({rel: None}), rel


def test_sqli_fix_validated():
    res, _ = run_case("s01_sqli_fstring")
    assert len(res["groups"]) == 1 and res["groups"][0].accepted
    val = res["groups"][0].validation
    assert val.v1_compiles and val.v2_sast_clean and val.v3_tests and val.v4_exploit_blocked


def test_xss_fix_validated():
    res, _ = run_case("x01_xss_fstring")
    assert res["groups"][0].accepted


def test_upload_fix_groups_two_rules_and_validates():
    res, rel = run_case("u01_upload_raw")
    assert len(res["findings"]) == 2 and len(res["groups"]) == 1
    g = res["groups"][0]
    assert g.accepted
    patched = apply_accepted(res["sources"][rel], res["groups"])
    assert "secure_filename" in patched


def test_wrong_fix_rejected_by_exploit_test():
    res, _ = run_case("u05_upload_substring_check")
    g = res["groups"][0]
    assert not g.accepted and g.attempts == 2
    assert g.validation.v2_sast_clean is True and g.validation.v4_exploit_blocked is False


def test_parse_diff():
    diff = textwrap.dedent("""\
        diff --git a/app.py b/app.py
        --- a/app.py
        +++ b/app.py
        @@ -1,3 +1,4 @@
         import os
        +import sys
         x = 1
         y = 2
        """)
    d = parse_diff(diff)
    assert d["app.py"]["added"] == {2}
    assert d["app.py"]["commentable"] == {1, 2, 3, 4}
