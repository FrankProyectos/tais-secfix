from flask import Blueprint, jsonify, render_template_string, request

from lab.db import get_db, rows_to_dicts

bp = Blueprint("home", __name__)

PAGE = """<!doctype html>
<title>Laboratorio TAIS</title>
<h1>Laboratorio TAIS</h1>
<p>Hola, {{ name }}.</p>
"""


@bp.route("/")
def index():
    # render_template_string con variables: Jinja2 escapa automáticamente
    return render_template_string(PAGE, name=request.args.get("name", "visitante"))


@bp.route("/users")
def users():
    name = request.args.get("name", "")
    cur = get_db().cursor()
    cur.execute("SELECT name, email FROM users WHERE role = 'user' AND name = ?", (name,))
    return jsonify(rows_to_dicts(cur.fetchall()))
