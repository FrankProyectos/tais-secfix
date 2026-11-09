from flask import Blueprint, jsonify, request

from lab.db import get_db, rows_to_dicts

bp = Blueprint("case", __name__)


@bp.route("/users/by-name")
def users_by_name():
    name = request.args.get("name", "")
    cur = get_db().cursor()
    cur.execute(f"SELECT name, email, notes FROM users WHERE role = 'user' AND name = '{name}'")
    return jsonify(rows_to_dicts(cur.fetchall()))
