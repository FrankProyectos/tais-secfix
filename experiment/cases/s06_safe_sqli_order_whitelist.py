from flask import Blueprint, jsonify, request

from lab.db import get_db, rows_to_dicts

bp = Blueprint("case", __name__)

SORT_COLUMNS = {"name": "name", "email": "email", "id": "id"}


@bp.route("/users/sorted")
def sorted_users():
    col = SORT_COLUMNS.get(request.args.get("sort", "name"), "name")
    cur = get_db().cursor()
    cur.execute(f"SELECT name, email, notes FROM users WHERE role = 'user' ORDER BY {col}")
    return jsonify(rows_to_dicts(cur.fetchall()))
