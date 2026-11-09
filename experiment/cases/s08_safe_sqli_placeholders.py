from flask import Blueprint, jsonify, request

from lab.db import get_db, rows_to_dicts

bp = Blueprint("case", __name__)


@bp.route("/users/many")
def many_users():
    ids = [i for i in request.args.get("ids", "").split(",") if i]
    if not ids:
        return jsonify([])
    placeholders = ",".join("?" * len(ids))
    sql = f"SELECT name, email, notes FROM users WHERE role = 'user' AND id IN ({placeholders})"
    cur = get_db().cursor()
    cur.execute(sql, ids)
    return jsonify(rows_to_dicts(cur.fetchall()))
