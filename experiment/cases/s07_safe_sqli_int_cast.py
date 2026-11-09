from flask import Blueprint, jsonify, request

from lab.db import get_db, rows_to_dicts

bp = Blueprint("case", __name__)


@bp.route("/users/by-id")
def user_by_id():
    try:
        uid = int(request.args.get("id", "0"))
    except ValueError:
        return jsonify({"error": "id inválido"}), 400
    cur = get_db().cursor()
    cur.execute(f"SELECT name, email, notes FROM users WHERE role = 'user' AND id = {uid}")
    return jsonify(rows_to_dicts(cur.fetchall()))
