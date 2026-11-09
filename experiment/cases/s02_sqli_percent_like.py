from flask import Blueprint, jsonify, request

from lab.db import get_db, rows_to_dicts

bp = Blueprint("case", __name__)


@bp.route("/users/search")
def search_users():
    q = request.args.get("q", "")
    sql = "SELECT name, email, notes FROM users WHERE role = 'user' AND name LIKE '%%%s%%'" % q
    cur = get_db().cursor()
    cur.execute(sql)
    return jsonify(rows_to_dicts(cur.fetchall()))
