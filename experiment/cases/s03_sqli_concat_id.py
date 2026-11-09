from flask import Blueprint, jsonify, request

from lab.db import get_db, rows_to_dicts

bp = Blueprint("case", __name__)


@bp.route("/users/detail")
def user_detail():
    uid = request.args.get("id", "0")
    cur = get_db().cursor()
    cur.execute("SELECT name, email, notes FROM users WHERE role = 'user' AND id = " + uid)
    return jsonify(rows_to_dicts(cur.fetchall()))
