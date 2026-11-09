from flask import Blueprint, jsonify, request

from lab.db import get_db, rows_to_dicts

bp = Blueprint("case", __name__)


@bp.route("/users/lookup", methods=["POST"])
def lookup_by_email():
    email = request.form.get("email", "")
    query = "SELECT name, email, notes FROM users WHERE email = '{}' AND role = 'user'".format(email)
    cur = get_db().cursor()
    cur.execute(query)
    return jsonify(rows_to_dicts(cur.fetchall()))
