from flask import Blueprint, jsonify, request

from lab.db import get_db, rows_to_dicts

bp = Blueprint("case", __name__)

BASE = "SELECT name, email, notes FROM users WHERE role = 'user'"


@bp.route("/users/filter")
def filter_users():
    name = request.args.get("name")
    sql = BASE
    if name:
        where = " AND name = '" + name + "'"
        sql = sql + where
    cur = get_db().cursor()
    cur.execute(sql)
    return jsonify(rows_to_dicts(cur.fetchall()))
