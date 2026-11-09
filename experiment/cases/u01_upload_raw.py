import os

from flask import Blueprint, current_app, jsonify, request

bp = Blueprint("case", __name__)


@bp.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    f.save(os.path.join(current_app.config["UPLOAD_DIR"], f.filename))
    return jsonify({"ok": True})
