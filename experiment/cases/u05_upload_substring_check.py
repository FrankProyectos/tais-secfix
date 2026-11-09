import os

from flask import Blueprint, abort, current_app, jsonify, request

bp = Blueprint("case", __name__)


@bp.route("/imagenes", methods=["POST"])
def imagenes():
    f = request.files["file"]
    if "png" not in f.filename and "jpg" not in f.filename:
        abort(400)
    f.save(os.path.join(current_app.config["UPLOAD_DIR"], f.filename))
    return jsonify({"ok": True})
