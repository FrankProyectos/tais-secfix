import os

from flask import Blueprint, abort, current_app, jsonify, request

bp = Blueprint("case", __name__)


@bp.route("/documentos", methods=["POST"])
def documentos():
    f = request.files["file"]
    if f.filename.endswith(".exe"):
        abort(400)
    f.save(os.path.join(current_app.config["UPLOAD_DIR"], f.filename))
    return jsonify({"ok": True})
