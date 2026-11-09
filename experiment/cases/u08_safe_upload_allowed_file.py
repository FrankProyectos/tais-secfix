import os

from flask import Blueprint, abort, current_app, jsonify, request
from werkzeug.utils import secure_filename

bp = Blueprint("case", __name__)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@bp.route("/adjuntos", methods=["POST"])
def adjuntos():
    f = request.files.get("file")
    if f is None or not allowed_file(f.filename):
        abort(400)
    nombre = secure_filename(f.filename)
    f.save(os.path.join(current_app.config["UPLOAD_DIR"], nombre))
    return jsonify({"ok": True, "archivo": nombre})
