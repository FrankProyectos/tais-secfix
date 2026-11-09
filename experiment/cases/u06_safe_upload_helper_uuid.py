import os
import uuid

from flask import Blueprint, abort, current_app, jsonify, request

bp = Blueprint("case", __name__)

PERMITIDAS = {".png", ".jpg", ".jpeg", ".gif"}


def es_imagen(ext):
    return ext in PERMITIDAS


@bp.route("/galeria", methods=["POST"])
def galeria():
    f = request.files["file"]
    ext = os.path.splitext(f.filename)[1].lower()
    if not es_imagen(ext):
        abort(400)
    nombre = uuid.uuid4().hex + ext
    f.save(os.path.join(current_app.config["UPLOAD_DIR"], nombre))
    return jsonify({"ok": True, "archivo": nombre})
