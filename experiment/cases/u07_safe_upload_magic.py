import os
import uuid

from flask import Blueprint, abort, current_app, jsonify, request

bp = Blueprint("case", __name__)

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


@bp.route("/escaneos", methods=["POST"])
def escaneos():
    f = request.files["file"]
    cabecera = f.stream.read(8)
    f.stream.seek(0)
    if cabecera != PNG_MAGIC:
        abort(400)
    destino = os.path.join(current_app.config["UPLOAD_DIR"], uuid.uuid4().hex + ".png")
    f.save(destino)
    return jsonify({"ok": True})
