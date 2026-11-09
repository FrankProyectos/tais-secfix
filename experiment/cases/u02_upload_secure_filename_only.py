import os

from flask import Blueprint, current_app, jsonify, request
from werkzeug.utils import secure_filename

bp = Blueprint("case", __name__)


@bp.route("/avatar", methods=["POST"])
def avatar():
    f = request.files["file"]
    nombre = secure_filename(f.filename)
    f.save(os.path.join(current_app.config["UPLOAD_DIR"], nombre))
    return jsonify({"ok": True, "archivo": nombre})
