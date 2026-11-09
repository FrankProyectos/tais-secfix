from flask import Blueprint, make_response, request

bp = Blueprint("case", __name__)


@bp.route("/comentarios", methods=["POST"])
def comentar():
    texto = request.form.get("texto", "")
    resp = make_response("<div class='comentario'>" + texto + "</div>")
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp
