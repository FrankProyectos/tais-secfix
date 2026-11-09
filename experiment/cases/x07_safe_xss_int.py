from flask import Blueprint, request

bp = Blueprint("case", __name__)


@bp.route("/listado")
def listado():
    try:
        page = int(request.args.get("page", "1"))
    except ValueError:
        return "<p>Página inválida</p>", 400
    return f"<p>Mostrando página {page}</p>"
