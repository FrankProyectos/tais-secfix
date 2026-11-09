from flask import Blueprint, render_template_string, request

bp = Blueprint("case", __name__)


@bp.route("/buscar")
def buscar():
    q = request.args.get("q", "")
    return render_template_string("<p>Resultados para: " + q + "</p>")
