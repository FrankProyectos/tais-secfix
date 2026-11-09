from flask import Blueprint, render_template_string, request
from markupsafe import Markup

bp = Blueprint("case", __name__)


@bp.route("/aviso")
def aviso():
    msg = request.args.get("msg", "")
    contenido = Markup(f"<b>{msg}</b>")
    return render_template_string("<div class='aviso'>{{ c }}</div>", c=contenido)
