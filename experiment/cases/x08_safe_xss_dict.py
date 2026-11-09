from flask import Blueprint, request

bp = Blueprint("case", __name__)

MESSAGES = {"es": "Bienvenido", "en": "Welcome", "pt": "Bem-vindo"}


@bp.route("/bienvenida")
def bienvenida():
    msg = MESSAGES.get(request.args.get("lang", "es"), MESSAGES["es"])
    return f"<p>{msg}</p>"
