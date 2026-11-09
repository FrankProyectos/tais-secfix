from flask import Blueprint, request

bp = Blueprint("case", __name__)


def limpiar(texto):
    return (texto.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;"))


@bp.route("/saludo")
def saludo():
    name = request.args.get("name", "visitante")
    return f"<h1>Hola, {limpiar(name)}</h1>"
