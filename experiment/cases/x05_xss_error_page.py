from flask import Blueprint, request

bp = Blueprint("case", __name__)

PAGES = {"inicio": "<p>Bienvenido</p>", "ayuda": "<p>Ayuda</p>"}


@bp.route("/pagina")
def pagina():
    nombre = request.args.get("p", "inicio")
    if nombre in PAGES:
        return PAGES[nombre]
    return "<p>Página no encontrada: %s</p>" % nombre, 404
