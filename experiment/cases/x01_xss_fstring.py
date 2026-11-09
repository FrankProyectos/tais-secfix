from flask import Blueprint, request

bp = Blueprint("case", __name__)


@bp.route("/hello")
def hello():
    name = request.args.get("name", "visitante")
    return f"<h1>Hola, {name}</h1>"
