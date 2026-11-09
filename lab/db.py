"""Base de datos SQLite del laboratorio.

La tabla `users` contiene un usuario administrador con una nota secreta
(FLAG). Las rutas legítimas solo exponen usuarios con rol 'user'; si una
respuesta contiene la FLAG, la inyección SQL fue explotada.
"""
import sqlite3

from flask import current_app, g

SEED_USERS = [
    (1, "alice", "alice@example.com", "user", "Le gusta Python"),
    (2, "bob", "bob@example.com", "user", "Fan de Flask"),
    (3, "admin", "admin@example.com", "admin", "FLAG{nota_secreta_admin}"),
]


def init_db(path: str) -> None:
    con = sqlite3.connect(path)
    con.executescript(
        """
        DROP TABLE IF EXISTS users;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            notes TEXT
        );
        """
    )
    con.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?)", SEED_USERS)
    con.commit()
    con.close()


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def rows_to_dicts(rows):
    return [dict(r) for r in rows]
