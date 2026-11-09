"""Recorte de contexto mínimo para el LLM y aplicación de parches por rango."""
from __future__ import annotations

import ast
import textwrap

MAX_HEADER_LINES = 40
WINDOW = 12


def enclosing_block(source: str, line: int):
    """Rango (inicio, fin) 1-based de la función que contiene `line`, con decoradores.

    Si el archivo no es Python válido o la línea no está en una función,
    devuelve una ventana de ±WINDOW líneas.
    """
    lines = source.splitlines()
    try:
        tree = ast.parse(source)
        best = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = min([node.lineno] + [d.lineno for d in node.decorator_list])
                if start <= line <= node.end_lineno:
                    if best is None or (node.end_lineno - start) < (best[1] - best[0]):
                        best = (start, node.end_lineno)
        if best:
            return best
    except SyntaxError:
        pass
    return max(1, line - WINDOW), min(len(lines), line + WINDOW)


def module_header(source: str) -> str:
    """Imports y constantes de nivel de módulo (lo que la función necesita para entenderse)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return "\n".join(source.splitlines()[:MAX_HEADER_LINES])
    lines = source.splitlines()
    keep = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign)):
            keep.extend(lines[node.lineno - 1: node.end_lineno])
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.decorator_list:
            # funciones auxiliares sin decorador (p. ej. validadores): solo su firma y cuerpo corto
            body = lines[node.lineno - 1: node.end_lineno]
            keep.extend(body[:12])
    return "\n".join(keep[:MAX_HEADER_LINES])


def numbered(code: str, start: int) -> str:
    return "\n".join(f"{start + i:4d} | {l}" for i, l in enumerate(code.splitlines()))


def get_lines(source: str, start: int, end: int) -> str:
    return "\n".join(source.splitlines()[start - 1:end])


def clean_code(code: str) -> str:
    code = code.strip("\n")
    if code.lstrip().startswith("```"):
        body = code.strip().split("\n")
        body = body[1:]
        if body and body[-1].strip().startswith("```"):
            body = body[:-1]
        code = "\n".join(body)
    return code.rstrip()


def reindent_like(new_code: str, original: str) -> str:
    """Ajusta la indentación del bloque nuevo a la del bloque original."""
    first = next((l for l in original.splitlines() if l.strip()), "")
    indent = first[: len(first) - len(first.lstrip())]
    return textwrap.indent(textwrap.dedent(new_code), indent) if indent else textwrap.dedent(new_code)


def apply_replacement(source: str, start: int, end: int, new_code: str) -> str:
    lines = source.splitlines()
    out = lines[: start - 1] + new_code.splitlines() + lines[end:]
    text = "\n".join(out)
    return text + ("\n" if source.endswith("\n") else "")
