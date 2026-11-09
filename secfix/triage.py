"""Etapa 3: el LLM clasifica cada hallazgo como verdadero o falso positivo."""
from __future__ import annotations

import pathlib

from secfix.context import enclosing_block, get_lines, module_header, numbered
from secfix.models import Finding

PROMPT = (pathlib.Path(__file__).parent / "prompts" / "triage.md").read_text(encoding="utf-8")


def build_user_prompt(f: Finding, source: str) -> str:
    start, end = enclosing_block(source, f.line)
    return (
        f"## Hallazgo\n- Regla: {f.short_rule}\n- CWE: {f.cwe}\n- Archivo: {f.path}\n"
        f"- Línea: {f.line}\n- Mensaje: {f.message}\n"
        f"- Traza de datos: {f.trace or 'no disponible'}\n\n"
        f"## Encabezado del módulo (imports, constantes y funciones auxiliares)\n"
        f"<<<CODIGO\n{module_header(source)}\nCODIGO>>>\n\n"
        f"## Función que contiene el hallazgo (con números de línea)\n"
        f"<<<CODIGO\n{numbered(get_lines(source, start, end), start)}\nCODIGO>>>\n"
    )


def triage(f: Finding, source: str, llm) -> Finding:
    data = llm.chat_json(PROMPT, build_user_prompt(f, source))
    verdict = str(data.get("verdict", "TP")).upper().strip()
    f.verdict = "FP" if verdict == "FP" else "TP"
    try:
        f.confidence = max(0.0, min(1.0, float(data.get("confidence", 0.5))))
    except (TypeError, ValueError):
        f.confidence = 0.5
    f.justification = str(data.get("justification", ""))[:600]
    return f
