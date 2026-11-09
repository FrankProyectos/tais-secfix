"""Etapa 4: el LLM propone la función corregida para un grupo de hallazgos."""
from __future__ import annotations

import pathlib

from secfix.context import clean_code, module_header, reindent_like
from secfix.models import RepairGroup

PROMPT = (pathlib.Path(__file__).parent / "prompts" / "repair.md").read_text(encoding="utf-8")


def build_user_prompt(group: RepairGroup, source: str, feedback: str | None) -> str:
    vulns = "\n".join(
        f"- {f.cwe} ({f.short_rule}) en la línea {f.line}: {f.message}"
        + (f" | Análisis previo: {f.justification}" if f.justification else "")
        for f in group.findings
    )
    text = (
        f"## Vulnerabilidades confirmadas\n{vulns}\n\n"
        f"## Encabezado del módulo (solo lectura)\n<<<CODIGO\n{module_header(source)}\nCODIGO>>>\n\n"
        f"## Función a corregir (líneas {group.start}-{group.end} de {group.path})\n"
        f"<<<CODIGO\n{group.original_code}\nCODIGO>>>\n"
    )
    if feedback:
        text += (f"\n## Tu intento anterior NO pasó la validación automática\n{feedback}\n"
                 "Corrige el problema y devuelve de nuevo la función completa.\n")
    return text


def propose_fix(group: RepairGroup, source: str, llm, feedback: str | None = None) -> RepairGroup:
    data = llm.chat_json(PROMPT, build_user_prompt(group, source, feedback))
    code = clean_code(str(data.get("fixed_code", "")))
    group.fixed_code = reindent_like(code, group.original_code) if code else None
    group.explanation = str(data.get("explanation", ""))[:800]
    group.attempts += 1
    return group
