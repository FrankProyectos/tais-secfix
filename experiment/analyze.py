"""Calcula las métricas del experimento a partir de experiment/results/runs.jsonl.

Genera:
  experiment/results/summary.md    tablas listas para el informe del Hito 2
  experiment/results/summary.csv   métricas por configuración y repetición
  experiment/results/*.png         gráficos (si matplotlib está instalado)
"""
from __future__ import annotations

import csv
import json
import pathlib
import statistics as st
from collections import defaultdict

RESULTS = pathlib.Path(__file__).resolve().parent / "results"


def confusion(rows):
    tp = sum(r["predicted"] and r["label"] for r in rows)
    fp = sum(r["predicted"] and not r["label"] for r in rows)
    fn = sum((not r["predicted"]) and r["label"] for r in rows)
    tn = sum((not r["predicted"]) and not r["label"] for r in rows)
    return tp, fp, fn, tn


def metrics(rows):
    tp, fp, fn, tn = confusion(rows)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    vuln = [r for r in rows if r["label"]]
    detected = [r for r in vuln if r["predicted"]]
    fixed = sum(r["fixed"] for r in vuln)
    return {
        "n": len(rows), "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "precision": prec, "recall": rec, "f1": f1,
        "accuracy": (tp + tn) / len(rows) if rows else 0.0,
        "fix_rate": fixed / len(vuln) if vuln else 0.0,
        "fix_rate_detected": fixed / len(detected) if detected else 0.0,
        "broke_function": sum(r["patch_broke_function"] for r in rows),
        "sec_per_case": st.mean(r["seconds"] for r in rows) if rows else 0.0,
        "llm_calls_per_case": st.mean(r["llm_calls"] for r in rows) if rows else 0.0,
        "tokens_per_case": st.mean(r["prompt_tokens"] + r["completion_tokens"] for r in rows) if rows else 0.0,
    }


def fmt(values, pct=True):
    if not values:
        return "—"
    m = st.mean(values)
    sd = st.stdev(values) if len(values) > 1 else 0.0
    return f"{m * 100:.1f} % ± {sd * 100:.1f}" if pct else f"{m:.1f} ± {sd:.1f}"


def main():
    # Lee runs.jsonl y cualquier runs_*.jsonl (p. ej. repeticiones corridas desde otras cuentas)
    rows, seen = [], set()
    for path in sorted(RESULTS.glob("runs*.jsonl")):
        for l in path.read_text(encoding="utf-8").splitlines():
            if l.strip():
                r = json.loads(l)
                key = (r["case"], r["config"], r["rep"])
                if key not in seen:
                    seen.add(key)
                    rows.append(r)
    by_cfg_rep = defaultdict(list)
    for r in rows:
        by_cfg_rep[(r["config"], r["rep"])].append(r)

    per_rep = []
    for (cfg, rep), rs in sorted(by_cfg_rep.items()):
        per_rep.append({"config": cfg, "rep": rep, **metrics(rs)})
    with (RESULTS / "summary.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(per_rep[0].keys()))
        w.writeheader()
        w.writerows(per_rep)

    configs = sorted({p["config"] for p in per_rep})
    agg = {c: [p for p in per_rep if p["config"] == c] for c in configs}
    md = ["# Resultados del experimento", "",
          f"Casos: {len({r['case'] for r in rows})} · repeticiones: "
          + ", ".join(f"{c}={len(agg[c])}" for c in configs), "",
          "## Detección y reparación (media ± desviación estándar entre repeticiones)", "",
          "| Métrica | " + " | ".join(configs) + " |", "|---|" + "---|" * len(configs)]
    for key, label, pct in [("precision", "Precisión", True), ("recall", "Recall (exhaustividad)", True),
                            ("f1", "F1", True), ("accuracy", "Exactitud", True),
                            ("FP", "Falsos positivos (casos)", False), ("FN", "Falsos negativos (casos)", False),
                            ("fix_rate", "Tasa de reparación (sobre casos vulnerables)", True),
                            ("fix_rate_detected", "Tasa de reparación (sobre vulnerables detectados)", True),
                            ("broke_function", "Parches candidatos que rompieron la funcionalidad", False),
                            ("sec_per_case", "Tiempo por caso (s)", False),
                            ("llm_calls_per_case", "Llamadas al LLM por caso", False),
                            ("tokens_per_case", "Tokens por caso", False)]:
        md.append(f"| {label} | " + " | ".join(fmt([p[key] for p in agg[c]], pct) for c in configs) + " |")

    if "C0" in agg:
        base_fp = st.mean(p["FP"] for p in agg["C0"])
        for c in configs:
            if c != "C0" and base_fp:
                red = (base_fp - st.mean(p["FP"] for p in agg[c])) / base_fp
                md += ["", f"Reducción de falsos positivos de {c} frente a C0: **{red * 100:.1f} %**."]

    md += ["", "## Desglose por CWE (todas las repeticiones juntas)", "",
           "| CWE | Config | Precisión | Recall | F1 | Tasa de reparación |", "|---|---|---|---|---|---|"]
    for cwe in sorted({r["cwe"] for r in rows}):
        for c in configs:
            rs = [r for r in rows if r["cwe"] == cwe and r["config"] == c]
            m = metrics(rs)
            md.append(f"| {cwe} | {c} | {m['precision']*100:.1f} % | {m['recall']*100:.1f} % | "
                      f"{m['f1']*100:.1f} % | {m['fix_rate']*100:.1f} % |")

    md += ["", "## Resultado por caso", "", "| Caso | Vulnerable | " + " | ".join(configs) + " |",
           "|---|---|" + "---|" * len(configs)]
    cases = sorted({r["case"] for r in rows})
    for case in cases:
        cells = []
        label = next(r["label"] for r in rows if r["case"] == case)
        for c in configs:
            rs = [r for r in rows if r["case"] == case and r["config"] == c]
            det = sum(r["predicted"] for r in rs)
            fx = sum(r["fixed"] for r in rs)
            cells.append(f"detectado {det}/{len(rs)}" + (f", reparado {fx}/{len(rs)}" if c != "C0" else ""))
        md.append(f"| `{case}` | {'sí' if label else 'no'} | " + " | ".join(cells) + " |")
    (RESULTS / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return
    keys = [("precision", "Precisión"), ("recall", "Recall"), ("f1", "F1"), ("fix_rate", "Reparación")]
    fig, ax = plt.subplots(figsize=(7, 3.6))
    width = 0.8 / len(configs)
    for i, c in enumerate(configs):
        vals = [st.mean(p[k] for p in agg[c]) * 100 for k, _ in keys]
        ax.bar([j + i * width for j in range(len(keys))], vals, width, label=c)
    ax.set_xticks([j + width * (len(configs) - 1) / 2 for j in range(len(keys))])
    ax.set_xticklabels([l for _, l in keys])
    ax.set_ylabel("%")
    ax.set_ylim(0, 105)
    ax.legend(frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(RESULTS / "metricas.png", dpi=160)


if __name__ == "__main__":
    main()
