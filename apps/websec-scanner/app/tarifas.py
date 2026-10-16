"""
tarifas — Estimación económica del modelo "pago por hallazgo" de Almenasec.

Reglas (las mismas que publica la web en /pago-por-hallazgo):
  • Cuota mínima: se paga siempre en la primera auditoría de un objetivo.
  • Cada vulnerabilidad ÚNICA se cobra según su tramo CVSS v3.1.
  • Los hallazgos Info y los duplicados no se cobran.
  • Tope máximo: el total nunca lo supera.
  • Re-escaneos del mismo objetivo (re-test, monitorización): solo se cobran los
    hallazgos NUEVOS frente al escaneo anterior, sin cuota mínima. Lo que persiste
    ya se facturó.

Es una ESTIMACIÓN previa a la validación manual: en el presupuesto final solo
cuentan los hallazgos confirmados. Importes en euros, sin IVA, configurables por
variables de entorno para ajustarlos a cada acuerdo.
"""
from __future__ import annotations

import os

from . import report


def _eur(var: str, defecto: float) -> float:
    try:
        return float(os.environ.get(var, defecto))
    except ValueError:
        return defecto


def tabla() -> dict:
    return {
        "cuota_minima": _eur("PRECIO_CUOTA_MINIMA", 190),
        "critica": _eur("PRECIO_CRITICA", 250),
        "alta": _eur("PRECIO_ALTA", 150),
        "media": _eur("PRECIO_MEDIA", 75),
        "baja": _eur("PRECIO_BAJA", 25),
        "info": 0.0,
        "tope": _eur("PRECIO_TOPE", 690),
    }


def _unicos(hallazgos: list[dict]) -> list[dict]:
    vistos: dict[str, dict] = {}
    for f in hallazgos:
        vistos.setdefault(report.clave(f), f)
    return list(vistos.values())


def presupuesto(actual: dict, anterior: dict | None = None) -> dict:
    """Desglose económico de un resultado. Con `anterior`, solo cuenta lo nuevo."""
    t = tabla()
    primer = anterior is None
    hallazgos = _unicos(report.hallazgos_de(actual))
    if not primer:
        hallazgos = report.diff(anterior, actual)["nuevos"]
    lineas, subtotal = [], 0.0
    for tramo in ("critica", "alta", "media", "baja"):
        n = sum(1 for f in hallazgos if f.get("severidad_cvss") == tramo)
        if n:
            lineas.append({"tramo": tramo, "unidades": n, "precio": t[tramo], "importe": n * t[tramo]})
            subtotal += n * t[tramo]
    cuota = t["cuota_minima"] if primer else 0.0
    bruto = cuota + subtotal
    total = min(bruto, t["tope"])
    return {
        "modalidad": "primer-escaneo" if primer else "re-escaneo",
        "cuota_minima": cuota,
        "lineas": lineas,
        "subtotal_hallazgos": subtotal,
        "tope": t["tope"],
        "tope_aplicado": bruto > t["tope"],
        "total": total,
        "moneda": "EUR",
        "nota": ("Estimación previa a la validación manual; solo se facturan hallazgos únicos y confirmados. "
                 "Info y duplicados no se cobran. Importes sin IVA."
                 + ("" if primer else " Re-escaneo: solo cuentan los hallazgos nuevos, sin cuota mínima.")),
    }


def aplicar(res: dict, anterior: dict | None) -> dict:
    """Añade res['presupuesto'] (anterior = fila de store.previous_scan o None)."""
    res["presupuesto"] = presupuesto(res, (anterior or {}).get("result"))
    return res
