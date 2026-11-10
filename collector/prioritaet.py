"""Priorität P1+ bis P4 aus KEV, EPSS und CVSS.

Übernommen aus SecScan (core/priority.py, MIT-Lizenz). Schema und Schwellen stammen
aus dem Projekt CVE Prioritizer; FIRST selbst nennt keine feste EPSS-Schwelle.
"""

from __future__ import annotations

EPSS_SCHWELLE = 0.2
CVSS_SCHWELLE = 6.0

REIHENFOLGE = ["P1+", "P1", "P2", "P3", "P4", "P?"]

BEDEUTUNG = {
    "P1+": "im KEV-Katalog, wird nachweislich ausgenutzt",
    "P1": "hohe Schwere und hohe Ausnutzungswahrscheinlichkeit",
    "P2": "hohe Schwere, niedrige Ausnutzungswahrscheinlichkeit",
    "P3": "geringe Schwere, hohe Ausnutzungswahrscheinlichkeit",
    "P4": "geringe Schwere, niedrige Ausnutzungswahrscheinlichkeit",
    "P?": "kein CVSS-Wert, von Hand zu bewerten",
}

# Empfohlene Fristen wie in SecScan
FRIST = {
    "P1+": "24 bis 72 Stunden",
    "P1": "7 Tage",
    "P2": "30 Tage",
    "P3": "30 Tage",
    "P4": "90 Tage",
    "P?": "von Hand bewerten",
}


def prioritaet(kev: bool, epss: float | None, cvss: float | None) -> str:
    # KEV hat immer Vorrang, unabhängig von der Schwere
    if kev:
        return "P1+"
    if cvss is None:
        return "P?"
    hoher_epss = (epss or 0.0) >= EPSS_SCHWELLE
    hoher_cvss = cvss >= CVSS_SCHWELLE
    if hoher_epss and hoher_cvss:
        return "P1"
    if hoher_cvss:
        return "P2"
    if hoher_epss:
        return "P3"
    return "P4"


def rang(stufe: str) -> int:
    return REIHENFOLGE.index(stufe)
