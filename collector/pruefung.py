"""Eine SBOM prüfen und belegen, dass "keine Befunde" wirklich geprüft heißt."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from collector import grype, sbom
from collector.kataloge import Kataloge

GEPRUEFT = "geprüft"
SBOM_LEER = "SBOM leer"
FEHLGESCHLAGEN = "nicht bewertet"

KONTROLLE = Path("kontrolle/kontrolle.cdx.json")
# Log4Shell steht im KEV-Katalog und hat EPSS und CVSS, prüft also alle drei Quellen mit
LOG4SHELL = "CVE-2021-44228"
ERWARTET = {LOG4SHELL, "CVE-2018-18074"}


class KontrolleFehlgeschlagen(RuntimeError):
    """Die Kontroll-SBOM hat nicht die erwarteten Befunde geliefert; der Lauf ist ungültig."""


@dataclass
class Ergebnis:
    status: str
    komponenten: int
    befunde: list[grype.Befund] = field(default_factory=list)
    fehler: str = ""


def pruefe(pfad: Path, kataloge: Kataloge) -> Ergebnis:
    komponenten = sbom.komponenten(pfad)
    # Ohne Komponenten hat Syft nichts gefunden; das ist kein sauberes Ergebnis
    if komponenten == 0:
        return Ergebnis(SBOM_LEER, 0)
    try:
        befunde = grype.befunde(grype.scanne(pfad), kataloge)
    except (RuntimeError, ValueError) as fehler:
        return Ergebnis(FEHLGESCHLAGEN, komponenten, fehler=str(fehler))
    return Ergebnis(GEPRUEFT, komponenten, befunde)


def pruefe_kontrolle(kataloge: Kataloge, pfad: Path = KONTROLLE) -> None:
    ergebnis = pruefe(pfad, kataloge)
    if ergebnis.status != GEPRUEFT:
        raise KontrolleFehlgeschlagen(f"Kontroll-SBOM {ergebnis.status}: {ergebnis.fehler}")
    gefunden = {b.kennung: b for b in ergebnis.befunde}
    fehlend = ERWARTET - gefunden.keys()
    if fehlend:
        raise KontrolleFehlgeschlagen(f"Grype findet {', '.join(sorted(fehlend))} nicht")
    log4shell = gefunden[LOG4SHELL]
    luecken = [
        name
        for name, fehlt in (
            ("KEV", not log4shell.kev),
            ("EPSS", log4shell.epss is None),
            ("CVSS", log4shell.cvss is None),
        )
        if fehlt
    ]
    if luecken:
        raise KontrolleFehlgeschlagen(f"{LOG4SHELL} ohne {', '.join(luecken)}, Katalog oder Auswertung defekt")
