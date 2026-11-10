"""Grype gegen eine SBOM laufen lassen und die Treffer in Befunde übersetzen."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from collector.kataloge import Kataloge
from collector.prioritaet import prioritaet

NVD_QUELLE = "nvd@nist.gov"
# Wie im Bewertungswerkzeug: 3.x vor 4.0, 2.0 nur als letzte Wahl
CVSS_REIHENFOLGE = ["3.1", "3.0", "4.0", "2.0"]


@dataclass
class Befund:
    kennung: str
    alias: str
    paket: str
    version: str
    typ: str
    fundort: str
    behoben_in: str
    cvss: float | None
    cvss_version: str
    epss: float | None
    perzentil: float | None
    kev: bool
    prioritaet: str


def scanne(sbom: Path) -> dict:
    # --by-cve stellt CVE-Kennungen vor GHSA-Kennungen, soweit es eine gibt
    lauf = subprocess.run(
        ["grype", f"sbom:{sbom}", "--by-cve", "-o", "json"], capture_output=True, text=True, check=False
    )
    if lauf.returncode != 0:
        raise RuntimeError(f"grype für {sbom} fehlgeschlagen: {lauf.stderr.strip()}")
    return json.loads(lauf.stdout)


def grype_stand() -> dict:
    """Version von Grype und Stand seiner Datenbank, für den Datenstand im Bericht."""
    version = _grype_json(["grype", "version", "-o", "json"]).get("version", "")
    datenbank = _grype_json(["grype", "db", "status", "-o", "json"]).get("built", "")
    return {"Grype": version, "Grype-Datenbank": datenbank}


def _grype_json(befehl: list[str]) -> dict:
    lauf = subprocess.run(befehl, capture_output=True, text=True, check=False)
    if lauf.returncode != 0:
        return {}
    try:
        return json.loads(lauf.stdout)
    except ValueError:
        return {}


def befunde(ergebnis: dict, kataloge: Kataloge) -> list[Befund]:
    gefunden: dict[tuple[str, str, str], Befund] = {}
    for treffer in ergebnis.get("matches", []):
        befund = _befund(treffer, kataloge)
        gefunden.setdefault((befund.kennung, befund.paket, befund.version), befund)
    return list(gefunden.values())


def _befund(treffer: dict, kataloge: Kataloge) -> Befund:
    schwachstelle, artefakt = treffer["vulnerability"], treffer["artifact"]
    kennung, alias = cve_kennung(treffer)
    cvss, cvss_version = waehle_cvss(treffer, kennung)
    epss, perzentil = kataloge.epss.get(kennung, (None, None))
    kev = kennung in kataloge.kev
    return Befund(
        kennung=kennung,
        alias=alias,
        paket=artefakt["name"],
        version=artefakt.get("version", ""),
        typ=artefakt.get("type", ""),
        fundort=", ".join(ort.get("path", "") for ort in artefakt.get("locations", [])),
        behoben_in=", ".join(schwachstelle.get("fix", {}).get("versions", [])),
        cvss=cvss,
        cvss_version=cvss_version,
        epss=epss,
        perzentil=perzentil,
        kev=kev,
        prioritaet=prioritaet(kev, epss, cvss),
    )


def cve_kennung(treffer: dict) -> tuple[str, str]:
    """CVE-Kennung des Treffers und die ursprüngliche Kennung, falls sie anders lautet."""
    eigene = treffer["vulnerability"]["id"]
    if eigene.startswith("CVE-"):
        return eigene, ""
    for verwandt in treffer.get("relatedVulnerabilities", []):
        if verwandt["id"].startswith("CVE-"):
            return verwandt["id"], eigene
    # Ohne CVE bleibt der Fund mit seiner GHSA- oder OSV-Kennung drin
    return eigene, ""


def waehle_cvss(treffer: dict, kennung: str) -> tuple[float | None, str]:
    eintraege = [eintrag for quelle in _cvss_quellen(treffer, kennung) for eintrag in quelle.get("cvss", [])]
    if not eintraege:
        return None, ""
    # Die eigene Bewertung der NVD geht vor der des Herstellers, dann zählt die Version
    bester = min(eintraege, key=lambda eintrag: (eintrag.get("source") != NVD_QUELLE, _versionsrang(eintrag)))
    return bester["metrics"]["baseScore"], bester.get("version", "")


def _cvss_quellen(treffer: dict, kennung: str) -> list[dict]:
    verwandte = [v for v in treffer.get("relatedVulnerabilities", []) if v["id"] == kennung]
    return [treffer["vulnerability"], *verwandte]


def _versionsrang(eintrag: dict) -> int:
    version = eintrag.get("version", "")
    return CVSS_REIHENFOLGE.index(version) if version in CVSS_REIHENFOLGE else len(CVSS_REIHENFOLGE)
