"""EPSS und KEV als Download statt API, damit viele SBOMs schnell bewertet werden."""

from __future__ import annotations

import csv
import gzip
import json
import urllib.request
from dataclasses import dataclass
from pathlib import Path

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_DATEI = "epss.csv.gz"
KEV_DATEI = "kev.json"
ZEITLIMIT_S = 120
KENNUNG = "sbom-collector"


@dataclass
class Kataloge:
    epss: dict[str, tuple[float, float]]
    epss_stand: str
    kev: set[str]
    kev_stand: str


def lade(ordner: Path) -> None:
    ordner.mkdir(parents=True, exist_ok=True)
    for url, name in ((EPSS_URL, EPSS_DATEI), (KEV_URL, KEV_DATEI)):
        _lade_datei(url, ordner / name)


def _lade_datei(url: str, ziel: Path) -> None:
    anfrage = urllib.request.Request(url, headers={"User-Agent": KENNUNG})
    zwischen = ziel.with_suffix(ziel.suffix + ".teil")
    with urllib.request.urlopen(anfrage, timeout=ZEITLIMIT_S) as antwort:
        zwischen.write_bytes(antwort.read())
    # Erst nach vollständigem Download ersetzen, sonst bliebe ein halber Katalog liegen
    zwischen.replace(ziel)


def oeffne(ordner: Path) -> Kataloge:
    epss_pfad, kev_pfad = ordner / EPSS_DATEI, ordner / KEV_DATEI
    for pfad in (epss_pfad, kev_pfad):
        if not pfad.exists():
            raise FileNotFoundError(f"{pfad} fehlt, erst 'python3 -m collector kataloge' ausführen")
    epss, epss_stand = lies_epss(epss_pfad)
    kev, kev_stand = lies_kev(kev_pfad)
    return Kataloge(epss, epss_stand, kev, kev_stand)


def lies_epss(pfad: Path) -> tuple[dict[str, tuple[float, float]], str]:
    with gzip.open(pfad, "rt", encoding="utf-8") as datei:
        # Erste Zeile: #model_version:v2026.06.15,score_date:2026-11-06T12:00:23Z
        kopf = datei.readline().lstrip("#").strip()
        stand = dict(teil.split(":", 1) for teil in kopf.split(",")).get("score_date", "")
        werte = {zeile["cve"]: (float(zeile["epss"]), float(zeile["percentile"])) for zeile in csv.DictReader(datei)}
    return werte, stand


def lies_kev(pfad: Path) -> tuple[set[str], str]:
    katalog = json.loads(pfad.read_text(encoding="utf-8"))
    kennungen = {eintrag["cveID"] for eintrag in katalog["vulnerabilities"]}
    return kennungen, katalog.get("dateReleased", "")
