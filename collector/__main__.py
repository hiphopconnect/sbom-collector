"""Aufruf: python3 -m collector abholen [--liste DATEI] | kataloge | bewerte [--alle | SBOM ...]"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from collector import abholen, bericht, grype, kataloge, pruefung, sbom

SBOM_ORDNER = Path("sboms")
BERICHT_ORDNER = Path("reports")
KATALOG_ORDNER = Path("kataloge")
QUELLEN = Path("quellen.txt")
# Für private Repos ein Token mit Lesezugriff, sonst reicht der Token des Workflows
TOKEN_VARIABLEN = ("SBOM_LESE_TOKEN", "GITHUB_TOKEN")


FEHLER_KONTROLLE = 2
FEHLER_REPO = 3


def bewerte(pfade: list[Path]) -> int:
    offen = kataloge.oeffne(KATALOG_ORDNER)
    stand = datenstand(offen)
    # Ohne bestandene Kontrolle wäre "keine Befunde" nicht von einem kaputten Scan zu unterscheiden
    try:
        beleg = pruefung.pruefe_kontrolle(offen)
    except pruefung.KontrolleFehlgeschlagen as fehler:
        print(f"Positivkontrolle fehlgeschlagen, keine Berichte geschrieben: {fehler}", file=sys.stderr)
        return FEHLER_KONTROLLE
    print(
        f"Positivkontrolle bestanden: {beleg.kennung} CVSS {beleg.cvss} (v{beleg.cvss_version}), "
        f"EPSS {beleg.epss}, KEV {beleg.kev}, Fix {beleg.behoben_in or '-'}"
    )
    nicht_geprueft = 0
    for pfad in pfade:
        herkunft = sbom.lies_herkunft(pfad, SBOM_ORDNER)
        ergebnis = pruefung.pruefe(pfad, offen)
        bericht.schreibe_repo(herkunft, ergebnis, stand, BERICHT_ORDNER / herkunft.repo)
        print(
            f"{herkunft.repo}: {ergebnis.status}, {ergebnis.komponenten} Komponenten, {len(ergebnis.befunde)} Befunde"
        )
        nicht_geprueft += ergebnis.status != pruefung.GEPRUEFT
    bericht.schreibe_uebersicht(BERICHT_ORDNER)
    return FEHLER_REPO if nicht_geprueft else 0


def hole(liste: Path | None) -> None:
    token = next((os.environ[name] for name in TOKEN_VARIABLEN if os.environ.get(name)), "")
    geaendert = abholen.abholen(abholen.lies_quellen(QUELLEN), SBOM_ORDNER, abholen.GitHub(token))
    for pfad in geaendert:
        print(f"neu oder geändert: {pfad}")
    if liste:
        liste.write_text("".join(f"{pfad}\n" for pfad in geaendert), encoding="utf-8")


def datenstand(offen: kataloge.Kataloge) -> dict:
    return {**grype.grype_stand(), "EPSS": offen.epss_stand, "KEV": offen.kev_stand}


def main() -> int:
    parser = argparse.ArgumentParser(prog="collector")
    befehle = parser.add_subparsers(dest="befehl", required=True)
    holen = befehle.add_parser("abholen", help="SBOMs der Repos aus quellen.txt holen")
    holen.add_argument("--liste", type=Path, help="Datei, in die die geänderten SBOMs geschrieben werden")
    befehle.add_parser("kataloge", help="EPSS und KEV herunterladen")
    bewerten = befehle.add_parser("bewerte", help="SBOMs scannen und Berichte schreiben")
    bewerten.add_argument("--alle", action="store_true", help="alle SBOMs unter sboms/")
    bewerten.add_argument("sboms", nargs="*", type=Path)
    argumente = parser.parse_args()

    if argumente.befehl == "abholen":
        hole(argumente.liste)
        return 0
    if argumente.befehl == "kataloge":
        kataloge.lade(KATALOG_ORDNER)
        return 0
    pfade = sbom.alle_sboms(SBOM_ORDNER) if argumente.alle else argumente.sboms
    # --alle ohne SBOMs läuft trotzdem, damit die Positivkontrolle die Kette prüft
    if not pfade and not argumente.alle:
        print("Keine SBOM angegeben", file=sys.stderr)
        return 1
    return bewerte(pfade)


if __name__ == "__main__":
    sys.exit(main())
