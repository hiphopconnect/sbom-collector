"""Herkunft einer SBOM: Repo, Commit und Autor, vom Workflow des Quell-Repos eingebettet."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

PRAEFIX = "sbom-collector:"
ENDUNG = ".cdx.json"


@dataclass
class Herkunft:
    repo: str
    commit: str
    ref: str
    autor: str
    autor_mail: str
    zeit: str


def lies_herkunft(pfad: Path, sbom_ordner: Path) -> Herkunft:
    dokument = json.loads(pfad.read_text(encoding="utf-8"))
    eigenschaften = {
        eintrag["name"].removeprefix(PRAEFIX): eintrag.get("value", "")
        for eintrag in dokument.get("metadata", {}).get("properties", [])
        if eintrag.get("name", "").startswith(PRAEFIX)
    }
    return Herkunft(
        repo=eigenschaften.get("repo") or repo_aus_pfad(pfad, sbom_ordner),
        commit=eigenschaften.get("commit", ""),
        ref=eigenschaften.get("ref", ""),
        autor=eigenschaften.get("autor", ""),
        autor_mail=eigenschaften.get("autor_mail", ""),
        zeit=eigenschaften.get("zeit", ""),
    )


def repo_aus_pfad(pfad: Path, sbom_ordner: Path) -> str:
    # sboms/<owner>/<repo>.cdx.json wird zu <owner>/<repo>
    return pfad.relative_to(sbom_ordner).as_posix().removesuffix(ENDUNG)


def alle_sboms(sbom_ordner: Path) -> list[Path]:
    return sorted(sbom_ordner.rglob(f"*{ENDUNG}"))


def komponenten(pfad: Path) -> int:
    """Zahl der Komponenten, auch verschachtelte; 0 heißt, Syft hat nichts gefunden."""
    offen = list(json.loads(pfad.read_text(encoding="utf-8")).get("components", []))
    anzahl = 0
    while offen:
        komponente = offen.pop()
        anzahl += 1
        offen.extend(komponente.get("components", []))
    return anzahl
