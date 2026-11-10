"""Bericht je Repo als Markdown und JSON, dazu die Übersicht über alle Repos."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from collector.grype import Befund
from collector.prioritaet import BEDEUTUNG, CVSS_SCHWELLE, EPSS_SCHWELLE, FRIST, REIHENFOLGE, rang
from collector.pruefung import FEHLGESCHLAGEN, GEPRUEFT, SBOM_LEER, Ergebnis
from collector.sbom import Herkunft, Inhalt

UEBERSICHT = "SUMMARY.md"
LEER = "-"
# Nicht geprüfte Repos stehen in der Übersicht vor allen Befunden
STATUSRANG = {FEHLGESCHLAGEN: 0, SBOM_LEER: 1, GEPRUEFT: 2}
STATUSTEXT = {
    FEHLGESCHLAGEN: "**nicht bewertet**: der Scan ist fehlgeschlagen, das Ergebnis sagt nichts über das Repo",
    SBOM_LEER: "**SBOM leer**: Syft hat keine Pakete gefunden. Das ist kein sauberes Ergebnis, "
    "sondern heißt meist, dass die SBOM-Erzeugung im Repo falsch eingerichtet ist",
}


def sortiert(befunde: list[Befund]) -> list[Befund]:
    # Innerhalb einer Stufe zuerst nach EPSS, dann nach CVSS, wie in SecScan
    return sorted(befunde, key=lambda b: (rang(b.prioritaet), -(b.epss or 0.0), -(b.cvss or 0.0), b.kennung))


def zaehle(befunde: list[Befund]) -> dict[str, int]:
    anzahl = Counter(b.prioritaet for b in befunde)
    return {stufe: anzahl.get(stufe, 0) for stufe in REIHENFOLGE}


def schreibe_repo(herkunft: Herkunft, ergebnis: Ergebnis, stand: dict, ziel: Path) -> None:
    ziel.parent.mkdir(parents=True, exist_ok=True)
    ergebnis.befunde = sortiert(ergebnis.befunde)
    inhalt = {
        "herkunft": asdict(herkunft),
        "status": ergebnis.status,
        "pakete": ergebnis.inhalt.pakete,
        "ci_actions": ergebnis.inhalt.ci_actions,
        "fehler": ergebnis.fehler,
        "stand": stand,
        "anzahl": zaehle(ergebnis.befunde),
        "befunde": [asdict(b) for b in ergebnis.befunde],
    }
    # Kein with_suffix: Repo-Namen dürfen Punkte enthalten
    (ziel.parent / f"{ziel.name}.json").write_text(
        json.dumps(inhalt, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (ziel.parent / f"{ziel.name}.md").write_text(repo_markdown(herkunft, ergebnis, stand), encoding="utf-8")


def repo_markdown(herkunft: Herkunft, ergebnis: Ergebnis, stand: dict) -> str:
    zeilen = [
        f"# {herkunft.repo}",
        "",
        f"- Commit: `{herkunft.commit[:12] or LEER}` auf `{herkunft.ref or LEER}`, {herkunft.zeit or LEER}",
        f"- Autor: {herkunft.autor or LEER} {_mail(herkunft.autor_mail)}".rstrip(),
        f"- Status: {ergebnis.status}, {_inhalt(ergebnis.inhalt)} in der SBOM",
        "",
        *_ergebnisteil(ergebnis),
        "",
        *_legende(stand),
    ]
    return "\n".join(zeilen) + "\n"


def _ergebnisteil(ergebnis: Ergebnis) -> list[str]:
    if ergebnis.status != GEPRUEFT:
        fehler = ["", "```", ergebnis.fehler, "```"] if ergebnis.fehler else []
        return [STATUSTEXT[ergebnis.status] + ".", *fehler]
    if not ergebnis.befunde:
        return [
            f"Keine Befunde. Geprüft wurden {_inhalt(ergebnis.inhalt)}; die Positivkontrolle "
            "dieses Laufs hat die erwarteten CVEs gefunden, der Scan hat also funktioniert."
        ]
    anzahl = zaehle(ergebnis.befunde)
    return [
        f"Befunde: {len(ergebnis.befunde)}, " + ", ".join(f"{stufe} {anzahl[stufe]}" for stufe in REIHENFOLGE),
        "",
        "| Priorität | Frist | CVE | Paket | Version | Behoben in | CVSS | EPSS | KEV |",
        "|---|---|---|---|---|---|---|---|---|",
        *(_befundzeile(b) for b in ergebnis.befunde),
    ]


def _inhalt(inhalt: Inhalt) -> str:
    return f"{inhalt.pakete} Pakete und {inhalt.ci_actions} CI-Actions"


def _befundzeile(b: Befund) -> str:
    kennung = b.kennung + (f" ({b.alias})" if b.alias else "")
    cvss = f"{b.cvss:.1f} (v{b.cvss_version})" if b.cvss is not None else LEER
    epss = f"{b.epss:.3f}" if b.epss is not None else LEER
    return (
        f"| {b.prioritaet} | {FRIST[b.prioritaet]} | {kennung} | {b.paket} | {b.version} | "
        f"{b.behoben_in or LEER} | {cvss} | {epss} | {'ja' if b.kev else 'nein'} |"
    )


def _legende(stand: dict) -> list[str]:
    return [
        "## Einordnung",
        "",
        f"KEV geht vor, danach entscheiden EPSS ab {EPSS_SCHWELLE} und CVSS ab {CVSS_SCHWELLE} über das Feld "
        "(Schema nach CVE Prioritizer, übernommen aus SecScan). Ohne EPSS-Wert zählt EPSS als 0.",
        "",
        *(f"- **{stufe}** {BEDEUTUNG[stufe]}" for stufe in REIHENFOLGE),
        "",
        "## Datenstand",
        "",
        *(f"- {name}: {wert or LEER}" for name, wert in stand.items()),
    ]


def _mail(adresse: str) -> str:
    return f"<{adresse}>" if adresse else ""


def schreibe_uebersicht(bericht_ordner: Path) -> None:
    berichte = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(bericht_ordner.rglob("*.json"))]
    berichte.sort(key=_dringlichkeit)
    zeilen = [
        "# Übersicht",
        "",
        "Zuerst Repos, die nicht geprüft werden konnten, dann nach der höchsten vorkommenden Priorität.",
        "",
        "| Repo | Status | Autor | Abhängigkeiten geändert | " + " | ".join(REIHENFOLGE) + " | EPSS-Stand |",
        "|---|---|---|---|" + "---|" * len(REIHENFOLGE) + "---|",
        *(_uebersichtszeile(b) for b in berichte),
    ]
    (bericht_ordner / UEBERSICHT).write_text("\n".join(zeilen) + "\n", encoding="utf-8")


def _dringlichkeit(bericht: dict) -> tuple:
    anzahl = bericht["anzahl"]
    hoechste = next((rang(s) for s in REIHENFOLGE if anzahl.get(s)), len(REIHENFOLGE))
    return (
        STATUSRANG.get(bericht.get("status"), 0),
        hoechste,
        *(-anzahl.get(s, 0) for s in REIHENFOLGE),
        bericht["herkunft"]["repo"],
    )


def _uebersichtszeile(bericht: dict) -> str:
    herkunft, anzahl = bericht["herkunft"], bericht["anzahl"]
    verweis = f"[{herkunft['repo']}]({herkunft['repo']}.md)"
    status = bericht.get("status", LEER)
    if status != GEPRUEFT:
        status = f"**{status}**"
    return (
        f"| {verweis} | {status} | {herkunft['autor'] or LEER} | {herkunft['zeit'][:10] or LEER} | "
        + " | ".join(str(anzahl.get(s, 0)) for s in REIHENFOLGE)
        + f" | {bericht['stand'].get('EPSS', LEER)} |"
    )
