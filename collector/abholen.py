"""SBOMs aus den Quell-Repos abholen: jedes Repo legt seine SBOM als Datei bei sich ab."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path

from collector.sbom import ENDUNG

# Auf GitHub Enterprise Server setzt Actions GITHUB_API_URL auf die eigene Instanz
STANDARD_API = "https://api.github.com"
QUELL_DATEI = "sbom.cdx.json"
ZEITLIMIT_S = 60
SEITENGROESSE = 100
NAECHSTE_SEITE = re.compile(r'<([^>]+)>;\s*rel="next"')
NICHT_GEFUNDEN = 404


class GitHub:
    """Lesender Zugriff auf die REST-API; ohne Token nur öffentliche Repos."""

    def __init__(self, token: str = "", api: str = STANDARD_API) -> None:
        self.api = api.rstrip("/")
        self.kopf = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            self.kopf["Authorization"] = f"Bearer {token}"

    def liste(self, pfad: str) -> list[dict]:
        eintraege, url = [], f"{self.api}{pfad}?per_page={SEITENGROESSE}"
        while url:
            inhalt, link = self._hole(url, self.kopf)
            eintraege.extend(json.loads(inhalt))
            treffer = NAECHSTE_SEITE.search(link)
            url = treffer.group(1) if treffer else ""
        return eintraege

    def datei(self, repo: str, pfad: str) -> bytes | None:
        kopf = {**self.kopf, "Accept": "application/vnd.github.raw"}
        try:
            inhalt, _ = self._hole(f"{self.api}/repos/{repo}/contents/{pfad}", kopf)
        except urllib.error.HTTPError as fehler:
            if fehler.code == NICHT_GEFUNDEN:
                return None
            raise
        return inhalt

    def _hole(self, url: str, kopf: dict) -> tuple[bytes, str]:
        anfrage = urllib.request.Request(url, headers=kopf)
        with urllib.request.urlopen(anfrage, timeout=ZEITLIMIT_S) as antwort:
            return antwort.read(), antwort.headers.get("Link", "")


def lies_quellen(pfad: Path) -> list[str]:
    zeilen = (zeile.split("#", 1)[0].strip() for zeile in pfad.read_text(encoding="utf-8").splitlines())
    return [zeile for zeile in zeilen if zeile]


def repos_aus(quelle: str, github: GitHub) -> list[str]:
    # "owner/repo" steht für sich, "owner" für alle nicht archivierten Repos des Kontos
    if "/" in quelle:
        return [quelle]
    try:
        repos = github.liste(f"/orgs/{quelle}/repos")
    except urllib.error.HTTPError as fehler:
        if fehler.code != NICHT_GEFUNDEN:
            raise
        repos = github.liste(f"/users/{quelle}/repos")
    return sorted(r["full_name"] for r in repos if not r.get("archived"))


def abholen(quellen: list[str], sbom_ordner: Path, github: GitHub) -> list[Path]:
    """Holt die SBOM jedes Repos und gibt die neuen oder geänderten zurück."""
    geaendert = []
    for repo in (r for quelle in quellen for r in repos_aus(quelle, github)):
        inhalt = github.datei(repo, QUELL_DATEI)
        if inhalt is None:
            continue
        ziel = sbom_ordner / f"{repo}{ENDUNG}"
        if ziel.exists() and ziel.read_bytes() == inhalt:
            continue
        ziel.parent.mkdir(parents=True, exist_ok=True)
        ziel.write_bytes(inhalt)
        geaendert.append(ziel)
    return geaendert
