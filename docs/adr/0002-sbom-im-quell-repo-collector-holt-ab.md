# 0002 - SBOM liegt im Quell-Repo, der Collector holt sie ab

- Status: akzeptiert
- Datum: 2026-11-10

## Kontext

Nach ADR 0001 schickt jedes Quell-Repo seine SBOM mit einem eigenen Token in den Collector. Bei sehr vielen Repos heißt das: in jedem Repo ein Secret, das gepflegt und erneuert werden muss, und jedes Repo braucht Schreibrechte auf den Collector. Ein Zeitplan in den Quell-Repos hilft nicht, weil GitHub geplante Workflows in öffentlichen Repos nach 60 Tagen ohne Commit abschaltet.

## Entscheidung

- Das Quell-Repo erzeugt bei jedem Push mit Syft `sbom.cdx.json` (CycloneDX) und committet sie mit dem eingebauten `GITHUB_TOKEN` ins eigene Repo, aber nur, wenn sich die Abhängigkeiten geändert haben. Zeitstempel, Seriennummer und die eingebettete Herkunft zählen dabei nicht als Änderung.
- Die Herkunft (Repo, Commit, Ref, Autor, Zeit) beschreibt damit den Commit, der die Abhängigkeiten zuletzt geändert hat.
- Der Collector holt täglich nach Zeitplan die `sbom.cdx.json` aller Repos aus `quellen.txt` über die REST-API ab, bewertet neue und geänderte SBOMs und montags alle.
- Für öffentliche Quell-Repos reicht der Token des Workflows; für private ein einziger Token oder eine GitHub App mit Lesezugriff im Collector.

## Betrachtete Alternativen

- **Push per Token je Repo (ADR 0001):** Bericht nach einer Minute, aber ein Secret in jedem Repo und Schreibzugriff auf den Collector.
- **Zeitplan in jedem Quell-Repo:** braucht weiterhin ein Secret und fällt in öffentlichen Repos nach 60 Tagen ohne Commit aus.
- **Wöchentlicher Commit der SBOM mit Zeitstempel, um das Repo aktiv zu halten:** Commits ohne Inhalt in jedem Repo.
- **SBOM-Export des Dependency Graph von GitHub:** kein Workflow nötig, kennt aber nur Manifest- und Lockfiles und liefert SPDX statt CycloneDX.

## Konsequenzen

- Kein Secret in den Quell-Repos, kein Schreibzugriff von außen auf den Collector.
- Die SBOM liegt versioniert neben dem Code.
- Ein Bericht ist bis zu einen Tag alt.
- Ist `main` geschützt, braucht der Bot eine Ausnahme, oder die SBOM liegt auf einem eigenen Branch.
- Löscht ein Repo seine SBOM, bleibt die letzte im Collector liegen, bis sie von Hand entfernt wird.
