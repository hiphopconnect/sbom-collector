# Projektstatus

Stand: 2026-11-10
Phase: MVP

## Aktueller Stand

Prototyp lokal gebaut (ADR 0002): Das Test-Repo `sbom-testrepo` erzeugt bei jedem Push mit Syft `sbom.cdx.json` und committet sie ins eigene Repo, wenn sich die Abhängigkeiten geändert haben. Der Collector holt die SBOMs täglich ab (`quellen.txt`), bewertet sie mit Grype, EPSS und KEV nach dem Schema aus SecScan und schreibt Berichte je Repo und eine Übersicht. Positivkontrolle in jedem Lauf und Status je Repo (geprüft, SBOM leer, nicht bewertet), damit "keine Befunde" belegt ist. 23 Tests und ruff ohne Befund; Abruf gegen die echte GitHub-API und Laden von EPSS und KEV lokal geprüft. Noch nicht auf GitHub gelaufen, Grype noch nicht echt ausgeführt.

## In Arbeit

- Erster Lauf auf GitHub: beide Repos anlegen und pushen, Workflow-Rechte auf "Read and write" stellen.

## Nächste Schritte

1. Repos `sbom-collector` und `sbom-testrepo` auf GitHub anlegen und pushen, dann der Ablauf: Collector von Hand starten (Kontrolle muss bestehen), Test-Repo pushen, Gegenproben ohne Funde und mit leerer `requirements.txt`.
2. Echte Grype-Ausgabe gegen die Annahmen in `tests/beispiel-grype.json` prüfen, vor allem `cvss[].source` und `grype db status -o json`.
3. Prüfen, ob `.syft.yaml` von `anchore/sbom-action` gelesen wird (sonst erzeugt jeder Push einen SBOM-Commit).
4. Beispiel-ZIP `sbom-pipeline-example` aus dem claude.ai-Konto abgleichen.
5. Für die Firma: GitHub App mit Lesezugriff statt Token; Hülle für Jenkins.

## Offene Fragen / Blocker

- Läuft es in der Firma auf GitHub Enterprise oder Jenkins, und gibt es dort eine GitHub App?

## Bekannte Probleme

- Die Testdaten für Grype sind nach dem dokumentierten Ausgabeformat geschrieben, nicht aus einem echten Lauf.
- Die Grype-Datenbank wird bei jedem Lauf neu geladen, kein Cache.
- Löscht ein Quell-Repo seine SBOM, bleibt die letzte im Collector liegen.

## Letzte Sessions

- 2026-11-10: Vision, Prototyp mit Push (ADR 0001), umgebaut auf Ablage im Quell-Repo und Abholen (ADR 0002)
