# Projektstatus

Stand: 2026-11-10
Phase: MVP

## Aktueller Stand

Erster Durchgang auf GitHub am 2026-11-10 erfolgreich (ADR 0002): `sbom-testrepo` erzeugt bei jedem Push mit Syft `sbom.cdx.json` und committet sie nur bei geänderten Abhängigkeiten (leerer Commit erzeugt keinen SBOM-Commit). Der Collector holt sie ab, die Positivkontrolle besteht (Log4Shell mit CVSS 10, EPSS, KEV), das Test-Repo ergibt 6 Pakete, 2 CI-Actions und 127 Befunde: P1+ 1 (CVE-2023-4863, Pillow), P1 7, P2 88, P4 30, P? 1 (GHSA ohne CVE). Berichte unter `reports/`.

Gegenproben: mit aktuellen Versionen "geprüft, 0 Befunde"; ohne Pakete ergab sich zunächst "geprüft" statt "SBOM leer", weil Dateieinträge und CI-Actions als Komponenten zählten. Korrigiert: gezählt werden nur Pakete der Anwendung, CI-Actions getrennt; danach ergibt die Probe "SBOM leer" und einen roten Lauf. Die API-Adresse kommt aus `GITHUB_API_URL`, damit es auch auf GitHub Enterprise Server läuft. Anleitung zum Übertragen in `docs/uebertragen.md`; Vorführung im Browser mit zwei vorbereiteten Pull Requests im Test-Repo.

## In Arbeit

- Vorführung vorbereiten: Test-Repo auf verwundbare Versionen zurücksetzen, Pull Requests "Abhängigkeiten auf aktuelle Versionen heben" und "Alle Abhängigkeiten entfernen" anlegen.

## Nächste Schritte

1. Vorführung im Browser durchspielen (README von sbom-testrepo).
2. Mit meinem früheren Entwurf `sbom-pipeline-example` abgleichen.
3. Für die Firma: GitHub App mit Lesezugriff statt Token; Hülle für Jenkins.

## Offene Fragen / Blocker

- Läuft es in der Firma auf GitHub Enterprise oder Jenkins, und gibt es dort eine GitHub App?

## Bekannte Probleme

- Grype schreibt leere Felder teils als null; die Auswertung fängt das ab, die Testdaten bilden es nach.
- Die Grype-Datenbank wird bei jedem Lauf neu geladen, kein Cache.
- Löscht ein Quell-Repo seine SBOM, bleibt die letzte im Collector liegen.

## Letzte Sessions

- 2026-11-10: Vision, Prototyp mit Push (ADR 0001), umgebaut auf Ablage im Quell-Repo und Abholen (ADR 0002), erster Durchgang auf GitHub erfolgreich
