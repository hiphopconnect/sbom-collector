# 0003 - Wiederverwendbarer Workflow für die Quell-Repos

- Status: offen
- Datum: 2026-11-10

## Idee

Heute trägt jedes Quell-Repo eine vollständige Kopie von `.github/workflows/sbom.yml`. Der Workflow soll an einer Stelle liegen und in den Quell-Repos nur noch aufgerufen werden.

## Erkenntnisse

- GitHub erlaubt wiederverwendbare Workflows (`on: workflow_call`). Das Quell-Repo enthält dann nur wenige Zeilen mit `uses: <owner>/<repo>/.github/workflows/sbom.yml@<Version>`.
- Änderungen, etwa eine neue Version von Syft oder eine Anpassung beim Einbetten der Herkunft, gelten dann für alle Repos, die auf die neue Version zeigen.
- Der Aufruf sollte auf eine feste Version (Tag oder Commit-SHA) zeigen, nicht auf `main`, damit eine Änderung nicht ungeprüft in alle Repos läuft.
- Der Workflow muss weiterhin im Quell-Repo committen dürfen; die Rechte (`contents: write`) werden im aufrufenden Workflow gesetzt.
- `.syft.yaml` bleibt im Quell-Repo, weil Syft sie dort im Arbeitsverzeichnis sucht; alternativ übergibt der Workflow die Ausschlüsse selbst.
- Für das Verteilen auf viele Repos braucht es zusätzlich einen Weg, die kurze Datei in jedes Repo zu bringen, etwa ein Skript über die REST-API oder einen Pull Request je Repo.

## Abhängigkeiten / Risiken

- Bei privaten Repos muss das Repo mit dem gemeinsamen Workflow für die anderen freigegeben sein (Settings > Actions > Access).
- Ein Fehler im gemeinsamen Workflow trifft alle Repos, die auf diese Version zeigen.

## Aufwand

klein

## Bezug

ADR 0002, `docs/uebertragen.md` Abschnitt 3, Idee 0001.
