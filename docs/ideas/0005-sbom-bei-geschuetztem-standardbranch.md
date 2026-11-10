# 0005 - SBOM bei geschütztem Standardbranch

- Status: offen
- Datum: 2026-11-10

## Idee

Der Workflow im Quell-Repo committet `sbom.cdx.json` direkt auf `main`, und der Collector committet SBOMs und Berichte ebenfalls auf `main`. Ist der Standardbranch geschützt, wie in Organisationen üblich, scheitern beide mit `GH006: Protected branch update failed`. Der Ablauf soll auch mit geschützten Branches funktionieren, ohne den Schutz für alle aufzuweichen.

## Erkenntnisse

Zwei Wege:

1. **Ausnahme in der Schutzregel.** In einem Ruleset des Repos oder der Organisation eine Ausnahme (Bypass) für den Akteur einrichten, der committet. Einfach, aber jede Ausnahme schwächt den Schutz; ob der eingebaute `GITHUB_TOKEN` als Akteur ausgenommen werden kann oder dafür eine GitHub App nötig ist (Idee 0002), ist zu prüfen.
2. **Eigener Branch für die SBOM.** Der Workflow im Quell-Repo committet `sbom.cdx.json` auf einen Branch `sbom`, der nur diese Datei enthält und nicht geschützt ist. `main` bleibt unberührt.
   - Der Collector liest dann `contents/sbom.cdx.json?ref=sbom` statt des Standardbranchs; `abholen.py` bekommt dafür den Branch als Einstellung.
   - Die Herkunft (Commit, Autor) beschreibt weiterhin den Commit auf `main`, der die Abhängigkeiten geändert hat; das bettet der Workflow schon heute ein.
   - Der Branch braucht keine gemeinsame Historie mit `main` (orphan branch) und wächst nur, wenn sich Abhängigkeiten ändern.

Für den Collector selbst gilt dasselbe: Berichte und SBOMs auf einen eigenen Branch, `main` enthält nur Code und Doku. Das deckt sich mit Idee 0001 (wachsende Historie).

## Abhängigkeiten / Risiken

- Der Branch `sbom` darf nicht von Regeln erfasst werden, die alle Branches schützen.
- Wer den Branch `sbom` beschreiben kann, kann die SBOM fälschen; das gilt heute für `main` genauso, wird aber auf einem ungeschützten Branch leichter.
- Die Vorführung im Browser (README von `sbom-testrepo`) zeigt den SBOM-Commit dann auf dem Branch `sbom`, nicht mehr in der Commit-Liste von `main`.

## Aufwand

klein

## Bezug

ADR 0002, `docs/uebertragen.md` Abschnitt 3 (Geschützter Standardbranch), Ideen 0001 und 0002.
