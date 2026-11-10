# 0001 - Betrieb mit vielen Repos

- Status: offen
- Datum: 2026-11-10

## Idee

Der Collector soll auch mit rund 1000 Quell-Repos zuverlässig und in vertretbarer Zeit laufen.

## Erkenntnisse

Gemessen an einem Lauf auf GitHub (`ubuntu-24.04`, Grype 0.121.0):

| Schritt | Dauer | Abhängig von |
|---|---|---|
| EPSS und KEV laden (zusammen 4,6 MB) | unter 1 s | einmal je Lauf |
| Grype-Datenbank laden | 70 s | einmal je Lauf |
| Bewerten | etwa 2,5 s je SBOM | Zahl der Repos und Größe der SBOMs |

Hochgerechnet auf 1000 Repos dauert die Neubewertung aller SBOMs am Montag 40 bis 50 Minuten, große SBOMs länger. Das Limit für einen Job auf GitHub-Runnern liegt bei 6 Stunden. Der tägliche Lauf bewertet nur geänderte SBOMs und bleibt kurz.

Engpässe und Gegenmittel:

1. **API-Grenze beim Abholen.** Jeder Lauf fragt jedes Repo einzeln ab, also über 1000 Anfragen. Der Token des Workflows erlaubt 1000 Anfragen pro Stunde.
   - GitHub App statt Token, mit höherem Limit und ohne ablaufende persönliche Tokens (Idee 0002).
   - Bedingte Anfragen mit `If-None-Match` (ETag): eine Antwort `304 Not Modified` zählt nicht gegen das Limit. Die ETags je Repo werden zwischen den Läufen gespeichert.
2. **Wachsende Historie des Collector-Repos.** 1000 SBOMs und 1000 Berichte, jede Änderung ein Commit.
   - Berichte nicht auf `main`, sondern auf einem eigenen Branch, der nur den letzten Stand hält, oder als Artefakt des Laufs.
   - SBOMs nur zwischenspeichern (Actions-Cache) statt sie zu committen; nachvollziehbar bleibt der Stand über `sbom.cdx.json` im jeweiligen Quell-Repo.
3. **Laufzeit der Neubewertung.**
   - Grype-Aufrufe parallel ausführen, die Zahl begrenzt nach Kernen des Runners.
   - Oder mehrere Jobs über eine Matrix, je ein Teil der SBOMs, die Übersicht in einem abschließenden Job.
   - Grype-Datenbank im Actions-Cache halten, solange sie am selben Tag gebaut wurde.
4. **Rollout in die Quell-Repos.** Workflow als wiederverwendbaren Workflow zentral ablegen; in den Quell-Repos nur noch ein Aufruf mit fester Version (Idee 0003).

## Abhängigkeiten / Risiken

- GitHub App braucht in einer Organisation die Freigabe durch einen Owner.
- Zahlen aus einem einzigen Lauf mit kleiner SBOM; vor einer Entscheidung mit realen, größeren SBOMs messen.
- Parallele Grype-Läufe teilen sich die Datenbank; nur lesend, sollte unkritisch sein, ist aber zu prüfen.

## Aufwand

mittel

## Bezug

ADR 0002 (SBOM im Quell-Repo, Collector holt ab), `docs/uebertragen.md`, Ideen 0002 und 0003.
