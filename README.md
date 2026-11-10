# sbom-collector

Sammelt die SBOMs vieler Repos an einer Stelle und priorisiert die CVEs darin nach KEV, EPSS und CVSS. Für jedes Repo entsteht ein Bericht mit dem Commit und dem Autor, der die Abhängigkeiten zuletzt geändert hat, damit klar ist, wen man anschreibt. Dazu eine Übersicht über alle Repos nach Dringlichkeit.

Stand: Prototyp. Hintergrund in [docs/VISION.md](docs/VISION.md), Entscheidungen in [docs/adr/](docs/adr/), Übertragen auf ein anderes GitHub und andere Repos in [docs/uebertragen.md](docs/uebertragen.md).

## Ablauf

```
Quell-Repo, bei jedem Push               sbom-collector, täglich 05:00 UTC
--------------------------               ---------------------------------
Syft erzeugt SBOM (CycloneDX)            sbom.cdx.json aller Repos aus quellen.txt holen
Abhängigkeiten geändert?                 Grype-Datenbank, EPSS, KEV laden
  nein: fertig                           neue oder geänderte SBOMs mit Grype scannen
  ja:   Repo, Commit, Autor einbetten    Priorität P1+ bis P4 je CVE
        sbom.cdx.json ins eigene Repo    reports/<owner>/<repo>.md und .json
        committen                        reports/SUMMARY.md
                                         montags: alle SBOMs neu bewerten
```

Die Quell-Repos brauchen kein Secret und keinen Zugriff auf den Collector. Montags wird alles neu bewertet, auch ohne neue SBOM: EPSS ändert sich täglich und KEV mehrmals pro Woche, ein unverändertes Repo kann also plötzlich P1+ haben.

## Priorität

Übernommen aus SecScan, Schema und Schwellen nach dem Projekt [CVE Prioritizer](https://github.com/TURROKS/CVE_Prioritizer):

| | CVSS ab 6,0 | CVSS unter 6,0 |
|---|---|---|
| **im KEV-Katalog** | P1+ | P1+ |
| **EPSS ab 0,2** | P1 | P3 |
| **EPSS unter 0,2** | P2 | P4 |

Ohne CVSS-Wert: P?, von Hand bewerten. Ohne EPSS-Wert zählt EPSS als 0. Beim CVSS-Wert geht die Bewertung der NVD vor der des Herstellers, Version 3.x vor 4.0 vor 2.0.

Die Schwellen sind die Standardwerte von CVE Prioritizer. FIRST, der Herausgeber von EPSS, nennt selbst keine feste Schwelle.

## Heißt "keine Befunde" wirklich sauber?

Ein leerer Bericht darf nicht bedeuten, dass der Scan gar nicht lief. Drei Sicherungen:

1. **Positivkontrolle in jedem Lauf.** `kontrolle/kontrolle.cdx.json` enthält `log4j-core 2.14.1` und `requests 2.19.1`. Grype muss dort CVE-2021-44228 und CVE-2018-18074 finden, Log4Shell zusätzlich mit KEV, EPSS und CVSS. Sonst bricht der Lauf mit Exit 2 ab und schreibt keine Berichte. Damit fallen ein kaputtes Grype, eine leere Datenbank, fehlende Kataloge und Fehler in der Auswertung auf.
2. **Status je Repo.** Jeder Bericht nennt die Zahl der Pakete und der CI-Actions in der SBOM und einen Status. Dateieinträge, die Syft ebenfalls als Komponenten führt, zählen nicht; GitHub Actions aus den Workflows (`pkg:github/...`) werden gescannt, zählen aber nicht als Pakete der Anwendung:

| Status | Bedeutung |
|---|---|
| geprüft | SBOM mit mindestens einem Paket, Scan gelaufen, Kontrolle bestanden; mit oder ohne Befunde |
| SBOM leer | Syft hat keine Pakete gefunden, höchstens CI-Actions: Repo ohne Abhängigkeiten oder SBOM-Erzeugung falsch eingerichtet, also kein sauberes Ergebnis |
| nicht bewertet | Grype ist an dieser SBOM gescheitert, mit Fehlermeldung im Bericht; der Lauf endet mit Exit 3 |

3. **Übersicht.** "nicht bewertet" und "SBOM leer" stehen vor allen Befunden. Die Spalte "Abhängigkeiten geändert" zeigt, wie alt eine SBOM ist; ein Repo, dessen Workflow nicht mehr läuft, fällt dort auf.

Der Datenstand im Bericht nennt Grype-Version, Stand der Grype-Datenbank, EPSS und KEV.

## Quellen

| Quelle | Woher | Wann |
|---|---|---|
| SBOMs | `sbom.cdx.json` im Standardbranch jedes Repos aus `quellen.txt` | täglich |
| Schwachstellen und CVSS | Datenbank von Grype | bei jedem Lauf |
| EPSS | `epss.empiricalsecurity.com`, Tages-CSV | bei jedem Lauf |
| KEV | CISA, JSON-Feed | bei jedem Lauf |

Alles wird als Datei geladen, nicht je CVE über eine API abgefragt.

## Einrichten

### Collector

1. Repo `sbom-collector` auf GitHub anlegen und diesen Inhalt pushen.
2. Settings > Actions > General > Workflow permissions: "Read and write permissions". Der Workflow committet SBOMs und Berichte.
3. In `quellen.txt` eintragen, wessen Repos abgeholt werden: `owner` für alle Repos eines Kontos oder einer Organisation, `owner/repo` für ein einzelnes.
4. Nur für private Quell-Repos: einen Fine-grained Token mit Lesezugriff (Contents "Read-only", Metadata "Read-only") auf diese Repos als Secret `SBOM_LESE_TOKEN` im Collector hinterlegen. Für öffentliche Repos ist nichts zu tun.

### Quell-Repo

1. `.github/workflows/sbom.yml` und `.syft.yaml` aus dem Test-Repo `sbom-testrepo` übernehmen.
2. Settings > Actions > General > Workflow permissions: "Read and write permissions".
3. Pushen. Nach dem Lauf liegt `sbom.cdx.json` im Repo.

## Lokal

Braucht Python 3.12 und `grype` im Pfad. Keine Python-Pakete.

```
python3 -m collector abholen                        # SBOMs aus quellen.txt nach sboms/
python3 -m collector kataloge                       # EPSS und KEV nach kataloge/
python3 -m collector bewerte sboms/a/b.cdx.json     # eine SBOM
python3 -m collector bewerte --alle                 # alle unter sboms/
python3 -m unittest discover -s tests -t .          # Tests, ohne Netz und ohne Grype
ruff check . && ruff format --check .
```

`abholen` nimmt den Token aus `SBOM_LESE_TOKEN` oder `GITHUB_TOKEN`; ohne Token geht es nur für öffentliche Repos und mit 60 Anfragen pro Stunde.

## Stolpersteine

| Meldung oder Verhalten | Ursache | Abhilfe |
|---|---|---|
| Quell-Repo: `remote: Permission to ... denied to github-actions[bot]` | Workflow darf nicht schreiben | Settings > Actions > Workflow permissions auf "Read and write" |
| Quell-Repo: `GH006: Protected branch update failed` | `main` ist geschützt | Ausnahme für GitHub Actions in der Regel, oder SBOM auf einen eigenen Branch legen |
| Quell-Repo: jeder Push erzeugt einen SBOM-Commit | Syft liest die eigene SBOM als Paketquelle mit | `.syft.yaml` mit `exclude: ["./sbom.cdx.json"]` fehlt |
| Collector holt ein Repo nicht | Repo nicht in `quellen.txt`, archiviert, oder `sbom.cdx.json` fehlt im Standardbranch | Eintrag und Datei prüfen |
| Collector: `HTTP Error 404` bei einem privaten Repo | Token fehlt oder sieht das Repo nicht | Secret `SBOM_LESE_TOKEN` und dessen Repository access prüfen |
| Collector: `HTTP Error 403`, rate limit | Zu viele Anfragen ohne Token oder mit `GITHUB_TOKEN` | Token oder GitHub App mit höherem Limit |
| Täglicher Lauf fehlt | GitHub schaltet Zeitpläne in öffentlichen Repos nach 60 Tagen ohne Commit ab | Unter Actions wieder aktivieren; der Collector committet aber normalerweise selbst regelmäßig |
| Lauf rot: `Positivkontrolle fehlgeschlagen` | Grype oder ein Katalog liefert nicht, was er soll | Meldung nennt, was fehlt: eine CVE (Grype-Datenbank) oder KEV, EPSS, CVSS (Kataloge, Auswertung) |
| Lauf rot, Exit 3 | Mindestens ein Repo ist "nicht bewertet" | Fehlermeldung im Bericht des Repos |
| Bericht "SBOM leer" | Syft findet im Quell-Repo keine Pakete | Liegen Manifeste wie `requirements.txt` im Repo? Schließt `.syft.yaml` zu viel aus? |
| `kataloge/epss.csv.gz fehlt` | `bewerte` vor `kataloge` aufgerufen | erst `python3 -m collector kataloge` |

## Datenschutz

Die Berichte enthalten Name und E-Mail-Adresse des Committers und die offenen Schwachstellen jedes Repos. In einem öffentlichen Collector ist das für jeden lesbar. Den Prototyp deshalb nur mit eigenen Repos betreiben; für fremde Repos muss der Collector privat sein.

## Lizenz

MIT. Die Priorisierung stammt aus SecScan, ebenfalls MIT.
