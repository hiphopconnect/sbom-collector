# 0001 - Push mit Syft, Bewertung mit Grype und heruntergeladenen Katalogen

- Status: abgelöst durch 0002
- Datum: 2026-11-10

## Kontext

Viele Repos sollen ihre Abhängigkeiten an eine Stelle melden, die daraus priorisierte CVE-Listen macht. Die Bewertung muss für sehr viele Repos schnell gehen und nachvollziehbar sein. Der Prototyp läuft auf GitHub, später soll es auf GitHub in der Firma oder Jenkins laufen.

## Entscheidung

- Jedes Quell-Repo erzeugt die SBOM im eigenen Workflow mit Syft über `anchore/sbom-action`, Format CycloneDX, und bettet Repo, Commit, Ref, Autor und Zeit als `metadata.properties` mit dem Präfix `sbom-collector:` ein.
- Die SBOM wird über die Contents-API als `sboms/<owner>/<repo>.cdx.json` in den Collector geschrieben. Im Prototyp mit einem Fine-grained Token je Quell-Repo.
- Der Collector scannt mit Grype (`--by-cve`), lädt EPSS als Tages-CSV und KEV als JSON-Feed herunter und ordnet nach der Priorisierung aus SecScan ein.
- Der CVSS-Wert kommt aus Grype; die Bewertung der NVD geht vor der des Herstellers, Version 3.x vor 4.0 vor 2.0.
- Eine neue SBOM wird sofort bewertet, montags werden alle SBOMs neu bewertet.

## Betrachtete Alternativen

- **SBOM-Export von GitHub abholen (Pull):** In den Quell-Repos wäre nichts einzubauen. Verworfen für den Prototyp, weil der Ablauf aus dem Repo heraus gewünscht ist und der Dependency Graph nicht alle Pakettypen kennt. Bleibt als Ergänzung für Repos ohne Workflow denkbar.
- **CVE Prioritizer selbst einsetzen:** fragt NVD und EPSS je CVE online ab, zu langsam für viele Repos, und lässt CVEs ohne CVSS oder EPSS stillschweigend weg.
- **EPSS und KEV aus der Grype-Datenbank:** möglich, aber dann hängt der Datenstand an der Grype-Datenbank. Eigene Downloads machen den Stand im Bericht nachvollziehbar und entsprechen SecScan.
- **`repository_dispatch` statt Datei im Repo:** die Nutzlast ist begrenzt, und die SBOM wäre nicht im Collector abgelegt.

## Konsequenzen

- Jedes Quell-Repo braucht einen Workflow und ein Secret. Für viele Repos ersetzt eine GitHub App die einzelnen Tokens.
- Die SBOMs liegen versioniert im Collector; jede Änderung ist nachvollziehbar.
- Commits der Berichte durch `GITHUB_TOKEN` lösen keinen neuen Lauf aus, eine Schleife entsteht nicht.
- Ein öffentlicher Collector veröffentlicht Autoren und offene CVEs; der Betrieb mit fremden Repos braucht ein privates Repo.
