# Vision

## Zweck

Viele Repos legen bei jedem Push, der ihre Abhängigkeiten ändert, eine SBOM bei sich ab. Ein zentrales Repo holt sie täglich ab; dort werden die Pakete mit Grype gegen bekannte Schwachstellen geprüft und die CVEs nach KEV, EPSS und CVSS in P1+ bis P4 eingeordnet. Der Verwalter des Collectors sieht über alle Repos, wo es brennt, und für jedes Repo, wer zuletzt committet hat und wen er anschreiben muss. Jeder Bericht lässt sich an das jeweilige Team weitergeben.

## Leitmotiv

Nachvollziehbar statt raffiniert: jede Priorität folgt aus drei öffentlichen Werten und zwei Schwellen, jeder Bericht nennt den Datenstand seiner Quellen.

## Zielgruppe und Nutzungssituation

- Verwalter des Collectors, der den Überblick über alle Repos braucht und Teams anschreibt.
- Entwickler, die den Bericht zu ihrem Repo bekommen und wissen wollen, welches Paket auf welche Version zu heben ist.
- Prototyp auf einem öffentlichen GitHub-Konto mit eigenen Repos; später auf GitHub in der Firma, für Tests auch mit Jenkins.

## Qualitätsansprüche

- Python 3.12, nur Standardbibliothek. Grype und Syft laufen als fertige Programme.
- Kern als Kommandozeilenprogramm, die CI ruft es nur auf. Ein Umzug zu Jenkins ist eine neue Hülle, kein Neubau.
- Kataloge als Download, nicht über APIs; ein Lauf über viele SBOMs lädt sie einmal.
- Actions und Programme mit fester Version und Prüfsumme bzw. Commit-SHA.
- Kein Inhalt aus der Firma im öffentlichen Repo.
- Berichte auf Deutsch.

## Nicht-Ziele

- Keine Geräte, Container-Images oder Binärdateien im ersten Schritt, nur Paketabhängigkeiten aus den Repos.
- Kein Coverage-Audit, keine Canaries, kein Dependency-Track (eigenes Vorhaben, Stand 2026-11-09).
- Keine Schutzbedarfs- oder Befundklassen; die bleiben im Freigabeprozess.
- Kein automatischer Mailversand an Autoren im Prototyp.
