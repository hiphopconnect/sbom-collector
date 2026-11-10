# 0004 - Container-Images und Binärdateien

- Status: offen
- Datum: 2026-11-10

## Idee

Neben den Paketabhängigkeiten eines Repos sollen auch die Container-Images bewertet werden, die ein Repo baut, und später die Binärdateien, die es ausliefert.

## Erkenntnisse

**Container-Images** (erster Schritt):

- Syft scannt Images direkt und erfasst die Pakete des Betriebssystems (dpkg, apk, rpm) und die Sprachpakete im Image. In Repos, die ein Image bauen, kommt nach dem Build ein zweiter Aufruf von `anchore/sbom-action` mit `image:` statt `path:` dazu.
- Grype kennt die Sicherheitsdaten der Distributionen (Debian, Ubuntu, Alpine, RHEL und weitere); an Priorisierung und Bericht ändert sich nichts Grundsätzliches.
- Ein Repo hat dann mehrere SBOMs. Ablage im Quell-Repo etwa als `sbom/` mit einer Datei je Image, Abholen und Bericht mit einem Abschnitt je SBOM.
- Images bringen viele Befunde, darunter solche, die der Distributor nicht beheben will (Grype: Fix-Status "wont-fix"). Das gehört als eigene Angabe in den Bericht, sonst wirken die Listen unlösbar.
- Die Positivkontrolle bekommt ein Betriebssystempaket mit bekannter Lücke, damit auch die Distributionsdaten in jedem Lauf geprüft werden.
- Alternative: Der Collector holt die Images selbst aus der Registry. Das braucht Zugangsdaten und eine Liste der Images; der Weg über das Quell-Repo ist einfacher.

**Binärdateien** (später):

- Gut erkennbar: Go-Programme (Build-Info), Rust mit `cargo auditable`, Java-JARs (Manifest, `pom.properties`), .NET (`deps.json`) und einige bekannte Programme über Muster im Binärcode, etwa OpenSSL, Python, Node.
- Kaum erkennbar: statisch gelinkte oder gestrippte C- und C++-Programme und fertige Installer von Drittherstellern. Syft findet dort wenig oder nichts.
- Erzeugen im Release-Workflow, Syft auf den Ausgabeordner, etwa `dist/`.
- Ohne Abgleich, ob die SBOM alle ausgelieferten Dateien erfasst, bleibt unklar, was fehlt. Das ist derzeit ausdrücklich kein Ziel (`docs/VISION.md`) und wäre vorher zu klären.

## Abhängigkeiten / Risiken

- Größere SBOMs verlängern den Lauf, siehe Idee 0001.
- Viele Befunde ohne Fix vom Distributor können die Übersicht verwässern; die Darstellung muss das trennen.

## Aufwand

mittel für Container-Images, gross für Binärdateien

## Bezug

ADR 0002, `docs/VISION.md` (Nicht-Ziele), Idee 0001.
