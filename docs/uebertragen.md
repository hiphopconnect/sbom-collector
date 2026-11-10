# Auf ein anderes GitHub und andere Repos übertragen

Diese Anleitung beschreibt, was zu tun ist, um den Collector in einem anderen Konto, einer Organisation oder auf GitHub Enterprise Server zu betreiben und dort Quell-Repos anzubinden. Am Ende steht eine Prüfung, mit der man sieht, ob alles läuft.

## 1. Voraussetzungen klären

| Was | Warum | Prüfen |
|---|---|---|
| GitHub Actions eingeschaltet | Collector und Quell-Repos arbeiten mit Workflows | Settings > Actions > General, "Allow all actions" oder die verwendeten Actions freigeben |
| Runner mit Ubuntu und Python 3.12 | Der Collector braucht nur die Standardbibliothek | `runs-on: ubuntu-24.04` hat Python 3.12; eigene Runner brauchen es selbst |
| Internetzugang des Runners | Grype, seine Datenbank, EPSS und KEV werden heruntergeladen | Freigaben für `github.com` (Grype-Release), den Download der Grype-Datenbank, `epss.empiricalsecurity.com`, `www.cisa.gov` |

## 2. Collector einrichten

1. **Repo anlegen.** Für echte Repos **privat**: Die Berichte enthalten Namen, E-Mail-Adressen und offene Schwachstellen.
2. **Inhalt übernehmen**, mit vollständiger Historie:
   ```
   git clone --mirror https://github.com/hiphopconnect/sbom-collector.git
   cd sbom-collector.git
   git push --mirror <neue Adresse>
   ```
   Danach `sboms/` und `reports/` leeren, sie gehören zum alten Bestand.
3. **`quellen.txt` anpassen.** Je Zeile `owner` (alle nicht archivierten Repos eines Kontos oder einer Organisation) oder `owner/repo`.
4. **Workflow darf schreiben.** Settings > Actions > General > Workflow permissions: "Read and write permissions". In Organisationen kann das zentral gesperrt sein, dann muss es die Organisation freigeben.
5. **Lesezugriff auf private Quell-Repos.** Für öffentliche Quell-Repos ist nichts zu tun. Für private:
   - **Token** (für wenige Repos): Fine-grained Personal Access Token, Resource owner = Konto oder Organisation der Quell-Repos, Repository access auf diese Repos, Permissions Contents "Read-only" und Metadata "Read-only". Als Secret `SBOM_LESE_TOKEN` im Collector ablegen. Der Token läuft ab und muss rechtzeitig erneuert werden.
   - **GitHub App** (für viele Repos, empfohlen in Organisationen): App mit Contents und Metadata "Read-only" anlegen und in der Organisation installieren. Der Workflow erzeugt sich daraus bei jedem Lauf einen kurzlebigen Token und gibt ihn als `SBOM_LESE_TOKEN` an `abholen`. Noch nicht eingebaut, siehe [Idee 0002](ideas/0002-github-app-fuer-lesezugriff.md).
6. **Zeitplan anpassen**, falls gewünscht: `cron` in `.github/workflows/bewerten.yml`, Zeiten in UTC. Montags werden alle SBOMs neu bewertet.
7. **Erster Lauf von Hand:** Actions > "SBOMs abholen und bewerten" > Run workflow, Haken bei "Alle SBOMs neu bewerten". Erwartet: grün, im Schritt "Bewerten" die Zeile `Positivkontrolle bestanden`.

## 3. Quell-Repos anbinden

Für jedes Repo:

1. `.github/workflows/sbom.yml` und `.syft.yaml` aus dem Test-Repo `sbom-testrepo` übernehmen.
2. **Standardbranch.** Der Workflow läuft bei Push auf `main`. Heißt der Standardbranch anders, `branches: [main]` und `git pull --rebase origin main` / `git push origin HEAD:main` im Workflow anpassen. Der Collector liest immer den Standardbranch.
3. **Workflow darf schreiben**, wie beim Collector.
4. **Geschützter Standardbranch.** Darf niemand direkt auf `main` pushen, scheitert der SBOM-Commit mit `GH006: Protected branch update failed`. Dann in der Regel GitHub Actions als Ausnahme zulassen oder die SBOM auf einen eigenen Branch legen (dann muss auch der Collector diesen Branch lesen; noch nicht eingebaut, siehe [Idee 0005](ideas/0005-sbom-bei-geschuetztem-standardbranch.md)).
5. **Im Collector eintragen**, falls das Repo nicht schon über `owner` in `quellen.txt` erfasst ist.
6. **Prüfen:** Push auf `main`, danach liegt `sbom.cdx.json` im Repo und hat mehr als 0 Pakete.

Bei vielen Repos lohnt es sich, den Workflow als wiederverwendbaren Workflow zentral abzulegen und in den Quell-Repos nur noch aufzurufen. Dann gibt es eine Stelle für Änderungen. Noch nicht umgesetzt, siehe [Idee 0003](ideas/0003-wiederverwendbarer-workflow.md).

## 4. Besonderheiten bei GitHub Enterprise Server

- **API-Adresse:** Der Collector nimmt sie aus `GITHUB_API_URL`, das Actions auf der eigenen Instanz selbst setzt. Lokal aufgerufen gilt ohne diese Variable `https://api.github.com`.
- **Actions von github.com:** `actions/checkout` und `anchore/sbom-action` kommen von github.com. Auf Enterprise Server müssen sie über GitHub Connect verfügbar sein oder in die eigene Instanz gespiegelt werden. Beim Spiegeln die festen Commit-SHAs in den Workflows beibehalten oder an die Spiegel anpassen.
- **Downloads:** Grype wird von den Releases auf github.com geladen und per SHA-256 geprüft. Ist github.com nicht erreichbar, das Archiv intern ablegen und die Adresse im Schritt "Grype installieren" ändern; die Prüfsumme bleibt.
- **Proxy:** Braucht der Runner einen Proxy, `HTTPS_PROXY` im Workflow setzen; Python, curl und Grype verwenden ihn.

## 5. Prüfen, ob alles läuft

Die Prüfung ist dieselbe wie beim ersten Aufbau. Am einfachsten mit einem eigenen Test-Repo wie `sbom-testrepo`:

| Schritt | Erwartung |
|---|---|
| Collector von Hand starten, "alle" | grün, `Positivkontrolle bestanden` |
| Test-Repo mit verwundbaren Paketen pushen | `sbom.cdx.json` mit Paketen im Test-Repo |
| Push ohne Änderung an den Abhängigkeiten | kein neuer SBOM-Commit |
| Collector starten | Bericht mit Befunden, Repo in `reports/SUMMARY.md` |
| Nur aktuelle Versionen | "geprüft", keine Befunde, Zahl der Pakete genannt |
| Keine Pakete | "SBOM leer", Lauf rot mit Exit 3 |

## 6. Stolpersteine

| Meldung oder Verhalten | Ursache | Abhilfe |
|---|---|---|
| Lauf startet nicht, `startup_failure` | Workflow-Datei ungültig oder Actions nicht erlaubt | Lauf im Browser öffnen, dort steht der Grund |
| `HTTP Error 404` beim Abholen | Token sieht das Repo nicht, oder `quellen.txt` falsch | Repository access des Tokens und Schreibweise prüfen |
| `Positivkontrolle fehlgeschlagen` | Grype, Datenbank oder Kataloge nicht erreichbar oder verändert | Meldung nennt, was fehlt; Freigaben und Downloads prüfen |
