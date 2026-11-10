# 0002 - GitHub App für den Lesezugriff

- Status: offen
- Datum: 2026-11-10

## Idee

Der Collector liest private Quell-Repos heute mit einem Fine-grained Personal Access Token (`SBOM_LESE_TOKEN`). Eine GitHub App soll ihn ersetzen.

## Erkenntnisse

- Der Token hängt an einer Person, läuft ab und muss von Hand erneuert werden; fällt das aus, meldet der Collector bei privaten Repos `HTTP Error 404`.
- Eine App gehört dem Konto oder der Organisation, braucht nur Contents und Metadata "Read-only" und wird für die Quell-Repos installiert. Neue Repos der Organisation lassen sich automatisch einschließen.
- Der Workflow erzeugt sich bei jedem Lauf aus App-ID und privatem Schlüssel einen Token, der nach einer Stunde verfällt, und gibt ihn als `SBOM_LESE_TOKEN` an `abholen`. Dafür gibt es die Action `actions/create-github-app-token`; alternativ ein kurzes Skript gegen die REST-API, ohne zusätzliche Action.
- Apps haben ein höheres Anfragelimit als der Token des Workflows, siehe Idee 0001.
- Am Collector-Code ändert sich nichts; er nimmt den Token weiterhin aus `SBOM_LESE_TOKEN`.

## Abhängigkeiten / Risiken

- In einer Organisation muss ein Owner die App anlegen oder freigeben.
- Der private Schlüssel der App liegt als Secret im Collector; wer ihn hat, kann alle freigegebenen Repos lesen.
- Eine zusätzliche Action ist eine neue Abhängigkeit; mit fester Commit-SHA einbinden oder das Skript selbst schreiben.

## Aufwand

klein

## Bezug

ADR 0002, `docs/uebertragen.md` Abschnitt 2, Idee 0001.
