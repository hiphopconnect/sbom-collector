# hiphopconnect/sbom-testrepo

- Commit: `effa85b26daf` auf `main`, 2026-11-10T21:03:36+01:00
- Autor: Michael Milke <michael.milke@posteo.de>
- Status: SBOM leer, 0 Pakete und 2 CI-Actions in der SBOM

**SBOM leer**: Syft hat keine Pakete gefunden. Das ist kein sauberes Ergebnis, sondern heißt meist, dass die SBOM-Erzeugung im Repo falsch eingerichtet ist.

## Einordnung

KEV geht vor, danach entscheiden EPSS ab 0.2 und CVSS ab 6.0 über das Feld (Schema nach CVE Prioritizer, übernommen aus SecScan). Ohne EPSS-Wert zählt EPSS als 0.

- **P1+** im KEV-Katalog, wird nachweislich ausgenutzt
- **P1** hohe Schwere und hohe Ausnutzungswahrscheinlichkeit
- **P2** hohe Schwere, niedrige Ausnutzungswahrscheinlichkeit
- **P3** geringe Schwere, hohe Ausnutzungswahrscheinlichkeit
- **P4** geringe Schwere, niedrige Ausnutzungswahrscheinlichkeit
- **P?** kein CVSS-Wert, von Hand zu bewerten

## Datenstand

- Grype: 0.121.0
- Grype-Datenbank: 2026-11-10T06:21:20Z
- EPSS: 2026-11-10T12:00:24Z
- KEV: 2026-11-10T19:03:29.8375Z
