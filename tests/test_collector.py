"""Tests ohne Netz und ohne Grype: Priorität, Auswertung der Grype-Ausgabe, Berichte.

python3 -m unittest discover -s tests
"""

import gzip
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from collector import bericht, grype, kataloge, pruefung, sbom
from collector.prioritaet import prioritaet

HIER = Path(__file__).parent


def lade_beispiel() -> dict:
    return json.loads((HIER / "beispiel-grype.json").read_text(encoding="utf-8"))


def beispielkataloge() -> kataloge.Kataloge:
    return kataloge.Kataloge(
        epss={"CVE-2018-18074": (0.05, 0.9), "CVE-2020-14343": (0.4, 0.99)},
        epss_stand="2026-11-10T00:00:00Z",
        kev={"CVE-2019-10906"},
        kev_stand="2026-11-09",
    )


class PrioritaetTest(unittest.TestCase):
    def test_kev_geht_vor(self):
        self.assertEqual(prioritaet(True, 0.0, 2.0), "P1+")

    def test_felder(self):
        self.assertEqual(prioritaet(False, 0.2, 6.0), "P1")
        self.assertEqual(prioritaet(False, 0.1, 9.8), "P2")
        self.assertEqual(prioritaet(False, 0.5, 5.9), "P3")
        self.assertEqual(prioritaet(False, None, 3.0), "P4")

    def test_ohne_cvss(self):
        self.assertEqual(prioritaet(False, 0.9, None), "P?")


class GrypeTest(unittest.TestCase):
    def setUp(self):
        self.befunde = {b.kennung: b for b in grype.befunde(lade_beispiel(), beispielkataloge())}

    def test_cve_aus_ghsa(self):
        befund = self.befunde["CVE-2018-18074"]
        self.assertEqual(befund.alias, "GHSA-x84v-xcm2-53pg")

    def test_nvd_vektor_geht_vor(self):
        # Der Hersteller sagt 6.1, die NVD 9.8: maßgeblich ist die NVD
        befund = self.befunde["CVE-2018-18074"]
        self.assertEqual((befund.cvss, befund.cvss_version), (9.8, "3.1"))
        self.assertEqual(befund.prioritaet, "P2")

    def test_kev_und_epss(self):
        self.assertEqual(self.befunde["CVE-2019-10906"].prioritaet, "P1+")
        self.assertEqual(self.befunde["CVE-2020-14343"].prioritaet, "P1")

    def test_ohne_cve_bleibt_drin(self):
        befund = self.befunde["GHSA-aaaa-bbbb-cccc"]
        self.assertEqual(befund.prioritaet, "P?")

    def test_doppelte_treffer_einmal(self):
        self.assertEqual(len(self.befunde), 4)
        self.assertEqual(len(grype.befunde(lade_beispiel(), beispielkataloge())), 4)

    def test_behoben_in(self):
        self.assertEqual(self.befunde["CVE-2018-18074"].behoben_in, "2.20.0")


class KatalogeTest(unittest.TestCase):
    def test_epss_mit_stand(self):
        with tempfile.TemporaryDirectory() as ordner:
            pfad = Path(ordner) / "epss.csv.gz"
            with gzip.open(pfad, "wt", encoding="utf-8") as datei:
                datei.write(
                    "#model_version:v2026.06.15,score_date:2026-11-10T12:00:00Z\n"
                    "cve,epss,percentile\nCVE-2021-44228,0.94,0.99\n"
                )
            werte, stand = kataloge.lies_epss(pfad)
        self.assertEqual(stand, "2026-11-10T12:00:00Z")
        self.assertEqual(werte["CVE-2021-44228"], (0.94, 0.99))

    def test_fehlender_katalog(self):
        with tempfile.TemporaryDirectory() as ordner, self.assertRaises(FileNotFoundError):
            kataloge.oeffne(Path(ordner))


class BerichtTest(unittest.TestCase):
    def test_herkunft_und_bericht(self):
        with tempfile.TemporaryDirectory() as ordner:
            wurzel = Path(ordner)
            sbom_pfad = wurzel / "sboms" / "beispiel" / "app.cdx.json"
            sbom_pfad.parent.mkdir(parents=True)
            sbom_pfad.write_text(
                json.dumps(
                    {
                        "metadata": {
                            "properties": [
                                {"name": "sbom-collector:commit", "value": "abcdef1234567890"},
                                {"name": "sbom-collector:autor", "value": "Erika Muster"},
                                {"name": "anderes:feld", "value": "x"},
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )
            herkunft = sbom.lies_herkunft(sbom_pfad, wurzel / "sboms")
            befunde = grype.befunde(lade_beispiel(), beispielkataloge())
            ziel = wurzel / "reports" / herkunft.repo
            ergebnis = pruefung.Ergebnis(pruefung.GEPRUEFT, 6, befunde)
            bericht.schreibe_repo(herkunft, ergebnis, {"EPSS": "2026-11-10"}, ziel)
            bericht.schreibe_uebersicht(wurzel / "reports")
            text = (wurzel / "reports" / "beispiel" / "app.md").read_text(encoding="utf-8")
            uebersicht = (wurzel / "reports" / "SUMMARY.md").read_text(encoding="utf-8")
        self.assertEqual(herkunft.repo, "beispiel/app")
        self.assertIn("Erika Muster", text)
        # P1+ steht oben in der Tabelle
        self.assertLess(text.index("CVE-2019-10906"), text.index("CVE-2018-18074"))
        self.assertIn("[beispiel/app](beispiel/app.md)", uebersicht)


def schreibe_sbom(ordner: Path, komponenten: list[dict]) -> Path:
    pfad = ordner / "sbom.cdx.json"
    pfad.write_text(json.dumps({"components": komponenten}), encoding="utf-8")
    return pfad


class PruefungTest(unittest.TestCase):
    def test_leere_sbom_ist_kein_sauberes_ergebnis(self):
        with tempfile.TemporaryDirectory() as ordner:
            ergebnis = pruefung.pruefe(schreibe_sbom(Path(ordner), []), beispielkataloge())
        self.assertEqual(ergebnis.status, pruefung.SBOM_LEER)

    def test_verschachtelte_komponenten_zaehlen(self):
        with tempfile.TemporaryDirectory() as ordner:
            pfad = schreibe_sbom(Path(ordner), [{"name": "a", "components": [{"name": "b"}]}])
            self.assertEqual(sbom.komponenten(pfad), 2)

    def test_scan_fehler_wird_sichtbar(self):
        with tempfile.TemporaryDirectory() as ordner:
            pfad = schreibe_sbom(Path(ordner), [{"name": "a"}])
            with mock.patch.object(grype, "scanne", side_effect=RuntimeError("grype fehlt")):
                ergebnis = pruefung.pruefe(pfad, beispielkataloge())
        self.assertEqual((ergebnis.status, ergebnis.fehler), (pruefung.FEHLGESCHLAGEN, "grype fehlt"))

    def test_keine_befunde_mit_beleg(self):
        herkunft = sbom.Herkunft("a/b", "", "", "", "", "")
        text = bericht.repo_markdown(herkunft, pruefung.Ergebnis(pruefung.GEPRUEFT, 7), {})
        self.assertIn("Geprüft wurden 7 Komponenten", text)


class KontrolleTest(unittest.TestCase):
    def kontrolle_mit(self, treffer: list[dict], kev: set[str]) -> None:
        kat = kataloge.Kataloge({"CVE-2021-44228": (0.94, 1.0)}, "", kev, "")
        mit_cvss = [
            {
                "vulnerability": {"id": t, "cvss": [{"version": "3.1", "metrics": {"baseScore": 10.0}}]},
                "artifact": {"name": "x"},
            }
            for t in treffer
        ]
        with mock.patch.object(grype, "scanne", return_value={"matches": mit_cvss}):
            pruefung.pruefe_kontrolle(kat, Path(__file__).parent.parent / pruefung.KONTROLLE)

    def test_besteht(self):
        self.kontrolle_mit(["CVE-2021-44228", "CVE-2018-18074"], {"CVE-2021-44228"})

    def test_fehlende_cve(self):
        with self.assertRaisesRegex(pruefung.KontrolleFehlgeschlagen, "CVE-2018-18074"):
            self.kontrolle_mit(["CVE-2021-44228"], {"CVE-2021-44228"})

    def test_kev_katalog_leer(self):
        with self.assertRaisesRegex(pruefung.KontrolleFehlgeschlagen, "ohne KEV"):
            self.kontrolle_mit(["CVE-2021-44228", "CVE-2018-18074"], set())


if __name__ == "__main__":
    unittest.main()
