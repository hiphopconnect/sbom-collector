"""Tests für das Abholen der SBOMs, mit einem Ersatz für die GitHub-API."""

import tempfile
import unittest
import urllib.error
from pathlib import Path

from collector import abholen


class FalschesGitHub(abholen.GitHub):
    def __init__(self, konten: dict[str, list[dict]], dateien: dict[str, bytes]) -> None:
        super().__init__()
        self.konten, self.dateien = konten, dateien

    def liste(self, pfad: str) -> list[dict]:
        if pfad not in self.konten:
            raise urllib.error.HTTPError(pfad, 404, "Not Found", None, None)
        return self.konten[pfad]

    def datei(self, repo: str, pfad: str) -> bytes | None:
        return self.dateien.get(f"{repo}/{pfad}")


GITHUB = FalschesGitHub(
    konten={
        "/users/erika/repos": [
            {"full_name": "erika/app"},
            {"full_name": "erika/alt", "archived": True},
            {"full_name": "erika/leer"},
        ]
    },
    dateien={"erika/app/sbom.cdx.json": b'{"a": 1}', "erika/alt/sbom.cdx.json": b"{}", "fremd/x/sbom.cdx.json": b"{}"},
)


class AbholenTest(unittest.TestCase):
    def test_konto_ohne_archivierte(self):
        # Kein Organisationskonto, also über /users; archivierte Repos fallen weg
        self.assertEqual(abholen.repos_aus("erika", GITHUB), ["erika/app", "erika/leer"])

    def test_einzelnes_repo(self):
        self.assertEqual(abholen.repos_aus("fremd/x", GITHUB), ["fremd/x"])

    def test_nur_neue_und_geaenderte(self):
        with tempfile.TemporaryDirectory() as ordner:
            sboms = Path(ordner)
            erstes = abholen.abholen(["erika", "fremd/x"], sboms, GITHUB)
            zweites = abholen.abholen(["erika"], sboms, GITHUB)
            inhalt = (sboms / "erika" / "app.cdx.json").read_bytes()
        self.assertEqual([p.relative_to(sboms).as_posix() for p in erstes], ["erika/app.cdx.json", "fremd/x.cdx.json"])
        self.assertEqual(zweites, [])
        self.assertEqual(inhalt, b'{"a": 1}')

    def test_quellen_ohne_kommentare(self):
        with tempfile.TemporaryDirectory() as ordner:
            pfad = Path(ordner) / "quellen.txt"
            pfad.write_text("# Kommentar\nerika\n\nfremd/x  # einzeln\n", encoding="utf-8")
            self.assertEqual(abholen.lies_quellen(pfad), ["erika", "fremd/x"])


if __name__ == "__main__":
    unittest.main()
