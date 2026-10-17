import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from tdxguard import credentials
from tdxguard.errors import NotLoggedInError


class TestCredentials(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.environ = {"XDG_CONFIG_HOME": self.directory.name}

    def tearDown(self):
        self.directory.cleanup()

    def sample(self):
        return credentials.Credentials(
            server="https://guard.example.com",
            token="api_token_secret",
            name="tdxguard-cli laptop",
            username="jane",
            expires="2027-01-15",
        )

    def test_path_respects_xdg(self):
        self.assertEqual(
            Path(self.directory.name) / "tdxguard" / "credentials.json", credentials.credentials_path(self.environ)
        )

    def test_path_default(self):
        self.assertTrue(
            str(credentials.credentials_path({})).endswith(os.path.join(".config", "tdxguard", "credentials.json"))
        )

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_save_permissions(self):
        path = credentials.save(self.sample(), self.environ)
        self.assertEqual(0o600, stat.S_IMODE(os.stat(path).st_mode))
        self.assertEqual(0o700, stat.S_IMODE(os.stat(path.parent).st_mode))

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_save_tightens_an_existing_directory(self):
        directory = Path(self.directory.name) / "tdxguard"
        directory.mkdir(mode=0o755)
        os.chmod(directory, 0o755)
        credentials.save(self.sample(), self.environ)
        self.assertEqual(0o700, stat.S_IMODE(os.stat(directory).st_mode))

    def test_round_trip(self):
        path = credentials.save(self.sample(), self.environ)
        with open(path) as f:
            stored = json.load(f)
        self.assertEqual(
            {"server", "token", "name", "username", "expires", "api_url"},
            set(stored),
        )
        loaded = credentials.load(self.environ)
        self.assertEqual("api_token_secret", loaded.token)
        self.assertEqual("jane", loaded.username)
        self.assertEqual("file", loaded.source)
        self.assertEqual("https://guard.example.com/api", loaded.api)
        self.assertEqual([], [p for p in path.parent.iterdir() if p.name.startswith(".credentials-")])

    def test_environment_wins(self):
        credentials.save(self.sample(), self.environ)
        environ = dict(self.environ, TDXGUARD_TOKEN="env_token", TDXGUARD_SERVER="https://other.example.com/api/")
        loaded = credentials.load(environ)
        self.assertEqual("env_token", loaded.token)
        self.assertEqual("https://other.example.com", loaded.server)
        self.assertEqual("https://other.example.com/api", loaded.api)
        self.assertEqual("environment", loaded.source)

    def test_environment_default_server(self):
        loaded = credentials.load(dict(self.environ, TDXGUARD_TOKEN="env_token"))
        self.assertEqual("https://guard.tdadevelop.com", loaded.server)

    def test_not_logged_in(self):
        self.assertIsNone(credentials.load(self.environ))
        with self.assertRaises(NotLoggedInError):
            credentials.require(self.environ)

    def test_corrupt_file(self):
        path = credentials.credentials_path(self.environ)
        path.parent.mkdir(parents=True)
        path.write_text("{not json")
        self.assertIsNone(credentials.load(self.environ))

    def test_delete(self):
        credentials.save(self.sample(), self.environ)
        self.assertTrue(credentials.delete(self.environ))
        self.assertFalse(credentials.delete(self.environ))

    def test_normalize_server(self):
        self.assertEqual("https://guard.example.com", credentials.normalize_server("guard.example.com/"))
        self.assertEqual("http://localhost:3000", credentials.normalize_server("http://localhost:3000/api"))
        self.assertEqual("https://guard.tdadevelop.com", credentials.normalize_server(""))


if __name__ == "__main__":
    unittest.main()
