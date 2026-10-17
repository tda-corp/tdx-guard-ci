import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tdxguard import __main__ as entry
from tdxguard import commands, credentials, http, oidc, server
from tdxguard.engine import scan, tools
from tdxguard.errors import EXIT_ERROR, EXIT_GATE, EXIT_OK, AuthenticationError


def run_main(argv):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = entry.main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


class TestBranchName(unittest.TestCase):
    def test_branch_name(self):
        self.assertEqual("local/jane@example.com/feature/x", commands.branch_name("jane@example.com", "feature/x"))
        self.assertEqual("local/Jane-Doe/main", commands.branch_name("Jane Doe", "main"))
        self.assertEqual("local/unknown/detached-abc123", commands.branch_name("", "detached-abc123"))


class TestArguments(unittest.TestCase):
    def parse(self, argv):
        return entry.build_parser().parse_args(argv)

    def test_verbose_before_and_after_the_command(self):
        self.assertTrue(self.parse(["-v", "scan"]).verbose)
        self.assertTrue(self.parse(["scan", "-v"]).verbose)
        self.assertFalse(self.parse(["scan"]).verbose)

    def test_skips(self):
        self.assertEqual(
            ["opengrep", "trivy"], commands.resolve_skips(self.parse(["scan", "--skip", "opengrep", "--skip", "trivy"]))
        )
        self.assertEqual(
            ["betterleaks", "opengrep", "trivy"], commands.resolve_skips(self.parse(["scan", "--image-only"]))
        )
        self.assertEqual(
            ["trivy", "image"], commands.resolve_skips(self.parse(["scan", "--skip", "trivy", "--no-images"]))
        )

    def test_image_flags_exclusive(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.parse(["scan", "--image-only", "--no-images"])

    def test_unknown_scanner(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.parse(["scan", "--skip", "zap"])


class TestRuntimeConfig(unittest.TestCase):
    def test_parse(self):
        text = (
            'window.__RUNTIME_CONFIG__ = {"API_BASE_URL":"https://guard.example.com/api","OIDC_ENABLE":"true",'
            '"OIDC_AUTHORITY":"https://sso.example.com","OIDC_CLIENT_ID":"abc","OIDC_SCOPE":"openid profile"};'
        )
        parsed = server.parse_runtime_config(text)
        self.assertEqual("https://sso.example.com", parsed["OIDC_AUTHORITY"])
        self.assertEqual("abc", parsed["OIDC_CLIENT_ID"])

    def test_parse_garbage(self):
        self.assertEqual({}, server.parse_runtime_config("<html>"))


class TestClient(unittest.TestCase):
    @patch("tdxguard.server.http.get")
    def test_401_means_login_again(self, get_mock):
        get_mock.return_value = http.Response(401, b'{"message": "API token has expired."}', {})
        with self.assertRaises(AuthenticationError) as cm:
            server.Client("https://g/api", token="t").me()
        self.assertIn("API token has expired.", cm.exception.message)
        self.assertIn("tdxguard login", cm.exception.hint)
        self.assertEqual({"Authorization": "APIToken t"}, get_mock.call_args[0][1])

    @patch("tdxguard.server.http.get")
    def test_find_product_exact_match(self, get_mock):
        get_mock.return_value = http.Response(
            200,
            json.dumps({"results": [{"id": 1, "name": "tdx-scribe-old"}, {"id": 2, "name": "tdx-scribe"}]}).encode(),
            {},
        )
        self.assertEqual(2, server.Client("https://g/api", token="t").find_product("tdx-scribe")["id"])
        self.assertIsNone(server.Client("https://g/api", token="t").find_product("tdx"))
        self.assertIn("products/?name=tdx&page_size=1000", get_mock.call_args[0][0])


class EnvironmentTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        patcher = patch.dict(
            os.environ,
            {"XDG_CONFIG_HOME": str(self.home / "config"), "XDG_CACHE_HOME": str(self.home / "cache"), "NO_COLOR": "1"},
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("TDXGUARD_TOKEN", None)
        os.environ.pop("TDXGUARD_SERVER", None)
        self.addCleanup(self.tmp.cleanup)


class TestLogin(EnvironmentTestCase):
    @patch("tdxguard.commands._open_browser", return_value=False)
    @patch("tdxguard.commands.server.Client")
    @patch("tdxguard.commands.oidc")
    @patch("tdxguard.commands.server.fetch_runtime_config")
    def test_login(self, runtime_mock, oidc_mock, client_cls, browser_mock):
        runtime_mock.return_value = {
            "API_BASE_URL": "https://guard.example.com/api",
            "OIDC_AUTHORITY": "https://sso.example.com",
            "OIDC_CLIENT_ID": "client-from-server",
            "OIDC_SCOPE": "openid profile email groups",
        }
        oidc_mock.start.return_value = oidc.DeviceAuthorization(
            "d", "ABCD", "https://sso/device", "https://sso/device?user_code=ABCD", 600, 5
        )
        oidc_mock.poll.return_value = {"id_token": "the-id-token"}
        client = client_cls.return_value
        client.create_cli_token.return_value = {
            "token": "api_token_SECRET",
            "name": "tdxguard-cli laptop",
            "expiration_date": "2027-01-15",
        }
        client.me.return_value = {"username": "jane"}

        code, out, err = run_main(["login", "--server", "https://guard.example.com"])

        self.assertEqual(EXIT_OK, code, err)
        oidc_mock.discover.assert_called_with("https://sso.example.com")
        self.assertEqual("client-from-server", oidc_mock.start.call_args[0][1])
        client_cls.assert_any_call("https://guard.example.com/api", bearer="the-id-token")
        self.assertIn("https://sso/device?user_code=ABCD", out)
        self.assertIn("ABCD", out)
        self.assertIn("as jane", out)
        self.assertNotIn("api_token_SECRET", out + err)
        stored = credentials.load_file()
        self.assertEqual("api_token_SECRET", stored.token)
        self.assertEqual("jane", stored.username)
        self.assertEqual("2027-01-15", stored.expires)


class TestWhoami(EnvironmentTestCase):
    @patch("tdxguard.commands.server.Client")
    def test_expired_token(self, client_cls):
        os.environ["TDXGUARD_TOKEN"] = "t"
        client_cls.return_value.me.side_effect = AuthenticationError(
            "TDxGuard rejected the token: API token has expired."
        )
        code, out, err = run_main(["whoami"])
        self.assertEqual(EXIT_ERROR, code)
        self.assertIn("API token has expired", err)
        self.assertIn("tdxguard login", err)

    def test_not_logged_in(self):
        code, _, err = run_main(["whoami"])
        self.assertEqual(EXIT_ERROR, code)
        self.assertIn("not logged in", err)


SUMMARY = {
    "version": "1",
    "tools": {"trivy": "0.58.1"},
    "rows": [
        {"scanner": "opengrep", "label": "Opengrep (SAST)", "report": "opengrep.sarif", "findings": 3, "severe": 1},
        {"scanner": "trivy", "label": "Trivy (dependencies)", "report": "sbom.cdx.json", "findings": 2, "severe": 1},
    ],
    "errors": [],
    "warnings": ["betterleaks: exclude does not apply to secrets"],
}


class TestScan(EnvironmentTestCase):
    def setUp(self):
        super().setUp()
        self.repo = self.home / "repo"
        (self.repo / "docker" / "api").mkdir(parents=True)
        (self.repo / "docker" / "api" / "Dockerfile").write_text("FROM scratch\n")
        (self.repo / ".tdxguard.yml").write_text(
            "project: tdx-scribe\nrepository: tda-corp/tdx-scribe\nexclude: [mobile/]\n"
            "images:\n  - dockerfile: docker/api/Dockerfile\n    context: .\ngate:\n  critical: 0\n"
        )
        self.commands_run = []
        for target, value in (
            ("tdxguard.commands.gitinfo.find_root", self.repo),
            ("tdxguard.commands.gitinfo.current_branch", "feature/login"),
            ("tdxguard.commands.gitinfo.remote_url", "git@github.com:tda-corp/tdx-scribe.git"),
            ("tdxguard.commands.docker.ensure_available", None),
            ("tdxguard.commands.docker.detect_socket", None),
        ):
            patcher = patch(target, return_value=value) if value is not None else patch(target)
            mock = patcher.start()
            self.addCleanup(patcher.stop)
            if target.endswith("detect_socket"):
                mock.return_value = commands.docker.Socket("/var/run/docker.sock", 0)
        patcher = patch("tdxguard.commands.docker.run", side_effect=self.fake_run)
        patcher.start()
        self.addCleanup(patcher.stop)

    def fake_run(self, command, verbose, cwd=None):
        self.commands_run.append(command)
        if command[:2] == ["docker", "run"]:
            # rsplit: a Windows host path carries a drive colon (C:\...:/out).
            out = Path(command[command.index("-v", 5) + 1].rsplit(":", 1)[0])
            (out / "summary.json").write_text(json.dumps(SUMMARY))
            (out / "opengrep.sarif").write_text(json.dumps({"runs": [{"results": [{"level": "error"}]}]}))
            (out / "sbom.cdx.json").write_text(
                json.dumps(
                    {
                        "vulnerabilities": [
                            {"ratings": [{"severity": "critical"}], "recommendation": "Upgrade x to version 2"},
                            {"ratings": [{"severity": "critical"}]},
                        ]
                    }
                )
            )
            (out / "sbom-image-docker-api.cdx.json").write_text(json.dumps({"vulnerabilities": []}))
        return 0, ""

    def test_no_upload_gate_fails(self):
        code, out, err = run_main(["scan", "--no-upload"])

        self.assertEqual(EXIT_GATE, code, err)
        build, scan = self.commands_run
        self.assertEqual(
            ["docker", "build", "-f", "docker/api/Dockerfile", "-t", "tdxguard-local/docker-api:scan", "."], build
        )
        self.assertEqual(["-v", f"{self.repo}:/src:ro"], scan[3:5])
        self.assertIn("/var/run/docker.sock:/var/run/docker.sock", scan)
        self.assertEqual(
            ["ghcr.io/tda-corp/tdxguard-scanner:v1", "scan", "--exclude", "mobile/", "--image",
             "tdxguard-local/docker-api:scan=docker-api"],
            scan[scan.index("ghcr.io/tda-corp/tdxguard-scanner:v1"):],
        )  # fmt: skip
        self.assertIn("Opengrep (SAST)", out)
        self.assertIn("exclude does not apply to secrets", out)
        # The unfixed critical vulnerability does not count (ignore_unfixed defaults to true).
        self.assertIn("local gate failed: 1 critical finding(s), the gate allows 0", out)

    def test_unfixed_counted_when_asked(self):
        with open(self.repo / ".tdxguard.yml", "a") as f:
            f.write("  ignore_unfixed: false\n")
        code, out, err = run_main(["scan", "--no-upload", "--no-images", "--json"])
        self.assertEqual(EXIT_GATE, code, err)
        self.assertEqual({"critical": 2, "high": 1}, json.loads(out)["counts"])

    def test_secrets_mode_git_refused_in_a_worktree(self):
        (self.repo / ".git").write_text("gitdir: /somewhere/else/.git/worktrees/repo\n")
        code, _, err = run_main(["scan", "--no-upload", "--secrets-mode", "git"])
        self.assertEqual(EXIT_ERROR, code)
        self.assertIn("git worktree", err)
        self.assertEqual([], self.commands_run)

    def test_log_opts(self):
        code, _, err = run_main(
            ["scan", "--no-upload", "--no-images", "--secrets-mode", "git", "--log-opts=--all -n 50"]
        )
        self.assertEqual(EXIT_GATE, code, err)
        self.assertEqual(["--secrets-mode", "git", "--log-opts=--all -n 50"], self.commands_run[0][-3:])

    def test_log_opts_needs_git_mode(self):
        code, _, err = run_main(["scan", "--no-upload", "--log-opts=--all"])
        self.assertEqual(EXIT_ERROR, code)
        self.assertIn("--secrets-mode git", err)

    @patch("tdxguard.commands.server.Client")
    def test_upload_creates_the_project(self, client_cls):
        os.environ["TDXGUARD_TOKEN"] = "t"
        os.environ["TDXGUARD_SERVER"] = "https://guard.example.com"
        client = client_cls.return_value
        client.me.return_value = {"username": "jane"}
        client.find_product.side_effect = [
            None,
            {"id": 7, "name": "tdx-scribe"},
            {"id": 7, "name": "tdx-scribe", "security_gate_passed": False},
        ]
        client.onboard.return_value = {"product": 7, "status": "Done"}
        client.upload.return_value = {"observations_new": 1, "observations_resolved": 0}

        code, out, err = run_main(["scan", "--no-images", "--json"])

        self.assertEqual(EXIT_GATE, code, err)
        client_cls.assert_called_with("https://guard.example.com/api", token="t")
        client.onboard.assert_called_with("tdx-scribe", "tda-corp/tdx-scribe")
        self.assertEqual(1, len(self.commands_run))
        uploads = [(Path(c[0][0]).name, c[0][1]) for c in client.upload.call_args_list]
        self.assertEqual(
            [
                (
                    "opengrep.sarif",
                    {"product_name": "tdx-scribe", "branch_name": "local/jane/feature/login", "parser_name": "SARIF"},
                ),
                (
                    "sbom.cdx.json",
                    {
                        "product_name": "tdx-scribe",
                        "branch_name": "local/jane/feature/login",
                        "parser_name": "CycloneDX",
                    },
                ),
                (
                    "sbom-image-docker-api.cdx.json",
                    {
                        "product_name": "tdx-scribe",
                        "branch_name": "local/jane/feature/login",
                        "parser_name": "CycloneDX",
                        "docker_image_name_tag": "tdxguard-local/docker-api:scan",
                    },
                ),
            ],
            uploads,
        )
        document = json.loads(out)
        self.assertEqual("https://guard.example.com/#/products/7/show", document["upload"]["url"])
        self.assertEqual({"critical": 1, "high": 1}, document["counts"])
        self.assertIn("Created the project tdx-scribe", err)
        self.assertFalse(document["upload"]["security_gate_passed"])
        self.assertIn("TDxGuard security gate: failed (this reflects the default branch", err)

    @patch("tdxguard.commands.server.Client")
    def test_expired_token_stops_before_scanning(self, client_cls):
        os.environ["TDXGUARD_TOKEN"] = "t"
        client_cls.return_value.me.side_effect = AuthenticationError()
        code, _, err = run_main(["scan"])
        self.assertEqual(EXIT_ERROR, code)
        self.assertEqual([], self.commands_run)
        self.assertIn("tdxguard login", err)

    def test_scanner_errors_exit_2(self):
        def failing_run(command, verbose, cwd=None):
            if command[:2] == ["docker", "run"]:
                out = Path(command[command.index("-v", 5) + 1].rsplit(":", 1)[0])
                (out / "summary.json").write_text(json.dumps(dict(SUMMARY, errors=["opengrep: rules download failed"])))
            return 1, ""

        with patch("tdxguard.commands.docker.run", side_effect=failing_run):
            code, out, _ = run_main(["scan", "--no-upload", "--no-images"])
        self.assertEqual(EXIT_ERROR, code)
        self.assertIn("opengrep: rules download failed", out)

    def test_no_summary(self):
        with patch("tdxguard.commands.docker.run", return_value=(125, "Unable to find image")):
            code, out, err = run_main(["scan", "--no-upload", "--no-images"])
        self.assertEqual(EXIT_ERROR, code)
        self.assertIn("without a summary", err)
        self.assertIn("Unable to find image", out)

    def test_registry_image_is_not_built_and_needs_no_socket(self):
        (self.repo / ".tdxguard.yml").write_text("project: tdx-scribe\nimages:\n  - ref: ghcr.io/tda-corp/web:1.2\n")
        code, out, err = run_main(["scan", "--no-upload", "--engine", "docker"])
        self.assertIn(code, (EXIT_OK, EXIT_GATE), err)
        (command,) = self.commands_run
        self.assertNotIn("/var/run/docker.sock:/var/run/docker.sock", command)
        self.assertEqual(["--remote-image", "ghcr.io/tda-corp/web:1.2=web-1.2"], command[-2:])
        self.assertIn("Engine:  docker (scanner image 1", out)

    def test_missing_config(self):
        (self.repo / ".tdxguard.yml").unlink()
        code, _, err = run_main(["scan", "--no-upload"])
        self.assertEqual(EXIT_ERROR, code)
        self.assertIn("tdxguard init", err)


class TestInitCommand(EnvironmentTestCase):
    def test_init_and_force(self):
        repo = self.home / "repo"
        (repo / "web").mkdir(parents=True)
        (repo / "web" / "Dockerfile").write_text("FROM scratch\n")
        with (
            patch("tdxguard.commands.gitinfo.find_root", return_value=repo),
            patch("tdxguard.commands.gitinfo.remote_url", return_value="https://github.com/tda-corp/TDX_Scribe.git"),
        ):
            code, out, _ = run_main(["init"])
            self.assertEqual(EXIT_OK, code)
            text = (repo / ".tdxguard.yml").read_text()
            self.assertIn("project: tdx-scribe", text)
            self.assertIn("repository: tda-corp/TDX_Scribe", text)
            self.assertIn("dockerfile: web/Dockerfile", text)

            code, _, err = run_main(["init"])
            self.assertEqual(EXIT_ERROR, code)
            self.assertIn("--force", err)

            code, _, _ = run_main(["init", "--force", "--project", "other"])
            self.assertEqual(EXIT_OK, code)
            self.assertIn("project: other", (repo / ".tdxguard.yml").read_text())


class TestEngineSelection(unittest.TestCase):
    def test_precedence(self):
        never = lambda: self.fail("Docker must not be asked when the engine is chosen")  # noqa: E731
        env = {"TDXGUARD_ENGINE": "docker"}
        self.assertEqual("native", commands.resolve_engine("native", env, "docker", never))
        self.assertEqual("docker", commands.resolve_engine(None, env, "native", never))
        self.assertEqual("native", commands.resolve_engine(None, {}, "native", never))
        self.assertEqual("native", commands.resolve_engine(None, {"TDXGUARD_ENGINE": " Native "}, None, never))

    def test_auto(self):
        self.assertEqual("docker", commands.resolve_engine(None, {}, None, lambda: True))
        self.assertEqual("native", commands.resolve_engine(None, {}, None, lambda: False))
        self.assertEqual("native", commands.resolve_engine("auto", {"TDXGUARD_ENGINE": "docker"}, None, lambda: False))
        self.assertEqual("docker", commands.resolve_engine(None, {"TDXGUARD_ENGINE": ""}, "auto", lambda: True))

    def test_unknown(self):
        with self.assertRaises(commands.ConfigError) as cm:
            commands.resolve_engine(None, {"TDXGUARD_ENGINE": "podman"}, None, lambda: True)
        self.assertIn("TDXGUARD_ENGINE", cm.exception.message)

    def test_docker_probe_asks_once(self):
        probe = commands._DockerProbe()
        with patch("tdxguard.commands.docker.is_available", return_value=False) as available:
            self.assertFalse(probe())
            self.assertFalse(probe())
        available.assert_called_once()


class TestNativeScan(EnvironmentTestCase):
    """--engine native: no Docker; Dockerfile images are skipped with a warning, registry images scanned."""

    def setUp(self):
        super().setUp()
        self.repo = self.home / "repo"
        self.repo.mkdir()
        (self.repo / "Dockerfile").write_text("FROM scratch\n")
        (self.repo / ".tdxguard.yml").write_text(
            "project: tdx-scribe\nimages:\n  - dockerfile: Dockerfile\n  - ref: ghcr.io/tda-corp/web:1.2\n"
        )
        self.scans = []
        for target, value in (
            ("tdxguard.commands.gitinfo.find_root", self.repo),
            ("tdxguard.commands.docker.is_available", False),
            ("tdxguard.commands.tools.detect_platform", "linux-x86_64"),
        ):
            patcher = patch(target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.ensure = patch("tdxguard.commands.tools.ensure", return_value=self.toolset()).start()
        self.addCleanup(patch.stopall)
        self.docker_run = patch("tdxguard.commands.docker.run", side_effect=AssertionError("docker was run")).start()
        patch("tdxguard.commands.scan.run", side_effect=self.fake_scan).start()

    def toolset(self):
        return tools.Toolset(Path("bl"), Path("og"), Path("tv"), Path("rules"))

    def fake_scan(self, options, toolset, environment, log, output):
        self.scans.append((options, environment))
        log("==> trivy image ghcr.io/tda-corp/web:1.2 (from the registry)")
        summary = dict(SUMMARY, engine="native", rows=SUMMARY["rows"] + [
            {"scanner": "image", "label": "Trivy (image `ghcr.io/tda-corp/web:1.2`)",
             "report": "sbom-image-web-1.2.cdx.json", "findings": 0, "severe": 0, "image": "ghcr.io/tda-corp/web:1.2"}
        ])  # fmt: skip
        (options.out / "summary.json").write_text(json.dumps(summary))
        return 0

    def test_without_docker(self):
        code, out, err = run_main(["scan", "--no-upload", "--engine", "native", "--json"])
        self.assertEqual(EXIT_OK, code, err)
        self.docker_run.assert_not_called()
        self.assertEqual(self.home / "cache" / "tdxguard" / "tools", self.ensure.call_args[0][1])
        options, environment = self.scans[0]
        self.assertEqual([scan.ImageTarget("ghcr.io/tda-corp/web:1.2", "web-1.2", remote=True)], options.images)
        self.assertEqual(("native", "dir", self.repo), (options.engine, options.secrets_mode, options.src))
        # One Trivy cache for both engines.
        self.assertEqual(str(self.home / "cache" / "tdxguard" / "scanner"), environment["TRIVY_CACHE_DIR"])
        self.assertIn(
            "Docker is not available, so 1 image(s) built from a Dockerfile are not scanned: Dockerfile (root)", err
        )
        document = json.loads(out)
        self.assertEqual("native", document["engine"])
        self.assertIn("Engine:  native (tools on this machine; trivy 0.58.1)", err)

    def test_auto_falls_back_to_native(self):
        code, _, err = run_main(["scan", "--no-upload"])
        self.assertEqual(EXIT_OK, code, err)
        self.assertEqual(1, len(self.scans))

    def test_tools_dir_from_the_environment(self):
        os.environ["TDXGUARD_TOOLS_DIR"] = str(self.home / "elsewhere")
        run_main(["scan", "--no-upload", "--engine", "native"])
        self.assertEqual(self.home / "elsewhere", self.ensure.call_args[0][1])

    def test_git_mode_in_a_worktree_is_fine_natively(self):
        (self.repo / ".git").write_text("gitdir: /somewhere/else/.git/worktrees/repo\n")
        code, _, err = run_main(["scan", "--no-upload", "--engine", "native", "--secrets-mode", "git"])
        self.assertEqual(EXIT_OK, code, err)
        self.assertEqual("git", self.scans[0][0].secrets_mode)

    def test_offline_first_run(self):
        self.ensure.side_effect = commands.tools.ToolError("Download failed (offline): https://github.com/...", "hint")
        code, _, err = run_main(["scan", "--no-upload", "--engine", "native"])
        self.assertEqual(EXIT_ERROR, code)
        self.assertIn("Download failed", err)
        self.assertEqual([], self.scans)

    def test_engine_from_config(self):
        with open(self.repo / ".tdxguard.yml", "a") as f:
            f.write("engine: docker\n")
        with patch(
            "tdxguard.commands.docker.ensure_available", side_effect=commands.DockerError("Docker is not running")
        ):
            code, _, err = run_main(["scan", "--no-upload"])
        self.assertEqual(EXIT_ERROR, code)
        self.assertIn("Docker is not running", err)


class TestToolsCommand(EnvironmentTestCase):
    def test_list_and_clean(self):
        os.environ["TDXGUARD_TOOLS_DIR"] = str(self.home / "tools")
        code, out, _ = run_main(["tools", "list", "--json", "-v"])
        self.assertEqual(EXIT_OK, code)
        listing = json.loads(out)
        self.assertEqual(str(self.home / "tools"), listing["directory"])
        self.assertEqual(
            ["betterleaks", "opengrep", "opengrep-rules", "trivy"], [entry["tool"] for entry in listing["tools"]]
        )
        self.assertEqual({"missing"}, {entry["state"] for entry in listing["tools"]})

        (self.home / "tools" / "trivy" / "0.1.0").mkdir(parents=True)
        code, out, _ = run_main(["tools", "clean", "--unused"])
        self.assertEqual(EXIT_OK, code)
        self.assertIn("trivy", out)
        self.assertFalse((self.home / "tools" / "trivy" / "0.1.0").exists())
        code, out, _ = run_main(["tools", "clean"])
        self.assertEqual(EXIT_OK, code)
        self.assertFalse((self.home / "tools").exists())

    def test_install(self):
        os.environ["TDXGUARD_TOOLS_DIR"] = str(self.home / "tools")
        with patch("tdxguard.commands.tools.ensure") as ensure:
            code, out, _ = run_main(["tools", "install", "--platform", "windows-x86_64"])
        self.assertEqual(EXIT_OK, code)
        self.assertEqual(("windows-x86_64", self.home / "tools"), ensure.call_args[0][:2])
        self.assertIn("Windows x86_64", out)


if __name__ == "__main__":
    unittest.main()
