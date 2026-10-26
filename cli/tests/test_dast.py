"""
DAST of the CLI (tdxguard/dast.py): the docker commands, the sign-in, the reports, `dast:` in
.tdxguard.yml and the --dast flags. Docker is a fake that records the commands and plays ZAP's
and Nuclei's part by writing their reports where `docker cp` fetches them.
"""

import argparse
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from tdxguard import commands, config, dast, reports
from tdxguard.errors import ConfigError
from tdxguard.ui import UI

REPOSITORY = Path(__file__).resolve().parents[2]
ZAP_DOCUMENT = {
    "site": [
        {
            "@name": "http://host.docker.internal:8000",
            "alerts": [
                {"name": "Application Error Disclosure", "riskcode": "3"},
                {"name": "X-Content-Type-Options Header Missing", "riskcode": "1"},
            ],
        }
    ]
}
NUCLEI_DOCUMENT = {
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "nuclei"}}, "results": [{"ruleId": "exposed-panel", "kind": "open",
                                                                     "level": "error"}]}],  # fmt: skip
}


class FakeDocker:
    """Records every command; `docker cp <container>:<path> <dest>` writes the scanner's report."""

    def __init__(self, auth_output="Bearer t0ken\n", fail=None):
        self.calls = []
        self.envs = []
        self.auth_output = auth_output
        self.fail = fail or set()
        self.copied_in = []

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        self.envs.append(kwargs.get("env"))
        stdout, code = "", 0
        if args[0] == "sh":
            stdout = self.auth_output
        elif args[:2] == ["docker", "cp"] and ":" in args[2] and not args[2].startswith("/"):
            source, destination = args[2], args[3]
            if "zap" in source and "zap" not in self.fail:
                Path(destination).write_text(json.dumps(ZAP_DOCUMENT))
            elif "nuclei" in source and "nuclei" not in self.fail:
                Path(destination).write_text(json.dumps(NUCLEI_DOCUMENT))
            else:
                code = 1
        elif args[:2] == ["docker", "cp"]:
            self.copied_in.append(sorted(p.name for p in Path(args[2].rstrip(".")).iterdir()))
        return subprocess.CompletedProcess(args, code, stdout, "")

    def find(self, *prefix):
        return [call for call in self.calls if call[: len(prefix)] == list(prefix)]


class DastTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "repo"
        self.out = Path(tmp.name) / "out"
        self.root.mkdir()
        self.out.mkdir()
        self.log = []

    def scan(self, target, docker, platform="darwin"):
        return dast.scan(target, self.root, self.out, log=self.log.append, run=docker, platform=platform)


class TestTargets(unittest.TestCase):
    def test_a_local_target_through_host_docker_internal_outside_linux(self):
        self.assertEqual("http://host.docker.internal:28080/api", dast.container_url("http://localhost:28080/api"))
        self.assertEqual("http://host.docker.internal/", dast.container_url("http://127.0.0.1/", "win32"))
        self.assertEqual(["--add-host", "host.docker.internal:host-gateway"], dast.network_args("http://localhost"))

    def test_a_local_target_through_the_host_network_on_linux(self):
        self.assertEqual("http://localhost:8000", dast.container_url("http://localhost:8000", "linux"))
        self.assertEqual(["--network", "host"], dast.network_args("http://localhost:8000", "linux"))

    def test_a_remote_target_as_it_is(self):
        self.assertEqual("https://stg.example.test", dast.container_url("https://stg.example.test"))
        self.assertEqual([], dast.network_args("https://stg.example.test"))


class TestScan(DastTestCase):
    def test_baseline_scan_signed_out(self):
        docker = FakeDocker()
        rows, errors = self.scan(dast.Dast(target="http://localhost:8000"), docker)
        self.assertEqual([], errors)
        create = docker.find("docker", "create")[0]
        self.assertIn(dast.ZAP_IMAGE, create)
        self.assertEqual(["zap-baseline.py", "-t", "http://host.docker.internal:8000", "-J", "zap.json", "-I"],
                         create[create.index(dast.ZAP_IMAGE) + 1:])  # fmt: skip
        # /zap/wrk is copied in before ZAP starts, then the report out, then the container goes.
        order = [call[1] for call in docker.calls]
        self.assertEqual(["create", "cp", "start", "cp", "rm"], order)
        self.assertEqual([{"scanner": "dast", "label": "ZAP (DAST)", "report": "zap.json", "findings": 2,
                           "severe": 1}], rows)  # fmt: skip
        self.assertNotIn("ZAP_AUTH_HEADER_VALUE", docker.envs[0])
        self.assertEqual([], [c for c in docker.calls if c[0] == "sh"])

    def test_api_scan_signed_in(self):
        (self.root / "docs").mkdir()
        (self.root / "docs" / "openapi.yaml").write_text("openapi: 3.0.0\n")
        docker = FakeDocker()
        target = dast.Dast(target="http://localhost:8000", api="docs/openapi.yaml", auth_command="./token.sh",
                           auth_header="X-Auth")  # fmt: skip
        rows, errors = self.scan(target, docker)
        self.assertEqual([], errors)
        create = docker.find("docker", "create")[0]
        self.assertEqual(
            ["zap-api-scan.py", "-t", "openapi.yaml", "-f", "openapi", "-O", "http://host.docker.internal:8000", "-S",
             "-J", "zap.json", "-I"],
            create[create.index(dast.ZAP_IMAGE) + 1:],
        )  # fmt: skip
        self.assertEqual([["openapi.yaml"]], docker.copied_in)
        # The value travels in the environment of `docker create -e NAME`, never on a command line.
        env = docker.envs[docker.calls.index(create)]
        names = ("ZAP_AUTH_HEADER", "ZAP_AUTH_HEADER_VALUE", "ZAP_AUTH_HEADER_SITE")
        self.assertEqual(("X-Auth", "Bearer t0ken", "host.docker.internal"), tuple(env[name] for name in names))
        self.assertFalse([call for call in docker.calls if any("t0ken" in part for part in call)])
        self.assertIn("-e", create)

    def test_full_mode_is_active(self):
        docker = FakeDocker()
        self.scan(dast.Dast(target="http://localhost:8000", mode="full"), docker, platform="linux")
        create = docker.find("docker", "create")[0]
        self.assertIn("zap-full-scan.py", create)
        self.assertIn("--network", create)

    def test_nuclei_signed_in_and_its_kind_fixed(self):
        docker = FakeDocker()
        rows, errors = self.scan(dast.Dast(target="http://localhost:8000", auth_command="x", nuclei=True), docker)
        self.assertEqual([], errors)
        nuclei = [c for c in docker.find("docker", "create") if dast.NUCLEI_IMAGE in c][0]
        self.assertIn("Authorization: Bearer t0ken", nuclei)
        self.assertIn(f"{dast.NUCLEI_VOLUME}:/root", nuclei)
        report = json.loads((self.out / "nuclei.sarif").read_text())
        self.assertEqual("fail", report["runs"][0]["results"][0]["kind"])
        self.assertEqual(["ZAP (DAST)", "Nuclei (DAST)"], [row["label"] for row in rows])

    def test_nuclei_without_matches_writes_no_file(self):
        docker = FakeDocker(fail={"nuclei"})
        rows, errors = self.scan(dast.Dast(target="http://localhost:8000", nuclei=True), docker)
        self.assertEqual([], errors)
        self.assertEqual(("Nuclei (DAST)", 0), (rows[1]["label"], rows[1]["findings"]))
        self.assertEqual([], json.loads((self.out / "nuclei.sarif").read_text())["runs"][0]["results"])

    def test_a_failing_sign_in_scans_nothing(self):
        docker = FakeDocker(auth_output="")
        rows, errors = self.scan(dast.Dast(target="http://localhost:8000", auth_command="./token.sh"), docker)
        self.assertEqual([], rows)
        self.assertIn("the auth command printed nothing", errors[0])
        self.assertEqual([], docker.find("docker", "create"))

    def test_no_report_is_an_error_and_the_container_still_goes(self):
        docker = FakeDocker(fail={"zap"})
        rows, errors = self.scan(dast.Dast(target="http://localhost:8000"), docker)
        self.assertEqual([], rows)
        self.assertTrue(errors[0].startswith("ZAP: ZAP wrote no report"))
        self.assertEqual(1, len(docker.find("docker", "rm")))

    def test_a_missing_api_definition(self):
        rows, errors = self.scan(dast.Dast(target="http://localhost:8000", api="nope.yaml"), FakeDocker())
        self.assertIn("not a file of the repository", errors[0])


class TestConfig(unittest.TestCase):
    def test_dast_section(self):
        cfg = config.parse({"project": "p", "dast": {"target": "http://localhost:8000", "api": "./docs/api.yaml",
                                                     "auth_command": "./t.sh", "nuclei": True}})  # fmt: skip
        self.assertEqual(("http://localhost:8000", "docs/api.yaml", "./t.sh", "Authorization", "baseline", True),
                         (cfg.dast.target, cfg.dast.api, cfg.dast.auth_command, cfg.dast.auth_header, cfg.dast.mode,
                          cfg.dast.nuclei))  # fmt: skip

    def test_rejections(self):
        for section, message in (
            ({"api": "x"}, "dast.target: is required"),
            ({"target": "localhost:8000"}, "must be an http:// or https:// URL"),
            ({"target": "http://localhost", "mode": "attack"}, "must be baseline or full"),
            ({"target": "http://localhost", "proxy": 1}, "unknown key"),
            ({"target": "https://stg.example.test", "mode": "full"}, "full is an attack"),
        ):
            with self.subTest(section=section), self.assertRaises(ConfigError) as caught:
                config.parse({"project": "p", "dast": section})
            self.assertIn(message, caught.exception.message)

    def test_full_on_a_remote_target_when_allowed(self):
        cfg = config.parse({"project": "p", "dast": {"target": "https://stg.example.test", "mode": "full",
                                                     "allow_full_on_remote": True}})  # fmt: skip
        self.assertEqual("full", cfg.dast.mode)


class TestFlags(unittest.TestCase):
    def args(self, **values):
        defaults = {"dast": None, "dast_api": None, "dast_auth_command": None, "dast_mode": None, "nuclei": False}
        return argparse.Namespace(**{**defaults, **values})

    def test_flags_override_the_file(self):
        cfg = config.parse({"project": "p", "dast": {"target": "http://localhost:8000", "nuclei": True}})
        target = commands.resolve_dast(self.args(dast="http://localhost:9000", dast_mode="full"), cfg)
        self.assertEqual(("http://localhost:9000", "full", True), (target.target, target.mode, target.nuclei))

    def test_nothing_without_a_target(self):
        self.assertIsNone(commands.resolve_dast(self.args(), config.parse({"project": "p"})))
        with self.assertRaises(ConfigError):
            commands.resolve_dast(self.args(dast_api="docs/api.yaml"), config.parse({"project": "p"}))

    def test_full_against_a_remote_flag_target(self):
        with self.assertRaises(ConfigError):
            commands.resolve_dast(self.args(dast="https://prod.example.test", dast_mode="full"),
                                  config.parse({"project": "p"}))  # fmt: skip

    def test_without_docker_a_warning(self):
        summary = {}
        errors = commands._scan_dast(UI(), dast.Dast(target="http://localhost:8000"), Path("."), Path("."), summary,
                                     lambda: False)  # fmt: skip
        self.assertEqual([], errors)
        self.assertIn("ZAP runs in Docker", summary["warnings"][0])


class TestReports(unittest.TestCase):
    def test_upload_and_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "zap.json").write_text(json.dumps(ZAP_DOCUMENT))
            (out / "nuclei.sarif").write_text(json.dumps(NUCLEI_DOCUMENT))
            plan = reports.upload_plan(out, {}, "http://localhost:8000")
            self.assertEqual(
                [("zap.json", "ZAP", "http://localhost:8000"), ("nuclei.sarif", "SARIF", "http://localhost:8000")],
                [(u.path.name, u.parser, u.fields("p", "b")["endpoint_url"]) for u in plan],
            )
            self.assertEqual(2, reports.count(out).high)  # ZAP's riskcode 3, Nuclei's error
            self.assertEqual(["nuclei.sarif", "zap.json"], [p.name for p in reports.report_files(out)])


@unittest.skipUnless((REPOSITORY / "ci-templates").is_dir(), "ci-templates/ is not next to the package")
class TestImagesMatchTheTemplates(unittest.TestCase):
    def test_images(self):
        github = (REPOSITORY / "ci-templates" / "github" / "tdxguard.yml").read_text(encoding="utf-8")
        gitlab = (REPOSITORY / "ci-templates" / "gitlab" / "tdxguard.yml").read_text(encoding="utf-8")
        self.assertIn(dast.ZAP_IMAGE, github)
        self.assertIn(dast.ZAP_IMAGE, gitlab)
        self.assertIn(dast.NUCLEI_IMAGE, gitlab)
        version = re.search(r'NUCLEI_VERSION: "([^"]+)"', github).group(1)
        self.assertTrue(dast.NUCLEI_IMAGE.endswith(f":v{version}"))


if __name__ == "__main__":
    unittest.main()
