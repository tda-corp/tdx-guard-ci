import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from tdxguard import coverage, http
from tdxguard.errors import EXIT_ERROR, EXIT_GATE, EXIT_OK, ConfigError
from tests.test_commands import EnvironmentTestCase, run_main


def write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def webapp(root: Path) -> None:
    write(root, "Dockerfile", "FROM python:3.12-slim\n")
    write(root, "web/Dockerfile", "FROM node:22-slim\n")
    write(root, "requirements.txt", "django\n")
    write(root, "package.json", json.dumps({"scripts": {"start": "node server.js"}}))
    write(root, "docker-compose.yml", "services:\n  api:\n    ports: ['8000:8000']\n  db:\n    image: postgres\n")


class TestInspect(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_webapp(self):
        webapp(self.root)
        write(self.root, "node_modules/x/Dockerfile", "FROM x\n")
        facts = coverage.inspect(self.root)
        self.assertEqual(["Dockerfile", "web/Dockerfile"], facts.dockerfiles)
        self.assertEqual({"package.json", "requirements.txt"}, set(facts.manifests))
        # Trivy's misconfiguration scan reads Dockerfiles: they count as IaC.
        self.assertEqual(["Dockerfile", "web/Dockerfile"], facts.iac_files)
        self.assertEqual(["docker-compose.yml"], facts.compose_files)
        commands = [command for command, _ in facts.start_hints]
        self.assertEqual(["npm start", "docker compose -f docker-compose.yml up api"], commands)

    def test_start_hint_prefers_the_service_built_here(self):
        compose = {
            "services": {
                "mailpit": {"image": "axllent/mailpit", "ports": ["8025:8025"]},
                "postgres": {"image": "postgres:16"},
                "app": {"build": ".", "ports": ["8000:8000"]},
            }
        }
        write(self.root, "docker-compose.yml", yaml.safe_dump(compose))
        commands = [command for command, _ in coverage.inspect(self.root).start_hints]
        self.assertEqual(["docker compose -f docker-compose.yml up app", "docker compose -f docker-compose.yml up mailpit"],
                         commands)  # fmt: skip

    def test_iac(self):
        write(self.root, "infra/main.tf", 'resource "x" "y" {}\n')
        write(self.root, "k8s/deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\n")
        write(self.root, "config/settings.yaml", "debug: true\n")
        write(self.root, "cfn/stack.yml", "AWSTemplateFormatVersion: '2010-09-09'\n")
        write(self.root, "chart/Chart.yaml", "name: x\n")
        facts = coverage.inspect(self.root)
        self.assertEqual(
            {"infra/main.tf", "k8s/deploy.yaml", "cfn/stack.yml", "chart/Chart.yaml"}, set(facts.iac_files)
        )
        self.assertEqual([], facts.start_hints)

    def test_library(self):
        write(self.root, "pyproject.toml", "[project]\nname='x'\n")
        write(self.root, "src/x/__init__.py", "")
        facts = coverage.inspect(self.root)
        self.assertEqual(["pyproject.toml"], facts.manifests)
        self.assertEqual([], facts.dockerfiles + facts.iac_files)
        self.assertEqual({"python": 1}, facts.source_languages)

    def test_source_languages(self):
        write(self.root, "app/Http/Controller.php", "<?php\n")
        write(self.root, "app/Models/User.php", "<?php\n")
        write(self.root, "resources/js/app.ts", "")
        write(self.root, "native/src/lib.rs", "")
        write(self.root, "vendor/laravel/x.php", "<?php\n")  # dependencies are not the product's code
        facts = coverage.inspect(self.root)
        self.assertEqual({"php": 2, "typescript": 1, "rust": 1}, facts.source_languages)
        self.assertEqual((["php", "typescript"], ["rust"]), coverage.sast_languages(facts))


class TestWorkflow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_github_workflow_found_and_parsed(self):
        options = coverage.CIOptions(
            dockerfiles=["Dockerfile", "web/Dockerfile web"],
            app_start_command='gunicorn -b 127.0.0.1:8000 "app.wsgi:application"',
            app_health_url="http://127.0.0.1:8000/health",
            dast_target="https://staging.example.com",
            mobile_apps=["app/build/outputs/apk/release/*.apk"],
        )
        write(
            self.root,
            ".github/workflows/tdxguard.yml",
            coverage.render_workflow("github", "app", "tda-corp/app", options),
        )
        write(self.root, ".github/workflows/other.yml", "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n")

        workflow = coverage.find_workflow(self.root)

        self.assertEqual("github", workflow.platform)
        self.assertEqual(".github/workflows/tdxguard.yml", workflow.path)
        self.assertEqual("Dockerfile\nweb/Dockerfile web\n", workflow.inputs["dockerfile"])
        self.assertEqual('gunicorn -b 127.0.0.1:8000 "app.wsgi:application"', workflow.inputs["app_start_command"])
        self.assertEqual("https://staging.example.com", workflow.inputs["zap_target"])
        self.assertEqual("app/build/outputs/apk/release/*.apk", workflow.inputs["mobile_app"])
        self.assertEqual("ci-app", workflow.inputs["bao_role"])
        self.assertTrue(all(coverage.configured_kinds(workflow).values()))

    def test_default_workflow_matches_the_new_project_snippet(self):
        text = coverage.render_workflow("github", "app", "tda-corp/app", coverage.CIOptions())
        self.assertIn("      bao_role: ci-app\n\n      # --- Runner (optional) ---\n", text)
        self.assertTrue(text.endswith("      # runs_on: ubuntu-latest\n"))
        other_org = coverage.render_workflow("github", "app", "someorg/app", coverage.CIOptions())
        self.assertIn("      runs_on: ubuntu-latest\n", other_org)

    def test_github_dast_needs_the_start_command(self):
        text = coverage.render_workflow("github", "app", "", coverage.CIOptions(dast_target="https://staging.x"))
        self.assertIn('# zap_target: "https://staging.x"', text)
        workflow = coverage.Workflow("github", "x", yaml.safe_load(text)["jobs"]["tdxguard"]["with"])
        self.assertFalse(coverage.configured_kinds(workflow)["dast"])

    def test_gitlab(self):
        options = coverage.CIOptions(
            dockerfiles=["Dockerfile"], image_ref="$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA", dast_target="https://staging.x"
        )
        text = coverage.render_workflow("gitlab", "app", "group/app", options)
        # GitLab's own !reference tags must not break the parsing.
        write(self.root, ".gitlab-ci.yml", text + "\nbuild:\n  script:\n    - !reference [.setup, script]\n")
        workflow = coverage.find_workflow(self.root)
        self.assertEqual("gitlab", workflow.platform)
        self.assertEqual("$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA", workflow.inputs["IMAGE_REF"])
        configured = coverage.configured_kinds(workflow)
        self.assertEqual((True, False, True), (configured["image"], configured["iast"], configured["dast"]))

    def test_gitlab_refuses_a_local_target(self):
        with self.assertRaises(ConfigError):
            coverage.render_workflow("gitlab", "app", "", coverage.CIOptions(dast_target="http://localhost:8000"))

    def test_gitlab_ci_without_tdxguard_is_no_workflow(self):
        write(self.root, ".gitlab-ci.yml", "stages: [build]\nbuild:\n  script: [make]\n")
        self.assertIsNone(coverage.find_workflow(self.root))

    def test_input_changes(self):
        existing = {"product": "app", "dockerfile": "Dockerfile", "app_start_command": "npm run dev"}
        suggested = coverage.suggested_inputs(
            "github",
            coverage.CIOptions(
                dockerfiles=["Dockerfile"], app_start_command="npm start", dast_target="http://127.0.0.1:3000"
            ),
        )
        self.assertEqual(
            [
                "= dockerfile (already set)",
                '~ app_start_command: "npm run dev" -> "npm start"',
                '+ zap_target: "http://127.0.0.1:3000"',
            ],
            coverage.input_changes(existing, suggested),
        )

    def test_validation(self):
        self.assertEqual("web/Dockerfile web", coverage.check_dockerfile("./web/Dockerfile web"))
        for bad in ("/Dockerfile", "../Dockerfile", "Dockerfile ../..", "a b c", "Docker;file"):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                coverage.check_dockerfile(bad)
        for bad in ("ftp://x", "staging.example.com", "https://x/$(id)"):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                coverage.check_url(bad, "URL")
        with self.assertRaises(ConfigError):
            coverage.check_command("npm start &", "Start")
        with self.assertRaises(ConfigError):
            coverage.check_command("a\nb", "Start")
        with self.assertRaises(ConfigError):
            coverage.check_image_ref("app:1 --privileged")
        self.assertEqual("ghcr.io/x:${{ github.sha }}", coverage.check_image_ref("ghcr.io/x:${{ github.sha }}"))


class TestDiagnose(unittest.TestCase):
    def facts(self, **kwargs):
        return coverage.RepoFacts(**kwargs)

    def test_no_workflow(self):
        rows = coverage.diagnose(self.facts(manifests=["go.mod"]), None, "github", None, "offline")
        by_kind = {row.kind: row for row in rows}
        self.assertEqual("tdxguard init --ci github", by_kind["sca"].action)
        self.assertEqual("", by_kind["image"].action)  # not expected: nothing to do
        self.assertFalse(coverage.exit_ok(rows))

    def test_missing_image_scan_github(self):
        workflow = coverage.Workflow("github", "x", {"product": "app"})
        facts = self.facts(dockerfiles=["Dockerfile", "web/Dockerfile"], iac_files=["Dockerfile"])
        coverage_data = {"image": {"last_import": None}, "sast": {"last_import": "2026-10-16T15:13:01+00:00"}}
        rows = {row.kind: row for row in coverage.diagnose(facts, workflow, "github", coverage_data, "ok")}
        self.assertEqual(coverage.YES, rows["image"].expected)
        self.assertEqual("dockerfile: |", rows["image"].action)
        self.assertIn("  web/Dockerfile", rows["image"].detail)
        self.assertEqual("2026-10-16", rows["sast"].received)
        self.assertEqual("never", rows["image"].received)
        self.assertFalse(coverage.exit_ok(list(rows.values())))

    def test_gitlab_suggestions(self):
        workflow = coverage.Workflow("gitlab", ".gitlab-ci.yml", {"PRODUCT": "app"})
        facts = self.facts(dockerfiles=["Dockerfile"], start_hints=[("npm start", "package.json")])
        rows = {row.kind: row for row in coverage.diagnose(facts, workflow, "gitlab", None, "old")}
        self.assertEqual('IMAGE_REF: "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA"', rows["image"].action)
        self.assertEqual('APP_START_COMMAND: "npm start"', rows["iast"].action)
        self.assertEqual(coverage.SUGGESTED, rows["iast"].expected)
        self.assertTrue(rows["dast"].action.startswith("ZAP_TARGET"))
        self.assertEqual("unknown (old server)", rows["sca"].received)

    def test_everything_expected_configured(self):
        workflow = coverage.Workflow("github", "x", {"dockerfile": "Dockerfile"})
        rows = coverage.diagnose(self.facts(dockerfiles=["Dockerfile"]), workflow, "github", None, "offline")
        self.assertTrue(coverage.exit_ok(rows))
        self.assertTrue(all(row.received == "not checked" for row in rows))

    def test_sast_names_the_languages_it_covers_and_those_it_does_not(self):
        workflow = coverage.Workflow("github", "x", {"product": "app"})
        facts = self.facts(source_languages={"php": 40, "javascript": 12, "rust": 7, "swift": 2})
        rows = {row.kind: row for row in coverage.diagnose(facts, workflow, "github", None, "offline")}
        self.assertEqual("php, javascript", rows["sast"].why)
        self.assertEqual(
            "Opengrep has no rules for rust (7 files), swift (2 files): SAST does not analyse that code. "
            "MobSF's mobile app analysis has rules for Swift and Objective-C.",
            rows["sast"].detail,
        )
        # Still configured, and a gap in the rules is not a gap in the workflow.
        self.assertTrue(coverage.exit_ok(list(rows.values())))

        rows = {row.kind: row for row in coverage.diagnose(self.facts(source_languages={"rust": 3}), workflow,
                                                             "github", None, "offline")}  # fmt: skip
        self.assertEqual("no rules for rust", rows["sast"].why)
        rows = {row.kind: row for row in coverage.diagnose(self.facts(source_languages={"java": 3}), workflow,
                                                             "github", None, "offline")}  # fmt: skip
        self.assertEqual(("java", ""), (rows["sast"].why, rows["sast"].detail))


class CommandTestCase(EnvironmentTestCase):
    def setUp(self):
        super().setUp()
        self.repo = self.home / "repo"
        self.repo.mkdir()
        for patcher in (
            patch("tdxguard.commands.gitinfo.find_root", return_value=self.repo),
            patch("tdxguard.commands.gitinfo.remote_url", return_value="https://github.com/tda-corp/shop.git"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)


class TestInitCI(CommandTestCase):
    def test_writes_the_workflow_with_detected_dockerfiles(self):
        webapp(self.repo)
        code, out, err = run_main(["init", "--yes"])
        self.assertEqual(EXIT_OK, code, err)
        inputs = yaml.safe_load((self.repo / ".github/workflows/tdxguard.yml").read_text())["jobs"]["tdxguard"]["with"]
        self.assertEqual(
            {"product": "shop", "bao_role": "ci-shop", "dockerfile": "Dockerfile\nweb/Dockerfile\n"}, inputs
        )
        # The start command is only suggested, never written on its own.
        self.assertIn("Possible start command for IAST: npm start", out)
        self.assertIn("CI covers 5 of 7", out)

    def test_flags(self):
        code, _, err = run_main(
            ["init", "--yes", "--dockerfile", "api/Dockerfile", "--start-command", "npm start",
             "--dast-target", "http://127.0.0.1:3000", "--health-url", "http://127.0.0.1:3000/"]
        )  # fmt: skip
        self.assertEqual(EXIT_OK, code, err)
        inputs = yaml.safe_load((self.repo / ".github/workflows/tdxguard.yml").read_text())["jobs"]["tdxguard"]["with"]
        self.assertEqual("api/Dockerfile", inputs["dockerfile"])
        self.assertEqual("npm start", inputs["app_start_command"])
        self.assertEqual("http://127.0.0.1:3000/", inputs["app_health_url"])
        self.assertEqual("http://127.0.0.1:3000", inputs["zap_target"])

    def test_invalid_flag_writes_nothing(self):
        code, _, err = run_main(["init", "--yes", "--dockerfile", "../Dockerfile"])
        self.assertEqual(EXIT_ERROR, code)
        self.assertIn("inside the repository", err)
        self.assertFalse((self.repo / ".tdxguard.yml").exists())

    def test_existing_workflow_is_not_overwritten_without_force(self):
        run_main(["init", "--yes"])
        path = self.repo / ".github/workflows/tdxguard.yml"
        before = path.read_text()

        code, out, _ = run_main(["init", "--yes", "--start-command", "npm start"])
        self.assertEqual(EXIT_OK, code)
        self.assertEqual(before, path.read_text())
        self.assertIn('+ app_start_command: "npm start"', out)
        self.assertIn("--force", out)

        code, out, _ = run_main(["init", "--yes", "--force", "--start-command", "npm start"])
        self.assertEqual(EXIT_OK, code)
        self.assertIn('app_start_command: "npm start"', path.read_text())

    def test_gitlab_ci_is_never_overwritten(self):
        (self.repo / ".gitlab-ci.yml").write_text("stages: [build]\n")
        code, out, _ = run_main(["init", "--yes", "--ci", "gitlab", "--force"])
        self.assertEqual(EXIT_OK, code)
        self.assertEqual("stages: [build]\n", (self.repo / ".gitlab-ci.yml").read_text())
        self.assertIn("PRODUCT: shop", out)

    def test_interactive(self):
        webapp(self.repo)
        answers = iter(["", "npm start", "http://127.0.0.1:3000/health", "http://127.0.0.1:3000"])
        with (
            patch("tdxguard.commands._interactive", return_value=True),
            patch("builtins.input", side_effect=lambda _prompt: next(answers)),
        ):
            code, out, err = run_main(["init"])
        self.assertEqual(EXIT_OK, code, err)
        inputs = yaml.safe_load((self.repo / ".github/workflows/tdxguard.yml").read_text())["jobs"]["tdxguard"]["with"]
        self.assertEqual("Dockerfile\nweb/Dockerfile\n", inputs["dockerfile"])  # Enter: yes
        self.assertEqual("npm start", inputs["app_start_command"])
        self.assertEqual("http://127.0.0.1:3000", inputs["zap_target"])
        self.assertIn("found: npm start", out)

    def test_no_ci(self):
        code, _, _ = run_main(["init", "--yes", "--no-ci"])
        self.assertEqual(EXIT_OK, code)
        self.assertFalse((self.repo / ".github").exists())


class TestDoctor(CommandTestCase):
    def test_offline_exit_codes(self):
        webapp(self.repo)
        code, out, _ = run_main(["doctor", "--offline"])
        self.assertEqual(EXIT_GATE, code)
        self.assertIn("Workflow: none found (github)", out)
        self.assertIn("tdxguard init --ci github", out)

        self.assertEqual(EXIT_OK, run_main(["doctor", "--offline", "--no-fail"])[0])

        run_main(["init", "--yes"])
        code, out, _ = run_main(["coverage", "--offline"])
        self.assertEqual(EXIT_OK, code)
        self.assertIn("Everything expected is configured in CI", out)
        self.assertIn('app_start_command: "npm start"', out)

    def test_json_and_server(self):
        write(self.repo, "Dockerfile", "FROM x\n")
        write(self.repo, ".tdxguard.yml", "project: shop\n")
        responses = [
            http.Response(200, json.dumps({"results": [{"id": 7, "name": "shop"}]}).encode(), {}),
            http.Response(
                200,
                json.dumps(
                    {"id": 7, "name": "shop", "scan_coverage": {"image": {"last_import": None, "checks": 0}}}
                ).encode(),
                {},
            ),
        ]
        with (
            patch.dict("os.environ", {"TDXGUARD_TOKEN": "t", "TDXGUARD_SERVER": "https://guard.example.com"}),
            patch("tdxguard.server.http.get", side_effect=responses) as get,
        ):
            code, out, _ = run_main(["doctor", "--json"])
        self.assertEqual(EXIT_GATE, code)
        self.assertEqual("https://guard.example.com/api/products/7/", get.call_args_list[1][0][0])
        data = json.loads(out)
        self.assertEqual("shop", data["project"])
        self.assertEqual("ok", data["server"])
        image = next(k for k in data["kinds"] if k["kind"] == "image")
        self.assertEqual("never", image["received"])
        self.assertEqual("tdxguard init --ci github", image["action"])

    def test_old_server(self):
        write(self.repo, ".tdxguard.yml", "project: shop\n")
        responses = [
            http.Response(200, json.dumps({"results": [{"id": 7, "name": "shop"}]}).encode(), {}),
            http.Response(200, json.dumps({"id": 7, "name": "shop"}).encode(), {}),
        ]
        with (
            patch.dict("os.environ", {"TDXGUARD_TOKEN": "t", "TDXGUARD_SERVER": "https://guard.example.com"}),
            patch("tdxguard.server.http.get", side_effect=responses),
        ):
            code, out, _ = run_main(["doctor", "--no-fail"])
        self.assertEqual(EXIT_OK, code)
        self.assertIn("does not report scan coverage yet", out)
        self.assertIn("unknown (old server)", out)


if __name__ == "__main__":
    unittest.main()
