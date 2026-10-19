"""
The scan engine: the container's command line, and a whole scan against fake scanners that
record their arguments and write recorded reports, so that the flags, the report files and
summary.json can be compared with what the bash entrypoint produced.
"""

import contextlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from tdxguard import reports
from tdxguard.engine import __main__ as container
from tdxguard.engine import scan, tools

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "reports"

# summary.json as the bash entrypoint wrote it, plus "engine".
SUMMARY_KEYS = [
    "version", "engine", "tools", "started_at", "duration_seconds", "secrets_mode", "skipped", "rows", "errors",
    "warnings",
]  # fmt: skip

FAKE_SCANNER = r"""
import json, os, shutil, sys
name = os.path.basename(sys.argv[0])
args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps([name] + args) + "\n")
fixtures = os.environ["FAKE_FIXTURES"]
if name in os.environ.get("FAKE_FAIL", "").split(","):
    sys.exit(3)
def out(flag):
    return args[args.index(flag) + 1]
if name == "betterleaks":
    # The engine's default config lives in its work directory, gone once the scan is over.
    if "-c" in args and os.path.isabs(out("-c")):
        shutil.copy(out("-c"), os.environ["FAKE_LOG"] + ".config")
    content = os.environ.get("FAKE_BETTERLEAKS")
    if content is not None:
        open(out("-r"), "w").write(content)
    else:
        shutil.copy(os.path.join(fixtures, "betterleaks.fixture.json"), out("-r"))
elif name == "opengrep":
    rules = out("--config")
    with open(os.environ["FAKE_LOG"] + ".rules", "w") as listing:
        listing.write("\n".join(sorted(os.path.relpath(os.path.join(d, f), rules)
                                         for d, _, fs in os.walk(rules) for f in fs)))
    shutil.copy(os.path.join(fixtures, "opengrep.fixture.json"), out("--output"))
    sys.exit(int(os.environ.get("FAKE_OPENGREP_EXIT", "0")))
elif name == "trivy":
    if args[0] == "fs":
        report = "trivy.fixture.json" if "misconfig" in args else "sbom.fixture.json"
    else:
        report = "trivy-image-secrets.fixture.json" if "secret" in args else "sbom-image.fixture.json"
    shutil.copy(os.path.join(fixtures, report), out("--output"))
"""


@unittest.skipUnless(os.name == "posix", "the fake scanners are scripts with a shebang")
class EngineTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.src = self.tmp / "repo"
        (self.src / "app").mkdir(parents=True)
        (self.src / "app" / "main.py").write_text("print('hello')\n")
        (self.src / "requirements.txt").write_text("flask==0.12\n")
        self.out = self.tmp / "out"
        self.out.mkdir()
        self.log = self.tmp / "calls.jsonl"
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        for name in ("betterleaks", "opengrep", "trivy"):
            path = bin_dir / name
            path.write_text(f"#!{sys.executable}\n" + FAKE_SCANNER)
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        rules = self.tmp / "rules"
        (rules / "python" / "flask" / "security" / "audit").mkdir(parents=True)
        (rules / "python" / "flask" / "security" / "audit" / "directly-returned-format-string.yaml").write_text(
            "rules:\n  - id: directly-returned-format-string\n"
        )
        (rules / "generic" / "secrets" / "security").mkdir(parents=True)
        (rules / "generic" / "secrets" / "security" / "detected-google-api-key.yaml").write_text("rules: []\n")
        (rules / "generic" / "nginx" / "security").mkdir(parents=True)
        (rules / "generic" / "nginx" / "security" / "alias-path-traversal.yaml").write_text("rules: []\n")
        (rules / tools.MARKER).write_text("{}")
        self.toolset = tools.Toolset(
            betterleaks=bin_dir / "betterleaks", opengrep=bin_dir / "opengrep", trivy=bin_dir / "trivy", rules=rules
        )
        self.environment = dict(os.environ, FAKE_LOG=str(self.log), FAKE_FIXTURES=str(FIXTURES))
        self.messages = []
        self.output = []

    def run_scan(self, **kwargs):
        options = scan.Options(src=self.src, out=self.out, version="test", **kwargs)
        return scan.Scan(
            options, self.toolset, scan.scanner_environment(self.environment), log=self.messages.append,
            output=self.output.append,
        ).run()  # fmt: skip

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def summary(self):
        return json.loads((self.out / "summary.json").read_text())


class TestScan(EngineTestCase):
    def test_full_scan(self):
        code = self.run_scan(
            excludes=["mobile/", "*.lock"],
            images=[scan.ImageTarget("tdxguard-local/api:scan", "api"),
                    scan.ImageTarget("ghcr.io/org/web:1.2", "web-1.2", remote=True)],
        )  # fmt: skip
        self.assertEqual(0, code, self.messages)
        summary = self.summary()
        self.assertEqual(SUMMARY_KEYS, list(summary))
        self.assertEqual("native", summary["engine"])
        self.assertEqual("test", summary["version"])
        self.assertEqual(tools.Toolset.versions(), summary["tools"])
        self.assertEqual(("dir", [], [], []), (summary["secrets_mode"], summary["skipped"], summary["errors"],
                                               summary["warnings"]))  # fmt: skip
        self.assertEqual(
            [
                ["betterleaks", "Betterleaks (secrets)", "betterleaks.json", 1, 1, None],
                ["opengrep", "Opengrep (SAST)", "opengrep.sarif", 7, 5, None],
                ["trivy", "Trivy (IaC)", "trivy.sarif", 3, 2, None],
                ["trivy", "Trivy (dependencies)", "sbom.cdx.json", 11, 6, None],
                ["image", "Trivy (image `tdxguard-local/api:scan`)", "sbom-image-api.cdx.json", 25, 22,
                 "tdxguard-local/api:scan"],
                ["image", "Trivy (image secrets)", "trivy-image-api.sarif", 1, 1, "tdxguard-local/api:scan"],
                ["image", "Trivy (image `ghcr.io/org/web:1.2`)", "sbom-image-web-1.2.cdx.json", 25, 22,
                 "ghcr.io/org/web:1.2"],
                ["image", "Trivy (image secrets)", "trivy-image-web-1.2.sarif", 1, 1, "ghcr.io/org/web:1.2"],
            ],
            [[r["scanner"], r["label"], r["report"], r["findings"], r["severe"], r.get("image")]
             for r in summary["rows"]],
        )  # fmt: skip
        self.assertEqual(
            sorted(["betterleaks.json", "opengrep.sarif", "trivy.sarif", "sbom.cdx.json", "summary.json",
                    "sbom-image-api.cdx.json", "trivy-image-api.sarif", "sbom-image-web-1.2.cdx.json",
                    "trivy-image-web-1.2.sarif"]),
            sorted(p.name for p in self.out.iterdir()),
        )  # fmt: skip

        calls = self.calls()
        out = str(self.out)
        betterleaks = calls[0]
        self.assertEqual(["betterleaks", "dir", ".", "-c"], betterleaks[:4])
        self.assertTrue(betterleaks[4].endswith("betterleaks.toml"), betterleaks)
        self.assertEqual(
            ["-f", "json", "-r", f"{out}/betterleaks.json", "--exit-code", "0", "--redact", "--no-banner"],
            betterleaks[5:],
        )
        self.assertEqual(scan.BETTERLEAKS_DEFAULT_CONFIG, Path(f"{self.log}.config").read_text())
        opengrep = calls[1]
        self.assertEqual(["opengrep", "scan", "--sarif", "--output", f"{out}/opengrep.sarif", "--quiet", "--config"],
                         opengrep[:7])  # fmt: skip
        self.assertTrue(opengrep[7].endswith("ogrules-security"))
        self.assertEqual(
            ["--exclude=node_modules", "--exclude=bower_components", "--exclude=vendor", "--exclude=Pods",
             "--exclude=Carthage", "--exclude=.venv", "--exclude=dist", "--exclude=build", "--exclude=*.md", "--exclude=*.example", "--exclude=ogrules", "--exclude=ogrules-security",
             "--exclude=mobile/", "--exclude=*.lock", "."],
            opengrep[8:],
        )  # fmt: skip
        skip = ["--skip-dirs", "**/node_modules", "--skip-dirs", "**/bower_components", "--skip-dirs", "**/vendor",
                "--skip-dirs", "**/Pods", "--skip-dirs", "**/Carthage", "--skip-dirs", ".venv",
                "--skip-dirs", "mobile/", "--skip-files", "mobile/",
                "--skip-dirs", "*.lock", "--skip-files", "*.lock"]  # fmt: skip
        self.assertEqual(
            ["trivy", "fs", ".", "--scanners", "misconfig", "--format", "sarif", "--output", f"{out}/trivy.sarif",
             *skip],
            calls[2],
        )  # fmt: skip
        self.assertEqual(
            ["trivy", "fs", ".", "--format", "cyclonedx", "--scanners", "vuln", "--output", f"{out}/sbom.cdx.json",
             *skip],
            calls[3],
        )  # fmt: skip
        self.assertEqual(
            ["trivy", "image", "--format", "cyclonedx", "--scanners", "vuln", "--output",
             f"{out}/sbom-image-api.cdx.json", "tdxguard-local/api:scan"],
            calls[4],
        )  # fmt: skip
        self.assertEqual(
            ["trivy", "image", "--image-src", "remote", "--scanners", "secret", "--format", "sarif", "--output",
             f"{out}/trivy-image-web-1.2.sarif", "ghcr.io/org/web:1.2"],
            calls[7],
        )  # fmt: skip
        self.assertEqual(8, len(calls))
        # The helper scripts ran for real: requirements.txt declares Flask.
        self.assertIn("opengrep-prune-rules: flask name-only rules (1): whole repository", self.output)
        self.assertTrue(any(line.startswith("sarif-enrich: opengrep.sarif") for line in self.output), self.output)

    def test_repository_secrets_config_wins(self):
        """A repository's own config replaces the default one, as in CI."""
        (self.src / ".gitleaks.toml").write_text("[extend]\nuseDefault = true\n")
        self.run_scan(skips=["opengrep", "trivy"])
        self.assertEqual(["-c", ".gitleaks.toml"], self.calls()[0][3:5])

        # Betterleaks reads a .betterleaks.toml by itself; -c would override it.
        (self.src / ".gitleaks.toml").unlink()
        (self.src / ".betterleaks.toml").write_text("[extend]\nuseDefault = true\n")
        self.log.unlink()
        self.run_scan(skips=["opengrep", "trivy"])
        self.assertNotIn("-c", self.calls()[0])

    def test_what_git_ignores_is_left_out(self):
        """Ignored build output and a nested worktree: not scanned, the repository's own config still applies."""
        subprocess.run(["git", "init", "-q", str(self.src)], check=True)
        (self.src / ".gitignore").write_text("target/\n*.log\n")
        (self.src / ".gitleaks.toml").write_text("[extend]\nuseDefault = true\n")
        (self.src / "target" / "debug").mkdir(parents=True)
        (self.src / "debug.log").write_text("x\n")
        (self.src / "a [b]").mkdir()
        subprocess.run(["git", "init", "-q", str(self.src / "a [b]")], check=True)
        self.assertEqual(["a [b]/", "debug.log", "target/"], scan.outside_repository(self.src))

        self.run_scan(skips=["opengrep"])
        betterleaks = self.calls()[0]
        self.assertTrue(betterleaks[4].endswith("betterleaks.toml"), betterleaks)
        config = tomllib.loads(Path(f"{self.log}.config").read_text())
        self.assertEqual({"path": str((self.src / ".gitleaks.toml").resolve())}, config["extend"])
        paths = config["allowlists"][0]["paths"]
        self.assertEqual(["^a \\[b\\]/", "^debug\\.log$", "^target/"], paths)
        for path, left_out in (
            ("target/debug/app.py", True),
            ("a [b]/x.py", True),
            ("debug.log", True),
            ("src/debug.log", False),
            ("debug.logx", False),
        ):
            self.assertEqual(left_out, any(re.search(p, path) for p in paths), path)  # fmt: skip
        trivy = self.calls()[1]
        self.assertIn(["--skip-dirs", "a \\[b\\]"], [trivy[i : i + 2] for i in range(len(trivy))])
        self.assertIn(["--skip-files", "debug.log"], [trivy[i : i + 2] for i in range(len(trivy))])
        self.assertIn(["--skip-dirs", "target"], [trivy[i : i + 2] for i in range(len(trivy))])

        # The history holds no ignored file: git mode keeps the repository's config as it is.
        self.log.unlink()
        self.run_scan(skips=["opengrep", "trivy"], secrets_mode="git")
        self.assertEqual(["-c", ".gitleaks.toml"], self.calls()[0][3:5])

    def test_default_secrets_config_skips_vendored_code(self):
        paths = re.search(r"paths = \['''(.+)'''\]", scan.BETTERLEAKS_DEFAULT_CONFIG).group(1)
        for path in (
            "Carthage/Checkouts/Alamofire/Tests/a.swift",
            "Pods/Firebase/x.m",
            "web/node_modules/a/b.js",
            "vendor/laravel/framework/c.php",
            "bower_components/d.js",
        ):
            self.assertIsNotNone(re.search(paths, path), path)
        for path in ("App/Config.swift", "src/vendors.ts", "MyPods/a.m", "app/Carthage.swift"):
            self.assertIsNone(re.search(paths, path), path)

    def test_rule_tree_untouched_and_marker_not_a_rule(self):
        self.run_scan(skips=["betterleaks", "trivy"])
        # Secrets are Betterleaks' job: the copy Opengrep reads has no generic/secrets.
        loaded = Path(f"{self.log}.rules").read_text().splitlines()
        self.assertIn("generic/nginx/security/alias-path-traversal.yaml", loaded)
        self.assertFalse([path for path in loaded if path.startswith("generic/secrets/")], loaded)
        self.assertTrue((self.toolset.rules / "generic" / "secrets" / "security").is_dir())
        # The pruning works on a copy; the installed rules stay as they are.
        self.assertTrue(
            (
                self.toolset.rules / "python" / "flask" / "security" / "audit" / "directly-returned-format-string.yaml"
            ).is_file()
        )

    def test_skips_and_git_mode(self):
        code = self.run_scan(skips=["opengrep", "trivy", "trivy"], secrets_mode="git", log_opts="--all -n 5")
        summary = self.summary()
        # Not a git repository: betterleaks git refuses, as in the bash entrypoint.
        self.assertEqual(1, code)
        self.assertEqual(["opengrep", "trivy"], summary["skipped"])
        self.assertIn("--secrets-mode git needs", summary["errors"][0])
        self.assertEqual([], self.calls())

    def test_scanner_failures_are_errors_not_crashes(self):
        self.environment["FAKE_FAIL"] = "trivy,betterleaks"
        code = self.run_scan(images=[scan.ImageTarget("app:1", "app", remote=True)])
        summary = self.summary()
        self.assertEqual(1, code)
        self.assertEqual(
            [
                "betterleaks exited with status 3",
                "trivy fs --scanners misconfig failed",
                "trivy fs --scanners vuln failed",
                "trivy image --scanners vuln failed for app:1",
                "trivy image --scanners secret failed for app:1",
            ],
            summary["errors"],
        )
        self.assertEqual(["opengrep.sarif"], [row["report"] for row in summary["rows"]])
        self.assertFalse((self.out / "trivy.sarif").exists())

    def test_opengrep_nonzero_with_report_is_a_warning(self):
        self.environment["FAKE_OPENGREP_EXIT"] = "2"
        code = self.run_scan(skips=["betterleaks", "trivy"])
        self.assertEqual(0, code)
        self.assertEqual(["opengrep exited with status 2 but wrote a report"], self.summary()["warnings"])

    def test_firebase_client_key_is_not_severe(self):
        findings = [
            {"RuleID": "gcp-api-key", "File": "android/app/src/prod/google-services.json"},
            {"RuleID": "gcp-api-key", "File": "lib/firebase_options_dev.dart"},
            {"RuleID": "gcp-api-key", "File": "lib/config.dart"},
        ]
        self.environment["FAKE_BETTERLEAKS"] = json.dumps(findings)
        self.run_scan(skips=["opengrep", "trivy"])
        row = self.summary()["rows"][0]
        self.assertEqual((3, 1), (row["findings"], row["severe"]))
        self.assertEqual(1, reports.count(self.out).high)

    def test_clean_betterleaks_and_uncountable_report(self):
        self.environment["FAKE_BETTERLEAKS"] = "null"
        self.assertEqual(0, self.run_scan(skips=["opengrep", "trivy"]))
        self.assertEqual(0, self.summary()["rows"][0]["findings"])

        self.environment["FAKE_BETTERLEAKS"] = "true"
        self.assertEqual(1, self.run_scan(skips=["opengrep", "trivy"]))
        self.assertEqual(["betterleaks.json: cannot count the findings (not valid for its format)"],
                         self.summary()["errors"])  # fmt: skip

        self.environment["FAKE_BETTERLEAKS"] = ""
        self.assertEqual(1, self.run_scan(skips=["opengrep", "trivy"]))
        self.assertIn("betterleaks wrote no valid betterleaks.json", self.summary()["errors"])

    def test_stale_reports_are_removed(self):
        (self.out / "trivy.sarif").write_text("{}")
        self.environment["FAKE_FAIL"] = "trivy"
        self.run_scan(skips=["betterleaks", "opengrep"])
        self.assertFalse((self.out / "trivy.sarif").exists())


class TestEnvironment(unittest.TestCase):
    def test_log_only_settings_and_locale(self):
        environment = scan.scanner_environment({"LANG": "C"}, platform="linux")
        self.assertEqual("true", environment["TRIVY_NO_PROGRESS"])
        self.assertEqual("true", environment["TRIVY_SKIP_VERSION_CHECK"])
        self.assertEqual("C.UTF-8", environment["LC_ALL"])
        self.assertEqual("en_US.UTF-8", scan.scanner_environment({}, platform="darwin")["LC_ALL"])
        self.assertNotIn("LC_ALL", scan.scanner_environment({"LANG": "de_DE.UTF-8"}, platform="linux"))
        self.assertNotIn("LC_ALL", scan.scanner_environment({}, platform="win32"))
        self.assertEqual("1", scan.scanner_environment({}, platform="win32")["PYTHONUTF8"])
        self.assertEqual("false", scan.scanner_environment({"TRIVY_NO_PROGRESS": "false"})["TRIVY_NO_PROGRESS"])

    def test_work_dir_avoids_rule_root_segments(self):
        """sarif-enrich.py trims a rule id at its first segment named like a rule root."""
        with tempfile.TemporaryDirectory() as tmp:
            # "c.smith" is two segments of a rule id, "c" and "smith"
            for name in ("go", "c.smith"):
                trap = Path(tmp) / name
                trap.mkdir()
                with patch.dict(os.environ, {"HOME": tmp, "USERPROFILE": tmp}):
                    work = scan.make_work_dir(trap)
                try:
                    below = work.parts[len(Path(tmp).resolve().parts) :]
                    segments = {segment for part in below for segment in part.split(".")}
                    self.assertFalse(segments & set(tools.RULE_LANGUAGES), work)
                    self.assertTrue(work.is_dir())
                finally:
                    shutil.rmtree(work, ignore_errors=True)

    def test_summary_written_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan.write_summary(Path(tmp), {"rows": [], "label": "Trivy (image `x`) — ü"})
            self.assertEqual(["summary.json"], os.listdir(tmp))
            self.assertIn("ü", (Path(tmp) / "summary.json").read_text(encoding="utf-8"))


class TestContainerArguments(unittest.TestCase):
    def test_parse(self):
        options, wants_help = container.parse(
            ["--exclude", "mobile/", "--exclude=docs", "--image", "a:1=a", "--remote-image=ghcr.io/o/b:2=b-2",
             "--skip", "opengrep", "--skip=trivy", "--secrets-mode", "git", "--log-opts=--all -n 5"]
        )  # fmt: skip
        self.assertFalse(wants_help)
        self.assertEqual(["mobile/", "docs"], options["excludes"])
        self.assertEqual(
            [scan.ImageTarget("a:1", "a"), scan.ImageTarget("ghcr.io/o/b:2", "b-2", remote=True)], options["images"]
        )
        self.assertEqual(["opengrep", "trivy"], options["skips"])
        self.assertEqual(("git", "--all -n 5"), (options["secrets_mode"], options["log_opts"]))
        # The reference may hold "=" itself; the slug is after the last one.
        self.assertEqual("reg/x@sha256=1", container.parse(["--image", "reg/x@sha256=1=x"])[0]["images"][0].ref)

    def test_usage_errors(self):
        cases = {
            ("--exclude",): "--exclude needs a value",
            ("--exclude", ""): "--exclude needs a value",
            ("--image", "nослаг"): "--image expects <ref>=<slug>",
            ("--image", "=x"): "--image has an empty reference",
            ("--image", "a=Bad"): "--image slug must match",
            ("--skip", "zap"): "--skip expects betterleaks, opengrep, trivy or image, got: zap",
            ("--secrets-mode", "all"): "--secrets-mode expects dir or git",
            ("--bogus",): "unknown option: --bogus",
        }
        for argv, message in cases.items():
            with self.subTest(argv=argv), self.assertRaises(container.UsageError) as cm:
                container.parse(list(argv))
            self.assertIn(message, str(cm.exception))

    def run_main(self, argv, environ=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.dict(os.environ, environ or {}),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            code = container.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_exit_codes(self):
        self.assertEqual(0, self.run_main(["--help"])[0])
        self.assertEqual(0, self.run_main([])[0])
        code, out, _ = self.run_main(["--version"], {"TDXGUARD_SCANNER_VERSION": "v1.2.3"})
        self.assertEqual(0, code)
        self.assertEqual(
            f"tdxguard-scanner v1.2.3\nbetterleaks {tools.BETTERLEAKS_VERSION}\nopengrep {tools.OPENGREP_VERSION} "
            f"(rules {tools.OPENGREP_RULES_SHA})\ntrivy {tools.TRIVY_VERSION}\n",
            out,
        )
        self.assertEqual(2, self.run_main(["frobnicate"])[0])
        self.assertEqual(2, self.run_main(["scan", "--skip", "zap"])[0])
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err = self.run_main(["scan"], {"TDXGUARD_SRC": str(Path(tmp) / "missing"), "TDXGUARD_OUT": tmp})
            self.assertEqual(2, code)
            self.assertIn("is not a readable directory", err)
            code, _, err = self.run_main(["scan"], {"TDXGUARD_SRC": tmp, "TDXGUARD_OUT": str(Path(tmp) / "missing")})
            self.assertEqual(2, code)
            self.assertIn("is not writable", err)
            # No tools installed in the given directory: a usable error, not a traceback.
            code, _, err = self.run_main(
                ["scan"], {"TDXGUARD_SRC": tmp, "TDXGUARD_OUT": tmp, "TDXGUARD_TOOLS_DIR": tmp}
            )
            self.assertEqual(2, code)
            self.assertIn("Not installed", err)

    def test_container_environment_without_home(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"HOME": "/nonexistent-home"}):
            os.environ.pop("TRIVY_CACHE_DIR", None)
            environment = container.container_environment(Path(tmp), "12345")
            self.assertEqual(str(Path(tmp) / "home"), environment["HOME"])
            self.assertTrue(Path(environment["HOME"]).is_dir())
            self.assertEqual("safe.directory", environment["GIT_CONFIG_KEY_0"])
            if not os.path.isdir("/cache"):
                self.assertEqual(str(Path(tmp) / "trivy-cache"), environment["TRIVY_CACHE_DIR"])


if __name__ == "__main__":
    unittest.main()
