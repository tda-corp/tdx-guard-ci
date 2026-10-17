"""
The standalone executable (tdxguard.frozen): the helper scripts never need a Python
interpreter when frozen, the hidden helper command runs them like `python -I -X utf8`, and
nothing changes for the package.
"""

import contextlib
import io
import json
import os
import re
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import tdxguard
from tdxguard import __main__ as cli
from tdxguard import frozen
from tdxguard.engine import helpers, scan
from tests.test_engine import EngineTestCase

CLI_ROOT = Path(__file__).resolve().parents[1]


@contextlib.contextmanager
def frozen_as(executable):
    """Pretends to be the PyInstaller executable at `executable`."""
    with patch.object(sys, "frozen", True, create=True), patch.object(sys, "executable", str(executable)):
        yield


class TestHelperCommand(unittest.TestCase):
    def test_package_runs_the_interpreter_isolated_in_utf8_mode(self):
        self.assertEqual(
            [sys.executable, "-I", "-X", "utf8", str(helpers.SARIF_ENRICH), "a.sarif", "."],
            frozen.helper_command(helpers.SARIF_ENRICH, ["a.sarif", "."]),
        )

    def test_frozen_runs_the_executable_itself(self):
        with frozen_as("/opt/tdxguard/tdxguard"):
            self.assertEqual(
                ["/opt/tdxguard/tdxguard", "__helper", "sarif-enrich", "a.sarif", ".", "--unescape-html"],
                frozen.helper_command(helpers.SARIF_ENRICH, ["a.sarif", ".", "--unescape-html"]),
            )
            self.assertEqual(
                ["/opt/tdxguard/tdxguard", "__helper", "opengrep-prune-rules", "rules", "."],
                frozen.helper_command(helpers.OPENGREP_PRUNE_RULES, ["rules", "."]),
            )
            with self.assertRaises(ValueError):
                frozen.helper_command(Path("other.py"), [])

    def test_every_bundled_helper_has_a_name(self):
        self.assertEqual({helpers.SARIF_ENRICH, helpers.OPENGREP_PRUNE_RULES}, set(frozen.HELPERS.values()))


class TestRunHelper(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)

    def run_main(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_runs_the_helper_as_main_with_its_argv(self):
        sarif = self.tmp / "report.sarif"
        sarif.write_text(
            json.dumps({"runs": [{"results": [{"message": {"text": "&#39;x&#39; is &quot;bad&quot;"}}]}]}),
            encoding="utf-8",
        )
        argv_before = list(sys.argv)
        code, stdout, _ = self.run_main(["__helper", "sarif-enrich", str(sarif), str(self.tmp), "--unescape-html"])
        self.assertEqual(0, code)
        self.assertIn("sarif-enrich: report.sarif", stdout)
        self.assertEqual("'x' is \"bad\"", json.loads(sarif.read_text())["runs"][0]["results"][0]["message"]["text"])
        self.assertEqual(argv_before, sys.argv)

    def test_exit_status_of_the_helper(self):
        code, _, stderr = self.run_main(["__helper", "sarif-enrich"])
        self.assertEqual(2, code)
        self.assertIn("sarif-enrich.py", stderr)

    def test_unknown_helper(self):
        code, _, stderr = self.run_main(["__helper", "rm-rf"])
        self.assertEqual(2, code)
        self.assertIn("opengrep-prune-rules, sarif-enrich", stderr)

    def test_frozen_without_utf8_mode_is_refused(self):
        with frozen_as("/opt/tdxguard"), patch.object(frozen.sys, "flags", type("F", (), {"utf8_mode": 0})()):
            code, _, stderr = self.run_main(["__helper", "sarif-enrich", "x", "y"])
        self.assertEqual(2, code)
        self.assertIn("UTF-8", stderr)

    def test_working_directory_cannot_shadow_a_module(self):
        (self.tmp / "json.py").write_text("raise SystemExit('shadowed')\n")
        sarif = self.tmp / "r.sarif"
        sarif.write_text('{"runs": []}', encoding="utf-8")
        cwd = os.getcwd()
        saved_path = list(sys.path)
        saved_json = sys.modules.pop("json")
        try:
            os.chdir(self.tmp)
            sys.path.insert(0, "")
            code, _, _ = self.run_main(["__helper", "sarif-enrich", "r.sarif", "."])
        finally:
            os.chdir(cwd)
            sys.path[:] = saved_path
            sys.modules["json"] = saved_json
        self.assertEqual(0, code)


@unittest.skipUnless(os.name == "posix", "the fake executable and scanners are scripts with a shebang")
class TestFrozenScanSpawnsNoPython(EngineTestCase):
    """A whole scan as the executable: every process started is a scanner, git or the executable."""

    def test_full_scan(self):
        executable = self.tmp / "dist" / "tdxguard"
        executable.parent.mkdir()
        # Stands in for the PyInstaller executable: runs this package's entry point.
        executable.write_text(f'#!/bin/sh\nPYTHONPATH={CLI_ROOT} exec {sys.executable} -X utf8 -m tdxguard "$@"\n')
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        started = []
        real_popen = scan.subprocess.Popen

        def recording_popen(command, *args, **kwargs):
            started.append([str(part) for part in command])
            return real_popen(command, *args, **kwargs)

        with frozen_as(executable), patch.object(scan.subprocess, "Popen", recording_popen):
            code = self.run_scan()
        self.assertEqual(0, code, self.messages + self.output)
        programs = [Path(command[0]).name for command in started]
        self.assertIn("tdxguard", programs)
        for command in started:
            self.assertNotRegex(Path(command[0]).name, re.compile(r"^python", re.IGNORECASE), command)
        helper_calls = [command[1:3] for command in started if Path(command[0]).name == "tdxguard"]
        self.assertIn(["__helper", "opengrep-prune-rules"], helper_calls)
        self.assertIn(["__helper", "sarif-enrich"], helper_calls)


class TestSslContext(unittest.TestCase):
    def test_package_keeps_urllibs_default(self):
        self.assertIsNone(frozen.ssl_context())

    @unittest.skipIf(os.name == "nt", "Windows reads the system certificate store")
    def test_frozen_loads_the_system_bundle(self):
        bundle = next((path for path in frozen.SYSTEM_CA_BUNDLES if os.path.isfile(path)), None)
        if bundle is None:
            self.skipTest("no system CA bundle on this machine")
        with frozen_as("/opt/tdxguard"):
            context = frozen.ssl_context()
        self.assertIsNotNone(context)
        self.assertGreater(context.cert_store_stats()["x509_ca"], 0)


class TestVersion(unittest.TestCase):
    def test_version_line(self):
        self.assertRegex(frozen.version_line("1.2.3"), r"^tdxguard 1\.2\.3 \([a-z0-9]+-[a-z0-9_]+, python 3\.\d+")
        with frozen_as("/opt/tdxguard"):
            self.assertRegex(frozen.version_line("1.2.3"), r"^tdxguard 1\.2\.3 \([a-z0-9]+-[a-z0-9_]+, standalone\)$")

    def test_package_version_matches_pyproject(self):
        pyproject = (CLI_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn(f'\nversion = "{tdxguard.__version__}"\n', pyproject)


if __name__ == "__main__":
    unittest.main()
