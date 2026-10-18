"""
`tdxguard report`: the vendored generator stays identical to ci-templates/compliance-report.py,
the API adapter, the arguments, the browser discovery per OS and the PDF printing.
"""

import contextlib
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

from tdxguard import __main__ as entry
from tdxguard import assessment, credentials, http
from tdxguard.assessment import browser
from tdxguard.assessment import compliance_report as generator
from tdxguard.errors import EXIT_ERROR, EXIT_OK, ApiError, AuthenticationError, CLIError, ConfigError

REPOSITORY = Path(__file__).resolve().parents[2]
TEMPLATE = REPOSITORY / "ci-templates" / "compliance-report.py"
FIXTURE = REPOSITORY / "ci-templates" / "tests" / "fixtures" / "report-data.json"
VENDORED = Path(generator.__file__)


def run_main(argv):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = entry.main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


def minimal_data(name="tdx-demo"):
    """The smallest data the generator renders: a product without findings."""
    return {
        "format_version": generator.REPORT_FORMAT_VERSION,
        "fetched": "2026-10-18T00:00:00+00:00",
        "product": {"id": 1, "name": name, "repository_default_branch": 5},
        "branch": {"id": 5, "name": "main"},
        "warnings": [],
        "active": [],
        "decided": [],
        "resolved_count": 0,
        "checks": [],
        "logs": [],
        "logs_mode": "empty",
        "period": {"days": 30, "age": "Past 30 days", "resolved": 0},
        "settings": None,
        "product_group": None,
        "metrics": None,
        "rules": {},
    }


@unittest.skipUnless(TEMPLATE.is_file(), "ci-templates/ is not next to the package")
class TestGeneratorInSync(unittest.TestCase):
    def test_vendored_copy_is_identical(self):
        self.assertEqual(
            TEMPLATE.read_bytes(),
            VENDORED.read_bytes(),
            f"{VENDORED} differs from {TEMPLATE}; copy it again: "
            "cp ci-templates/compliance-report.py cli/tdxguard/assessment/compliance_report.py",
        )


class TestArguments(unittest.TestCase):
    def parse(self, argv):
        return entry.build_parser().parse_args(["report"] + argv)

    def test_defaults(self):
        args = self.parse([])
        self.assertEqual("vi", args.lang)
        self.assertEqual(30, args.period_days)
        self.assertIsNone(args.product)
        self.assertIsNone(args.out)
        self.assertFalse(args.open or args.no_pdf or args.all_branches)

    def test_options(self):
        args = self.parse(["--lang", "en", "--branch", "develop", "--out", "report", "--product", "x", "--open"])
        self.assertEqual(("en", "develop", "report", "x", True), (args.lang, args.branch, args.out, args.product, True))

    def test_branch_and_all_branches_exclude_each_other(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.parse(["--branch", "main", "--all-branches"])

    def test_languages_and_periods_come_from_the_generator(self):
        self.assertEqual(sorted(generator.STRINGS), assessment.LANGUAGES)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.parse(["--lang", "de"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.parse(["--period-days", "14"])

    def test_generator_args(self):
        args = assessment.Options(
            product="p", branch="develop", lang="en", period_days=90, prepared_for="ACME", classification=""
        ).generator_args()
        self.assertEqual(("p", "develop", "en", 90, "ACME", ""), (args.product, args.branch, args.lang,
                         args.period_days, args.prepared_for, args.classification))  # fmt: skip
        self.assertEqual("", args.from_data)
        self.assertEqual("TDA security team", args.tester)
        self.assertEqual("Confidential", assessment.Options(product="p").generator_args().classification)

    def test_output_base(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        self.assertEqual(Path("tdx-scribe-security-report-vi"), assessment.output_base(None, "tdx-scribe", "vi"))
        self.assertEqual(Path("report"), assessment.output_base("report", "p", "vi"))
        self.assertEqual(Path("out/report"), assessment.output_base("out/report.html", "p", "vi"))
        self.assertEqual(Path("report"), assessment.output_base("report.PDF", "p", "vi"))
        self.assertEqual(Path("report.v2"), assessment.output_base("report.v2", "p", "vi"))
        self.assertEqual(Path(tmp) / "p-security-report-en", assessment.output_base(tmp, "p", "en"))
        self.assertEqual("a-b-security-report-en", assessment.default_base("a/b", "en"))


class TestBrowserDiscovery(unittest.TestCase):
    def find(self, system, files=(), on_path=None, environ=None, home="/home/jane"):
        on_path = on_path or {}
        return browser.find_browser(
            environ=environ or {},
            system=system,
            which=lambda name: on_path.get(name),
            is_file=lambda path: path in files,
            home=home,
        )

    def test_macos_applications(self):
        chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        edge = "/Users/jane/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
        self.assertEqual(browser.Browser("Google Chrome", chrome), self.find("Darwin", {chrome, edge}))
        self.assertEqual(browser.Browser("Microsoft Edge", edge), self.find("Darwin", {edge}, home="/Users/jane"))
        self.assertEqual(
            browser.Browser("Chromium", "/opt/homebrew/bin/chromium"),
            self.find("Darwin", on_path={"chromium": "/opt/homebrew/bin/chromium"}),
        )
        self.assertIsNone(self.find("Darwin"))

    def test_windows_install_locations(self):
        environ = {
            "PROGRAMFILES": r"C:\Program Files",
            "ProgramFiles(x86)": r"C:\Program Files (x86)",
            "LOCALAPPDATA": r"C:\Users\jane\AppData\Local",
        }
        edge = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        chrome = r"C:\Users\jane\AppData\Local\Google\Chrome\Application\chrome.exe"
        self.assertEqual(browser.Browser("Microsoft Edge", edge), self.find("Windows", {edge}, environ=environ))
        self.assertEqual(
            browser.Browser("Google Chrome", chrome), self.find("Windows", {edge, chrome}, environ=environ)
        )

    def test_windows_path(self):
        found = self.find("Windows", on_path={"msedge": r"C:\Tools\msedge.EXE"})
        self.assertEqual(browser.Browser("Microsoft Edge", r"C:\Tools\msedge.EXE"), found)
        found = self.find("Windows", on_path={"msedge": r"C:\a\msedge.exe", "chrome": r"C:\b\chrome.exe"})
        self.assertEqual("Google Chrome", found.name)
        self.assertIsNone(self.find("Windows"))

    def test_linux_path(self):
        self.assertEqual(
            browser.Browser("Chromium", "/usr/bin/chromium-browser"),
            self.find("Linux", on_path={"chromium-browser": "/usr/bin/chromium-browser"}),
        )
        found = self.find("Linux", on_path={"microsoft-edge": "/usr/bin/microsoft-edge", "google-chrome": "/g"})
        self.assertEqual(browser.Browser("Google Chrome", "/g"), found)
        self.assertEqual("Microsoft Edge", self.find("Linux", on_path={"microsoft-edge": "/e"}).name)
        self.assertIsNone(self.find("Linux"))
        # Fixed locations are a macOS and Windows thing.
        self.assertIsNone(self.find("Linux", {"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}))

    def test_environment_variable_wins(self):
        chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        found = self.find(
            "Darwin", {chrome, "/opt/chrome-beta/chrome"}, environ={"TDXGUARD_BROWSER": "/opt/chrome-beta/chrome"}
        )
        self.assertEqual("/opt/chrome-beta/chrome", found.path)
        found = self.find("Linux", on_path={"vivaldi": "/usr/bin/vivaldi"}, environ={"TDXGUARD_BROWSER": "vivaldi"})
        self.assertEqual("/usr/bin/vivaldi", found.path)
        with self.assertRaises(ConfigError) as cm:
            self.find("Darwin", {chrome}, environ={"TDXGUARD_BROWSER": "/nowhere/chrome"})
        self.assertIn("TDXGUARD_BROWSER", cm.exception.message)


class TestPrintCommand(unittest.TestCase):
    def test_command_line(self):
        html = Path(tempfile.gettempdir()) / "my report.html"
        command = browser.print_command(
            browser.Browser("Google Chrome", "/c/chrome"), html, Path("/out/r.pdf"), "/tmp/profile"
        )
        self.assertEqual("/c/chrome", command[0])
        self.assertIn("--headless", command)
        self.assertIn("--no-pdf-header-footer", command)
        self.assertIn("--print-to-pdf-no-header", command)
        self.assertIn(f"--print-to-pdf={Path('/out/r.pdf')}", command)
        self.assertIn("--user-data-dir=/tmp/profile", command)
        self.assertNotIn("--no-sandbox", command)
        self.assertEqual(html.resolve().as_uri(), command[-1])
        self.assertIn("my%20report.html", command[-1])

    def test_root_needs_no_sandbox(self):
        command = browser.print_command(browser.Browser("Chromium", "c"), Path("r.html"), Path("r.pdf"), "p", True)
        self.assertIn("--no-sandbox", command)
        self.assertTrue(command[-1].startswith("file:"))

    def test_page_count(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        pdf = tmp / "r.pdf"
        pdf.write_bytes(b"%PDF-1.4\n<< /Type /Pages /Count 2 >>\n<< /Type /Page >>\n<</Type/Page/Parent 1 0 R>>\n")
        self.assertEqual(2, browser.page_count(pdf))
        self.assertTrue(browser.is_pdf(pdf))
        self.assertEqual(0, browser.page_count(tmp / "missing.pdf"))
        self.assertFalse(browser.is_pdf(tmp / "missing.pdf"))


FAKE_BROWSER = """#!{python}
import os, sys, time
mode = os.environ.get("FAKE_BROWSER_MODE", "ok")
with open(os.environ["FAKE_BROWSER_LOG"], "w") as log:
    log.write("\\n".join(sys.argv[1:]))
pdf = [a.split("=", 1)[1] for a in sys.argv if a.startswith("--print-to-pdf=")][0]
if mode == "sleep":
    time.sleep(30)
if mode == "fail":
    print("[0101/000000.000:ERROR:headless_shell.cc] Unable to open the file")
    sys.exit(1)
if mode != "silent":
    with open(pdf, "wb") as f:
        f.write(b"%PDF-1.4\\n<< /Type /Page >>\\n<< /Type /Page >>\\n<< /Type /Page >>\\n")
"""


@unittest.skipIf(os.name == "nt", "the fake browser is a script with a shebang")
class FakeBrowserTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fake = self.tmp / "fake-chrome"
        self.fake.write_text(FAKE_BROWSER.format(python=sys.executable))
        self.fake.chmod(self.fake.stat().st_mode | stat.S_IXUSR)
        self.log = self.tmp / "browser-arguments.txt"
        patcher = patch.dict(os.environ, {"FAKE_BROWSER_LOG": str(self.log), "FAKE_BROWSER_MODE": "ok"})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.html = self.tmp / "r.html"
        self.html.write_text("<html></html>")
        self.chrome = browser.Browser("Fake Chrome", str(self.fake))


class TestPrintToPdf(FakeBrowserTestCase):
    def test_writes_the_pdf(self):
        (self.tmp / "r.pdf").write_text("old")
        browser.print_to_pdf(self.chrome, self.html, self.tmp / "r.pdf")
        self.assertEqual(3, browser.page_count(self.tmp / "r.pdf"))
        arguments = self.log.read_text().splitlines()
        self.assertEqual(self.html.resolve().as_uri(), arguments[-1])
        profile = next(a.split("=", 1)[1] for a in arguments if a.startswith("--user-data-dir="))
        self.assertFalse(Path(profile).exists(), "the temporary profile is removed")

    def test_browser_fails(self):
        os.environ["FAKE_BROWSER_MODE"] = "fail"
        with self.assertRaises(CLIError) as cm:
            browser.print_to_pdf(self.chrome, self.html, self.tmp / "r.pdf")
        self.assertIn("exit code 1", cm.exception.message)
        self.assertIn("Unable to open the file", cm.exception.message)
        self.assertIn("print it to PDF", cm.exception.hint)

    def test_exit_zero_without_a_pdf_is_a_failure(self):
        os.environ["FAKE_BROWSER_MODE"] = "silent"
        (self.tmp / "r.pdf").write_bytes(b"%PDF-1.4 stale")
        with self.assertRaises(CLIError):
            browser.print_to_pdf(self.chrome, self.html, self.tmp / "r.pdf")
        self.assertFalse((self.tmp / "r.pdf").exists(), "a PDF of an earlier run does not pass for a new one")

    def test_timeout(self):
        os.environ["FAKE_BROWSER_MODE"] = "sleep"
        with self.assertRaises(CLIError) as cm:
            browser.print_to_pdf(self.chrome, self.html, self.tmp / "r.pdf", timeout=1)
        self.assertIn("within 1 s", cm.exception.message)

    def test_cannot_start(self):
        with self.assertRaises(CLIError) as cm:
            browser.print_to_pdf(browser.Browser("Chromium", str(self.tmp / "nope")), self.html, self.tmp / "r.pdf")
        self.assertIn("Cannot start Chromium", cm.exception.message)


class FakeApi:
    """Answers the generator's requests like a TDxGuard API with one empty product."""

    def __init__(self, status=None):
        self.urls = []
        self.status = status or {}

    def __call__(self, url, headers=None, timeout=None):
        self.urls.append(url)
        self.headers = headers
        parts = urllib.parse.urlsplit(url)
        path = parts.path
        query = dict(urllib.parse.parse_qsl(parts.query))
        for prefix, status in self.status.items():
            if path.startswith(prefix):
                return http.Response(status, b'{"message": "no"}', {})
        if path.endswith("/products/"):
            body = {"results": [{"id": 1, "name": query.get("name"), "repository_default_branch": 5,
                                 "repository_default_branch_name": "main"}]}  # fmt: skip
            if query.get("name") == "missing":
                body = {"results": []}
        elif path.endswith("/branches/"):
            body = {"results": [{"id": 5, "name": "main"}, {"id": 6, "name": "develop"}]}
        elif path.endswith("/settings/1/"):
            body = {"security_gate_active": False}
        else:
            body = {"count": 0, "next": None, "results": []}
        return http.Response(200, json.dumps(body).encode(), {})


class TestApi(unittest.TestCase):
    creds = credentials.Credentials(server="https://guard.example", token="secret-token")

    def fetch(self, fake, **options):
        with patch.object(assessment.http, "get", fake):
            return assessment.fetch(self.creds, assessment.Options(**options), lambda stage: None)

    def test_fetch_through_the_cli_http_client(self):
        fake = FakeApi()
        data = self.fetch(fake, product="tdx-demo")
        self.assertEqual("tdx-demo", data["product"]["name"])
        self.assertEqual("main", data["branch"]["name"])
        self.assertEqual(len(fake.urls), data["requests"])
        self.assertTrue(all(url.startswith("https://guard.example/api/") for url in fake.urls), fake.urls)
        self.assertFalse(any("/api/api/" in url for url in fake.urls))
        self.assertEqual({"Authorization": "APIToken secret-token"}, fake.headers)

    def test_own_api_url(self):
        fake = FakeApi()
        creds = credentials.Credentials(server="https://guard.example", token="t", api_url="https://api.example/v1")
        with patch.object(assessment.http, "get", fake):
            assessment.fetch(creds, assessment.Options(product="p", branch="develop"), lambda stage: None)
        self.assertTrue(all(url.startswith("https://api.example/v1/") for url in fake.urls), fake.urls)
        self.assertIn("name=develop", fake.urls[1])

    def test_product_not_found(self):
        with self.assertRaises(ApiError) as cm:
            self.fetch(FakeApi(), product="missing")
        self.assertIn("'missing' not found", cm.exception.message)
        self.assertIn("member", cm.exception.hint)

    def test_branch_not_found(self):
        with self.assertRaises(ApiError) as cm:
            self.fetch(FakeApi(), product="p", branch="feature/x")
        self.assertIn("Branch 'feature/x' not found", cm.exception.message)
        self.assertIn("default branch", cm.exception.hint)

    def test_expired_token(self):
        with self.assertRaises(AuthenticationError):
            self.fetch(FakeApi({"/api/products/": 401}), product="p")

    def test_unreadable_settings_are_a_warning(self):
        data = self.fetch(FakeApi({"/api/settings/": 403}), product="p")
        self.assertEqual(["settings_unreadable"], data["warnings"])
        self.assertIn("gate thresholds", assessment.warnings_of(data)[0])

    def test_server_error(self):
        with self.assertRaises(ApiError) as cm:
            self.fetch(FakeApi({"/api/observations/": 500}), product="p")
        self.assertIn("HTTP 500", cm.exception.message)

    def test_capped_log_scan_warning(self):
        text = assessment.warnings_of({"warnings": ["log_scan_capped:3000:12000"]})[0]
        self.assertIn("newest 3000 of 12000", text)


class TestReportCommand(FakeBrowserTestCase):
    def setUp(self):
        super().setUp()
        patcher = patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.tmp / "config"), "NO_COLOR": "1"})
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("TDXGUARD_TOKEN", "TDXGUARD_SERVER", "TDXGUARD_BROWSER"):
            os.environ.pop(name, None)
        cwd = os.getcwd()
        self.work = self.tmp / "repository"
        self.work.mkdir()
        os.chdir(self.work)
        self.addCleanup(os.chdir, cwd)
        self.browser = patch.object(browser, "find_browser", return_value=self.chrome)
        self.find = self.browser.start()
        self.addCleanup(self.browser.stop)

    def login(self):
        os.environ["TDXGUARD_TOKEN"] = "t"
        os.environ["TDXGUARD_SERVER"] = "https://guard.example"

    def test_not_logged_in(self):
        code, _, stderr = run_main(["report", "--product", "p"])
        self.assertEqual(EXIT_ERROR, code)
        self.assertIn("not logged in", stderr)

    def test_no_product(self):
        self.login()
        code, _, stderr = run_main(["report"])
        self.assertEqual(EXIT_ERROR, code)
        self.assertIn("--product", stderr)

    def test_html_and_pdf_for_the_project_of_tdxguard_yml(self):
        self.login()
        (self.work / ".tdxguard.yml").write_text("project: tdx-demo\n")
        with patch.object(assessment, "fetch", return_value=minimal_data()) as fetch:
            code, stdout, stderr = run_main(["report", "--lang", "en", "--branch", "develop", "--out", "report"])
        self.assertEqual(EXIT_OK, code, stdout + stderr)
        options = fetch.call_args[0][1]
        self.assertEqual(("tdx-demo", "develop", "en", "https://guard.example"),
                         (options.product, options.branch, options.lang, options.ui_url))  # fmt: skip
        self.assertEqual("t", fetch.call_args[0][0].token)
        self.assertIn("Fetching the findings of tdx-demo (branch develop) from https://guard.example", stdout)
        self.assertIn("Printing to PDF with Fake Chrome", stdout)
        self.assertIn("report.pdf (3 pages, ", stdout)
        html = (self.work / "report.html").read_text(encoding="utf-8")
        self.assertIn('<html lang="en">', html)
        self.assertIn("Security assessment report", html)
        self.assertTrue(browser.is_pdf(self.work / "report.pdf"))

    def test_vietnamese_is_the_default(self):
        self.login()
        with patch.object(assessment, "fetch", return_value=minimal_data()):
            code, stdout, _ = run_main(["report", "--product", "tdx-demo", "--no-pdf"])
        self.assertEqual(EXIT_OK, code)
        html = (self.work / "tdx-demo-security-report-vi.html").read_text(encoding="utf-8")
        self.assertIn("Báo cáo đánh giá bảo mật", html)
        self.assertFalse((self.work / "tdx-demo-security-report-vi.pdf").exists())
        self.find.assert_not_called()

    def test_without_a_browser(self):
        self.login()
        self.find.return_value = None
        with patch.object(assessment, "fetch", return_value=minimal_data()):
            code, stdout, _ = run_main(["report", "--product", "tdx-demo", "--out", "r"])
        self.assertEqual(EXIT_OK, code)
        self.assertTrue((self.work / "r.html").is_file())
        self.assertIn("No Chrome, Chromium or Edge found", stdout)
        self.assertIn("Open r.html and print it to PDF", stdout)
        self.assertIn("--open", stdout)

    def test_open(self):
        self.login()
        self.find.return_value = None
        with (
            patch.object(assessment, "fetch", return_value=minimal_data()),
            patch("tdxguard.commands._open_browser", return_value=True) as opened,
        ):
            code, stdout, _ = run_main(["report", "--product", "tdx-demo", "--out", "r", "--open"])
        self.assertEqual(EXIT_OK, code)
        self.assertEqual((self.work / "r.html").resolve().as_uri(), opened.call_args[0][0])
        self.assertNotIn("run again with --open", stdout)

    def test_pdf_failure_keeps_the_html(self):
        self.login()
        os.environ["FAKE_BROWSER_MODE"] = "fail"
        with patch.object(assessment, "fetch", return_value=minimal_data()):
            code, _, stderr = run_main(["report", "--product", "tdx-demo", "--out", "r"])
        self.assertEqual(EXIT_ERROR, code)
        self.assertTrue((self.work / "r.html").is_file())
        self.assertIn("did not write the PDF", stderr)
        self.assertIn("print it to PDF", stderr)

    def test_missing_output_directory(self):
        self.login()
        with patch.object(assessment, "fetch") as fetch:
            code, _, stderr = run_main(["report", "--product", "p", "--out", "nowhere/r"])
        self.assertEqual(EXIT_ERROR, code)
        self.assertIn("does not exist", stderr)
        fetch.assert_not_called()

    def test_save_and_render_again_offline(self):
        self.login()
        data = minimal_data()
        data["warnings"] = ["settings_unreadable"]
        with patch.object(assessment, "fetch", return_value=data):
            code, stdout, _ = run_main(["report", "--product", "tdx-demo", "--no-pdf", "--save-data", "d.json"])
        self.assertEqual(EXIT_OK, code)
        self.assertIn("gate thresholds may be unknown", stdout)
        for name in ("TDXGUARD_TOKEN", "TDXGUARD_SERVER"):
            os.environ.pop(name)
        with patch.object(assessment, "fetch") as fetch:
            code, stdout, stderr = run_main(
                ["report", "--from-data", "d.json", "--out", "again", "--markdown", "--csv", "--lang", "en"]
            )
        self.assertEqual(EXIT_OK, code, stdout + stderr)
        fetch.assert_not_called()
        self.assertNotIn("Fetching", stdout)
        for suffix in (".html", ".md", ".csv", ".pdf"):
            self.assertTrue((self.work / f"again{suffix}").is_file(), suffix)

    def test_bad_data_file(self):
        (self.work / "d.json").write_text("[1, 2]")
        code, _, stderr = run_main(["report", "--from-data", "d.json"])
        self.assertEqual(EXIT_ERROR, code)
        self.assertIn("not report data", stderr)

    @unittest.skipUnless(FIXTURE.is_file(), "the recorded fixture of ci-templates/tests is not here")
    def test_recorded_product_has_the_standards_mapping(self):
        code, stdout, stderr = run_main(["report", "--from-data", str(FIXTURE), "--out", "r", "--lang", "en"])
        self.assertEqual(EXIT_OK, code, stdout + stderr)
        html = (self.work / "r.html").read_text(encoding="utf-8")
        self.assertIn("ISO/IEC 27001", html)
        self.assertIn("OWASP Top 10", html)
        self.assertIn("verdict: action required", stdout)


if __name__ == "__main__":
    unittest.main()
