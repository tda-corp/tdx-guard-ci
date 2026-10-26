import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile
import tempfile
import unittest
import urllib.error
import zipfile
from pathlib import Path
from unittest.mock import patch

from tdxguard.engine import tools
from tdxguard.errors import ToolError

REPOSITORY = Path(__file__).resolve().parents[2]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tar_gz(files, symlinks=()):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
        for name, target in symlinks:
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tf.addfile(info)
    return buffer.getvalue()


def zip_bytes(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buffer.getvalue()


def serving(payload: bytes, calls=None):
    """A downloader that writes payload, recording the URLs asked for."""

    def download(url, dest):
        if calls is not None:
            calls.append(url)
        Path(dest).write_bytes(payload)

    return download


def leftovers(root: Path):
    return sorted(p.name for p in root.rglob(".*") if p.name != tools.MARKER)


class TestPlatform(unittest.TestCase):
    def test_mapping(self):
        cases = [
            (("Darwin", "arm64", None), "darwin-arm64"),
            (("Darwin", "x86_64", None), "darwin-x86_64"),
            (("Linux", "x86_64", "glibc"), "linux-x86_64"),
            (("Linux", "amd64", "glibc"), "linux-x86_64"),
            (("Linux", "aarch64", "glibc"), "linux-aarch64"),
            (("Linux", "arm64", "glibc"), "linux-aarch64"),
            (("Linux", "x86_64", "musl"), "linux-x86_64-musl"),
            (("Linux", "aarch64", "musl"), "linux-aarch64-musl"),
            (("Windows", "AMD64", None), "windows-x86_64"),
        ]
        for (system, machine, libc), expected in cases:
            with self.subTest(system=system, machine=machine, libc=libc):
                self.assertEqual(expected, tools.detect_platform(system, machine, libc))

    def test_unsupported(self):
        for system, machine in (("Windows", "ARM64"), ("FreeBSD", "amd64"), ("Linux", "riscv64"), ("Linux", "i686")):
            with self.subTest(system=system, machine=machine), self.assertRaises(ToolError) as cm:
                tools.detect_platform(system, machine, "glibc")
            self.assertIn("--engine docker", cm.exception.hint)

    def test_assets(self):
        expected = {
            ("opengrep", "darwin-arm64"): "opengrep_osx_arm64",
            ("opengrep", "darwin-x86_64"): "opengrep_osx_x86",
            ("opengrep", "linux-x86_64"): "opengrep_manylinux_x86",
            ("opengrep", "linux-aarch64"): "opengrep_manylinux_aarch64",
            ("opengrep", "linux-x86_64-musl"): "opengrep_musllinux_x86",
            ("opengrep", "linux-aarch64-musl"): "opengrep_musllinux_aarch64",
            ("opengrep", "windows-x86_64"): "opengrep_windows_x86.exe",
            ("trivy", "darwin-arm64"): "trivy_0.76.0_macOS-ARM64.tar.gz",
            ("trivy", "darwin-x86_64"): "trivy_0.76.0_macOS-64bit.tar.gz",
            ("trivy", "linux-x86_64"): "trivy_0.76.0_Linux-64bit.tar.gz",
            # Trivy and Betterleaks are static Go binaries: musl uses the same build.
            ("trivy", "linux-aarch64-musl"): "trivy_0.76.0_Linux-ARM64.tar.gz",
            ("trivy", "windows-x86_64"): "trivy_0.76.0_windows-64bit.zip",
            ("betterleaks", "darwin-arm64"): "betterleaks_1.9.0_darwin_arm64.tar.gz",
            ("betterleaks", "darwin-x86_64"): "betterleaks_1.9.0_darwin_x64.tar.gz",
            ("betterleaks", "linux-x86_64-musl"): "betterleaks_1.9.0_linux_x64.tar.gz",
            ("betterleaks", "linux-aarch64"): "betterleaks_1.9.0_linux_arm64.tar.gz",
            ("betterleaks", "windows-x86_64"): "betterleaks_1.9.0_windows_x64.zip",
            ("opengrep-rules", "windows-x86_64"): "f1d2b562b414783763fd02a6ed2736eaed622efa.tar.gz",
        }
        for (name, platform), asset in expected.items():
            with self.subTest(tool=name, platform=platform):
                self.assertEqual(asset, tools.TOOLS[name].asset_for(platform).name)

    def test_windows_members_and_executables(self):
        self.assertEqual("trivy.exe", tools.TOOLS["trivy"].asset_for("windows-x86_64").member)
        self.assertEqual("betterleaks.exe", tools.TOOLS["betterleaks"].asset_for("windows-x86_64").member)
        self.assertEqual("trivy.exe", tools.TOOLS["trivy"].executable_name("windows-x86_64"))
        self.assertEqual("opengrep", tools.TOOLS["opengrep"].executable_name("linux-x86_64-musl"))

    def test_urls(self):
        trivy = tools.TOOLS["trivy"]
        self.assertEqual(
            "https://github.com/aquasecurity/trivy/releases/download/v0.76.0/trivy_0.76.0_Linux-64bit.tar.gz",
            trivy.download_url(trivy.asset_for("linux-x86_64")),
        )
        rules = tools.TOOLS["opengrep-rules"]
        self.assertEqual(
            "https://github.com/opengrep/opengrep-rules/archive/f1d2b562b414783763fd02a6ed2736eaed622efa.tar.gz",
            rules.download_url(rules.asset_for("darwin-arm64")),
        )


class TestPinnedTable(unittest.TestCase):
    def test_every_platform_has_every_tool(self):
        for platform in tools.PLATFORMS:
            for tool in tools.TOOLS.values():
                with self.subTest(platform=platform, tool=tool.name):
                    if not tool.required and not tool.available_for(platform):
                        # An optional tool may lack a build for musl only (zizmor links glibc).
                        self.assertTrue(platform.endswith("-musl"))
                        self.assertIsNone(tools.installed(tool, platform, Path("/nonexistent")))
                        continue
                    asset = tool.asset_for(platform)
                    self.assertRegex(asset.sha256, r"^[0-9a-f]{64}$")
                    if tool.binary:
                        self.assertIn(tool.version, tool.download_url(asset))

    def test_checksums_are_distinct(self):
        digests = [a.sha256 for t in tools.TOOLS.values() for a in t.assets.values()]
        self.assertEqual(len(digests), len(set(digests)))

    @unittest.skipUnless((REPOSITORY / "ci-templates").is_dir(), "ci-templates/ is not next to the package")
    def test_versions_match_the_ci_templates(self):
        """The table must move together with the templates' env blocks."""
        pins = {
            "BETTERLEAKS_VERSION": tools.BETTERLEAKS_VERSION,
            "OPENGREP_VERSION": tools.OPENGREP_VERSION,
            "OPENGREP_RULES_SHA": tools.OPENGREP_RULES_SHA,
            "TRIVY_VERSION": tools.TRIVY_VERSION,
        }
        for template in ("github/tdxguard.yml", "gitlab/tdxguard.yml"):
            text = (REPOSITORY / "ci-templates" / template).read_text(encoding="utf-8")
            for variable, pinned in pins.items():
                found = set(re.findall(rf'^\s*{variable}:\s*"([^"]+)"', text, re.MULTILINE))
                with self.subTest(template=template, variable=variable):
                    self.assertEqual({pinned}, found)

    @unittest.skipUnless((REPOSITORY / "ci-templates").is_dir(), "ci-templates/ is not next to the package")
    def test_zizmor_matches_the_github_template(self):
        """The GitHub template downloads the same zizmor and checks the same checksums (GitLab runs none)."""
        text = (REPOSITORY / "ci-templates" / "github" / "tdxguard.yml").read_text(encoding="utf-8")
        zizmor = tools.TOOLS["zizmor"]
        pins = {
            "ZIZMOR_VERSION": tools.ZIZMOR_VERSION,
            "ZIZMOR_SHA256_X86_64": zizmor.assets["linux-x86_64"].sha256,
            "ZIZMOR_SHA256_AARCH64": zizmor.assets["linux-aarch64"].sha256,
        }
        for variable, pinned in pins.items():
            with self.subTest(variable=variable):
                self.assertEqual([pinned], re.findall(rf'^\s*{variable}:\s*"([^"]+)"', text, re.MULTILINE))

    def test_a_musl_system_scans_without_zizmor(self):
        self.assertFalse(tools.TOOLS["zizmor"].available_for("linux-x86_64-musl"))
        self.assertTrue(tools.TOOLS["trivy"].available_for("linux-x86_64-musl"))
        self.assertTrue(tools.TOOLS["zizmor"].available_for("linux-x86_64"))

    @unittest.skipUnless((REPOSITORY / "ci-templates").is_dir(), "ci-templates/ is not next to the package")
    def test_the_image_takes_its_tools_from_this_table(self):
        dockerfile = (REPOSITORY / "ci-templates" / "scanner" / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("python3 -P -m tdxguard.engine.tools install", dockerfile)
        # No second copy of a checksum: the only digest in the Dockerfile is the base image's.
        digests = re.findall(r"[0-9a-f]{64}", dockerfile)
        self.assertEqual(1, len(digests), digests)
        self.assertNotIn(digests[0], [a.sha256 for t in tools.TOOLS.values() for a in t.assets.values()])


class TestLocations(unittest.TestCase):
    def test_tools_dir(self):
        self.assertEqual(Path("/x/tools"), tools.tools_dir({"TDXGUARD_TOOLS_DIR": "/x/tools"}))
        self.assertEqual(Path("/c/tdxguard/tools"), tools.tools_dir({"XDG_CACHE_HOME": "/c"}))
        self.assertEqual(Path("/c/tdxguard"), tools.cache_dir({"XDG_CACHE_HOME": "/c"}))

    def test_install_dir_is_tool_and_version(self):
        root = Path("tools-root")
        self.assertEqual(root / "trivy" / "0.76.0", tools.install_dir(tools.TOOLS["trivy"], root))
        self.assertEqual(
            root / "opengrep-rules" / tools.OPENGREP_RULES_SHA, tools.install_dir(tools.TOOLS["opengrep-rules"], root)
        )


class InstallTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "tools"


class TestVerify(InstallTestCase):
    def test_match_and_mismatch(self):
        path = Path(self.tmp.name) / "f"
        path.write_bytes(b"payload")
        tools.verify(path, sha(b"payload"), "f")
        tools.verify(path, sha(b"payload").upper(), "f")
        with self.assertRaises(ToolError) as cm:
            tools.verify(path, sha(b"other"), "f")
        self.assertIn(sha(b"payload"), cm.exception.message)
        self.assertIn(sha(b"other"), cm.exception.message)


class TestInstall(InstallTestCase):
    def tool(self, assets, binary="fake"):
        return tools.Tool("fake", "1.0", "https://example.invalid/v{version}/{asset}", assets, binary=binary)

    def test_raw_binary(self):
        payload = b"#!/bin/sh\necho fake\n"
        calls = []
        tool = self.tool({"linux-x86_64": tools.Asset("fake_linux", sha(payload))})
        target = tools.install(tool, "linux-x86_64", self.root, downloader=serving(payload, calls), run_check=False)

        self.assertEqual(self.root / "fake" / "1.0", target)
        self.assertEqual(["https://example.invalid/v1.0/fake_linux"], calls)
        self.assertEqual(payload, (target / "fake").read_bytes())
        marker = json.loads((target / tools.MARKER).read_text())
        self.assertEqual({"tool": "fake", "version": "1.0", "platform": "linux-x86_64"}, {
            k: marker[k] for k in ("tool", "version", "platform")
        })  # fmt: skip
        self.assertEqual(target, tools.installed(tool, "linux-x86_64", self.root))
        self.assertEqual([], leftovers(self.root))
        if os.name == "posix":
            self.assertTrue(os.stat(target / "fake").st_mode & stat.S_IXUSR)
            self.assertEqual(0o755, stat.S_IMODE(os.stat(target).st_mode))

    def test_tar_member(self):
        archive = tar_gz({"LICENSE": b"text", "fake": b"binary"})
        tool = self.tool({"darwin-arm64": tools.Asset("fake.tar.gz", sha(archive), "fake")})
        with patch("tdxguard.engine.tools.remove_quarantine") as quarantine:
            target = tools.install(tool, "darwin-arm64", self.root, downloader=serving(archive), run_check=False)
        self.assertEqual(b"binary", (target / "fake").read_bytes())
        self.assertFalse((target / "LICENSE").exists())
        if os.name == "posix" and os.uname().sysname == "Darwin":
            # Called on the file it just wrote, before the directory is renamed into place.
            quarantine.assert_called_once()
            self.assertEqual("fake", quarantine.call_args[0][0].name)

    def test_windows_zip(self):
        archive = zip_bytes({"README.md": b"x", "fake.exe": b"MZ binary"})
        tool = self.tool({"windows-x86_64": tools.Asset("fake.zip", sha(archive), "fake.exe")})
        target = tools.install(tool, "windows-x86_64", self.root, downloader=serving(archive), run_check=False)
        self.assertEqual(b"MZ binary", (target / "fake.exe").read_bytes())
        self.assertFalse((target / "fake").exists())

    def test_missing_member(self):
        archive = tar_gz({"other": b"x"})
        tool = self.tool({"linux-x86_64": tools.Asset("fake.tar.gz", sha(archive), "fake")})
        with self.assertRaises(ToolError):
            tools.install(tool, "linux-x86_64", self.root, downloader=serving(archive), run_check=False)
        self.assertIsNone(tools.installed(tool, "linux-x86_64", self.root))

    def test_checksum_mismatch_installs_nothing(self):
        tool = self.tool({"linux-x86_64": tools.Asset("fake_linux", sha(b"expected"))})
        with self.assertRaises(ToolError) as cm:
            tools.install(tool, "linux-x86_64", self.root, downloader=serving(b"tampered"), run_check=False)
        self.assertIn("Checksum mismatch", cm.exception.message)
        self.assertFalse((self.root / "fake" / "1.0").exists())
        self.assertEqual([], leftovers(self.root))

    def test_offline(self):
        tool = self.tool({"linux-x86_64": tools.Asset("fake_linux", sha(b"x"))})
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("nodename nor servname provided")):
            with self.assertRaises(ToolError) as cm:
                tools.install(tool, "linux-x86_64", self.root, run_check=False)
        self.assertIn("Download failed (nodename nor servname provided)", cm.exception.message)
        self.assertIn("tdxguard tools install", cm.exception.hint)
        self.assertIn("--engine docker", cm.exception.hint)
        self.assertFalse((self.root / "fake" / "1.0").exists())
        self.assertEqual([], leftovers(self.root))

    def test_http_error(self):
        tool = self.tool({"linux-x86_64": tools.Asset("fake_linux", sha(b"x"))})
        error = urllib.error.HTTPError("https://example.invalid", 404, "Not Found", {}, None)
        with patch("urllib.request.urlopen", side_effect=error), self.assertRaises(ToolError) as cm:
            tools.install(tool, "linux-x86_64", self.root, run_check=False)
        self.assertIn("HTTP 404", cm.exception.message)

    def test_foreign_install_is_replaced(self):
        """A cache shared with another platform, or an older pin, is not taken for installed."""
        payload = b"new"
        tool = self.tool({"linux-x86_64": tools.Asset("fake_linux", sha(payload))})
        stale = self.root / "fake" / "1.0"
        stale.mkdir(parents=True)
        (stale / "fake").write_bytes(b"darwin binary")
        (stale / tools.MARKER).write_text(json.dumps({"sha256": sha(b"darwin binary")}))
        self.assertIsNone(tools.installed(tool, "linux-x86_64", self.root))

        tools.install(tool, "linux-x86_64", self.root, downloader=serving(payload), run_check=False)
        self.assertEqual(payload, (stale / "fake").read_bytes())
        self.assertEqual([], leftovers(self.root))

    def test_install_finished_meanwhile_by_another_process(self):
        payload = b"bin"
        tool = self.tool({"linux-x86_64": tools.Asset("fake_linux", sha(payload))})

        def racing(url, dest):
            # The other process completes its install while this one downloads.
            tools.install(tool, "linux-x86_64", self.root, downloader=serving(payload), run_check=False)
            Path(dest).write_bytes(payload)

        target = tools.install(tool, "linux-x86_64", self.root, downloader=racing, run_check=False)
        self.assertEqual(target, tools.installed(tool, "linux-x86_64", self.root))
        self.assertEqual([], leftovers(self.root))

    def test_opengrep_version_check(self):
        payload = b"opengrep"
        tool = tools.Tool(
            "opengrep", "1.29.0", "https://example.invalid/{asset}",
            {"linux-x86_64": tools.Asset("og", sha(payload))}, binary="opengrep",
        )  # fmt: skip
        with patch("tdxguard.engine.tools.check_opengrep", side_effect=ToolError("does not run")) as check:
            with self.assertRaises(ToolError):
                tools.install(tool, "linux-x86_64", self.root, downloader=serving(payload), run_check=True)
        check.assert_called_once()
        self.assertIsNone(tools.installed(tool, "linux-x86_64", self.root))
        self.assertEqual([], leftovers(self.root))

    def test_ensure_downloads_only_what_is_missing(self):
        payloads = {name: f"{name} binary".encode() for name in ("betterleaks", "opengrep", "trivy")}
        rules = tar_gz({"r-abc/python/x/security/rule.yaml": b"rules: []\n"})
        table = {
            name: tools.Tool(name, "1", "https://example.invalid/{asset}",
                             {"linux-x86_64": tools.Asset(name, sha(payloads[name]))}, binary=name)
            for name in payloads
        }  # fmt: skip
        table["opengrep-rules"] = tools.Tool(
            "opengrep-rules", "abc", "https://example.invalid/{asset}", {"any": tools.Asset("abc.tar.gz", sha(rules))}
        )
        calls = []

        def download(url, dest):
            calls.append(url.rsplit("/", 1)[-1])
            name = url.rsplit("/", 1)[-1]
            Path(dest).write_bytes(rules if name == "abc.tar.gz" else payloads[name])

        with (
            patch.dict(tools.TOOLS, table, clear=True),
            patch.object(tools, "MIN_RULES", 1),
            patch.object(tools, "RULE_LANGUAGES", ("python",)),
            patch("tdxguard.engine.tools.check_opengrep"),
        ):
            toolset = tools.ensure("linux-x86_64", self.root, downloader=download)
            self.assertEqual(["betterleaks", "opengrep", "trivy", "abc.tar.gz"], calls)
            self.assertEqual(self.root / "trivy" / "1" / "trivy", toolset.trivy)
            self.assertEqual(self.root / "opengrep-rules" / "abc", toolset.rules)
            tools.ensure("linux-x86_64", self.root, downloader=download)
            self.assertEqual(4, len(calls))
            self.assertEqual(toolset.opengrep, tools.toolset("linux-x86_64", self.root).opengrep)

            # Rules extracted for another language list are stale although the archive is the
            # same: an upgrade that adds a language extracts them again.
            with patch.object(tools, "RULE_LANGUAGES", ("python", "php")):
                self.assertIsNone(tools.installed(table["opengrep-rules"], "linux-x86_64", self.root))
            marker = json.loads((toolset.rules / tools.MARKER).read_text())
            self.assertEqual(["python"], marker["languages"])

            tools.clean(self.root)
            with self.assertRaises(ToolError) as cm:
                tools.toolset("linux-x86_64", self.root)
            self.assertIn("tdxguard tools install", cm.exception.hint)


class TestRules(InstallTestCase):
    def test_security_directories_only(self):
        archive = Path(self.tmp.name) / "rules.tar.gz"
        archive.write_bytes(
            tar_gz(
                {
                    "opengrep-rules-abc/python/django/security/injection/sql.yaml": b"a",
                    "opengrep-rules-abc/python/django/security/injection/sql.py": b"fixture",
                    "opengrep-rules-abc/python/lang/correctness/x.yaml": b"not security",
                    "opengrep-rules-abc/go/security/y.yaml": b"b",
                    "opengrep-rules-abc/generic/secrets/security/z.yaml": b"c",
                    "opengrep-rules-abc/solidity/security/s.yaml": b"other language",
                    "opengrep-rules-abc/terraform/aws/security/t.yaml": b"infrastructure, Trivy's",
                    "opengrep-rules-abc/python/security.yaml": b"a file named like the directory",
                    "opengrep-rules-abc/Pipfile": b"x",
                },
                symlinks=[("opengrep-rules-abc/python/flask/security/link.yaml", "/etc/passwd")],
            )
        )
        dest = Path(self.tmp.name) / "rules"
        dest.mkdir()
        with patch.object(tools, "MIN_RULES", 3), patch.object(tools, "RULE_LANGUAGES", ("python", "go", "generic")):
            self.assertEqual(3, tools.extract_rules(archive, dest))
        files = sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file())
        self.assertEqual(
            [
                "generic/secrets/security/z.yaml",
                "go/security/y.yaml",
                "python/django/security/injection/sql.py",
                "python/django/security/injection/sql.yaml",
            ],
            files,
        )

    def test_too_few_rules(self):
        archive = Path(self.tmp.name) / "rules.tar.gz"
        archive.write_bytes(tar_gz({"top/python/security/a.yaml": b"a"}))
        dest = Path(self.tmp.name) / "rules"
        dest.mkdir()
        with self.assertRaises(ToolError) as cm:
            tools.extract_rules(archive, dest)
        self.assertIn("layout changed", cm.exception.message)

    def test_language_without_rules(self):
        """Enough rules in total must not hide a language whose directory went away."""
        archive = Path(self.tmp.name) / "rules.tar.gz"
        archive.write_bytes(tar_gz({f"top/python/security/{n}.yaml": b"a" for n in range(5)}))
        dest = Path(self.tmp.name) / "rules"
        dest.mkdir()
        with (
            patch.object(tools, "MIN_RULES", 5),
            patch.object(tools, "RULE_LANGUAGES", ("python", "php")),
            self.assertRaises(ToolError) as cm,
        ):
            tools.extract_rules(archive, dest)
        self.assertIn("No security rules for php", cm.exception.message)

    def test_rule_languages(self):
        """The application languages of opengrep-rules; infrastructure as code is Trivy's."""
        self.assertEqual(len(set(tools.RULE_LANGUAGES)), len(tools.RULE_LANGUAGES))
        for language in ("python", "javascript", "typescript", "go", "php", "java", "kotlin", "scala", "ruby",
                         "csharp", "c", "generic"):  # fmt: skip
            self.assertIn(language, tools.RULE_LANGUAGES)
        for language in ("terraform", "yaml", "dockerfile", "json"):
            self.assertNotIn(language, tools.RULE_LANGUAGES)

    def test_traversal_refused(self):
        archive = Path(self.tmp.name) / "rules.tar.gz"
        archive.write_bytes(tar_gz({"top/python/security/../../../../evil.yaml": b"a"}))
        dest = Path(self.tmp.name) / "rules"
        dest.mkdir()
        with patch.object(tools, "MIN_RULES", 0), self.assertRaises(ToolError):
            tools.extract_rules(archive, dest)
        self.assertFalse((Path(self.tmp.name).parent / "evil.yaml").exists())


class TestQuarantineAndCheck(unittest.TestCase):
    def test_quarantine_removed_only_when_present(self):
        calls = []

        def run(command, **kwargs):
            calls.append(command[:2])
            return subprocess.CompletedProcess(command, 0 if present else 1)

        present = True
        self.assertTrue(tools.remove_quarantine(Path("/x/opengrep"), run=run))
        self.assertEqual([["xattr", "-p"], ["xattr", "-d"]], calls)
        calls.clear()
        present = False
        self.assertFalse(tools.remove_quarantine(Path("/x/opengrep"), run=run))
        self.assertEqual([["xattr", "-p"]], calls)

    def test_opengrep_check(self):
        good = subprocess.CompletedProcess([], 0, stdout="1.31.0\n", stderr="")
        bad = subprocess.CompletedProcess([], 0, stdout="1.12.0\n", stderr="")
        with patch("subprocess.run", return_value=good):
            tools.check_opengrep(Path("opengrep"))
        with patch("subprocess.run", return_value=bad), self.assertRaises(ToolError):
            tools.check_opengrep(Path("opengrep"))
        with patch("subprocess.run", side_effect=OSError("Exec format error")), self.assertRaises(ToolError) as cm:
            tools.check_opengrep(Path("opengrep"))
        self.assertIn("Exec format error", cm.exception.message)


class TestWindowsHandling(InstallTestCase):
    def test_no_executable_bit_or_quarantine_on_windows(self):
        path = Path(self.tmp.name) / "trivy.exe"
        path.write_bytes(b"MZ")
        with patch("tdxguard.engine.tools.remove_quarantine") as quarantine, patch("os.chmod") as chmod:
            tools._make_executable(path, "windows-x86_64")
        chmod.assert_not_called()
        quarantine.assert_not_called()

    def test_toolset_paths(self):
        toolset = tools._toolset("windows-x86_64", Path("cache") / "tools")
        self.assertEqual(Path("cache", "tools", "trivy", tools.TRIVY_VERSION, "trivy.exe"), toolset.trivy)
        self.assertEqual(Path("cache", "tools", "opengrep", tools.OPENGREP_VERSION, "opengrep.exe"), toolset.opengrep)
        self.assertEqual(Path("cache", "tools", "opengrep-rules", tools.OPENGREP_RULES_SHA), toolset.rules)


class TestClean(InstallTestCase):
    def test_clean_unused_keeps_pinned(self):
        pinned = self.root / "trivy" / tools.TRIVY_VERSION
        old = self.root / "trivy" / "0.58.1"
        for directory in (pinned, old):
            directory.mkdir(parents=True)
        self.assertEqual([old], tools.clean(self.root, unused_only=True))
        self.assertTrue(pinned.is_dir())
        self.assertEqual([self.root], tools.clean(self.root))
        self.assertFalse(self.root.exists())
        self.assertEqual([], tools.clean(self.root))


if __name__ == "__main__":
    unittest.main()
