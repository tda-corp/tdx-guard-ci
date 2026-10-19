"""
Scan coverage: what a repository should be scanned for, what its TDxGuard CI workflow
switches on, and the workflow itself.

`tdxguard init` writes the workflow with the detected settings, `tdxguard doctor` compares
the three: expected (from the files in the repository), configured (the workflow's inputs)
and received (the product's `scan_coverage` in TDxGuard).

The workflow text and the input semantics follow the TDxGuard backend's snippet generator
(backend/application/onboarding/services/snippets.py), which in turn follows the CI
templates (ci-templates/github/tdxguard.yml, ci-templates/gitlab/tdxguard.yml). The three
always-on scans need nothing but product and bao_role; the image scan, IAST and DAST are
switched on by optional inputs:

  GitHub   dockerfile / image_ref          -> image scan (several Dockerfiles: one per line)
           app_start_command               -> IAST (Aikido Zen), the runtime job
           app_start_command + zap_target  -> DAST (ZAP, and Nuclei with nuclei: true)
           mobile_app / mobile_source      -> mobile app analysis (MobSF), GitHub only
  GitLab   IMAGE_REF                       -> image scan (one image, already pushed)
           APP_START_COMMAND               -> IAST
           ZAP_TARGET / NUCLEI_TARGET      -> DAST against a deployed environment
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import yaml

from tdxguard.config import find_dockerfiles, repository_files
from tdxguard.engine.tools import RULE_LANGUAGES
from tdxguard.errors import ConfigError

GITHUB = "github"
GITLAB = "gitlab"
PLATFORMS = (GITHUB, GITLAB)

GITHUB_WORKFLOW = ".github/workflows/tdxguard.yml"
GITLAB_CI = ".gitlab-ci.yml"
DEFAULT_GITHUB_ORG = "tda-corp"
DEFAULT_APP_HEALTH_URL = "http://127.0.0.1:8000/"
DEFAULT_RUNTIME_IMAGE = "python:3.12-slim"
GITLAB_IMAGE_REF_HINT = "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA"

KINDS: List[Tuple[str, str]] = [
    ("secrets", "Secrets"),
    ("sast", "Code (SAST)"),
    ("sca", "Dependencies (SCA)"),
    ("iac", "Infrastructure as code"),
    ("image", "Container images"),
    ("iast", "Runtime (IAST)"),
    ("dast", "Running app (DAST)"),
    ("mobile", "Mobile app (MobSF)"),
]
ALWAYS_ON = ("secrets", "sast", "sca", "iac")

# Expected?
YES = "yes"
SUGGESTED = "suggested"
NO = "no"

PATH_PATTERN = re.compile(r"^[A-Za-z0-9_.@+/-]+$")
LOCAL_HOSTS = ("127.0.0.1", "localhost", "0.0.0.0", "::1")  # nosec B104

LOCKFILES = (
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "package.json",
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "pyproject.toml",
    "go.sum",
    "go.mod",
    "Cargo.lock",
    "composer.lock",
    "Gemfile.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "packages.lock.json",
    "pubspec.lock",
    "mix.lock",
)
LOCKFILE_PATTERNS = ("requirements*.txt", "*.csproj")
GRADLE_BUILD_FILES = ("build.gradle", "build.gradle.kts")
GRADLE_SETTINGS_FILES = ("settings.gradle", "settings.gradle.kts")
# Trivy reads gradle.lockfile in every module, and buildscript-gradle.lockfile and
# settings-gradle.lockfile next to them; build.gradle and libs.versions.toml it does not read.
GRADLE_LOCKFILE_SUFFIX = "gradle.lockfile"
COMPOSE_PATTERNS = ("docker-compose*.yml", "docker-compose*.yaml", "compose*.yml", "compose*.yaml")
MAX_FILES = 20000

# Source files by language, named as opengrep-rules names its directories where it has
# one. SAST covers a language only when RULE_LANGUAGES loads its rules: a Rust or Swift
# repository passes Opengrep's generic rules and nothing else, and doctor says so instead
# of reporting it as covered.
SOURCE_LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".php": "php",
    ".java": "java",
    ".kt": "kotlin",
    ".scala": "scala",
    ".rb": "ruby",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cpp": "c++",
    ".cc": "c++",
    ".cxx": "c++",
    ".hpp": "c++",
    ".rs": "rust",
    ".swift": "swift",
    ".m": "objective-c",
    ".mm": "objective-c",
    ".dart": "dart",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".lua": "lua",
    ".pl": "perl",
    ".groovy": "groovy",
    ".clj": "clojure",
    ".ml": "ocaml",
    ".sol": "solidity",
    ".cls": "apex",
}


# --- What the repository contains ------------------------------------------------------


@dataclass
class RepoFacts:
    dockerfiles: List[str] = field(default_factory=list)
    # Number of source files per language (SOURCE_LANGUAGES).
    source_languages: Dict[str, int] = field(default_factory=dict)
    manifests: List[str] = field(default_factory=list)
    iac_files: List[str] = field(default_factory=list)
    compose_files: List[str] = field(default_factory=list)
    # Commands that may start the application, with where they come from. Hints only.
    start_hints: List[Tuple[str, str]] = field(default_factory=list)
    # Mobile apps: the platforms found ("android", "ios", "flutter", "react-native") and
    # the files Trivy needs to see their dependencies.
    mobile_platforms: List[str] = field(default_factory=list)
    gradle_modules: List[str] = field(default_factory=list)  # directories with a build.gradle(.kts)
    gradle_roots: List[str] = field(default_factory=list)  # directories with a settings.gradle(.kts)
    gradle_lockfiles: List[str] = field(default_factory=list)
    android_manifests: List[str] = field(default_factory=list)
    xcode_projects: List[str] = field(default_factory=list)
    podfiles: List[str] = field(default_factory=list)
    swift_packages: List[str] = field(default_factory=list)  # Package.swift
    ios_lockfiles: List[str] = field(default_factory=list)  # Podfile.lock, Package.resolved
    cartfiles: List[str] = field(default_factory=list)  # Cartfile.resolved
    pubspecs: List[str] = field(default_factory=list)  # pubspec.yaml of a Flutter app
    pubspec_locks: List[str] = field(default_factory=list)
    react_native: List[str] = field(default_factory=list)  # package.json of a React Native or Expo app
    truncated: int = 0  # the file count, when it is over MAX_FILES and only the first MAX_FILES were read


def _looks_like_kubernetes(path: Path) -> bool:
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:4000]
    except OSError:
        return False
    return bool(re.search(r"^apiVersion:\s*\S+", head, re.M) and re.search(r"^kind:\s*\S+", head, re.M))


def inspect(root: Path) -> RepoFacts:
    files = [p for p in repository_files(root) if not p.startswith(".venv/")]
    facts = RepoFacts(dockerfiles=find_dockerfiles(root, files))
    if len(files) > MAX_FILES:
        facts.truncated = len(files)
    for relative in files[:MAX_FILES]:
        name = relative.rsplit("/", 1)[-1]
        lower = name.lower()
        _mobile_file(root, facts, relative, name)
        language = SOURCE_LANGUAGES.get(os.path.splitext(lower)[1])
        if language:
            facts.source_languages[language] = facts.source_languages.get(language, 0) + 1
        if name in LOCKFILES or any(fnmatch.fnmatch(lower, p) for p in LOCKFILE_PATTERNS):
            facts.manifests.append(relative)
        if any(fnmatch.fnmatch(lower, p) for p in COMPOSE_PATTERNS):
            facts.compose_files.append(relative)
        if (
            lower.endswith((".tf", ".tf.json"))
            or name in ("Chart.yaml", "kustomization.yaml", "kustomization.yml")
            or (lower.endswith((".yaml", ".yml", ".json")) and _is_cloudformation(root / relative))
        ):
            facts.iac_files.append(relative)
        elif lower.endswith((".yaml", ".yml")) and not relative.startswith(".github/") and relative != GITLAB_CI:
            if _looks_like_kubernetes(root / relative):
                facts.iac_files.append(relative)
    # Trivy's misconfiguration scan reads Dockerfiles too.
    facts.iac_files += [d for d in facts.dockerfiles if d not in facts.iac_files]
    facts.start_hints = start_hints(root, facts.compose_files)
    facts.mobile_platforms = _mobile_platforms(root, facts)
    return facts


def _directory(relative: str) -> str:
    return os.path.dirname(relative) or "."


def _mobile_file(root: Path, facts: RepoFacts, relative: str, name: str) -> None:
    if name in GRADLE_BUILD_FILES:
        facts.gradle_modules.append(_directory(relative))
    elif name in GRADLE_SETTINGS_FILES:
        facts.gradle_roots.append(_directory(relative))
    elif name.endswith(GRADLE_LOCKFILE_SUFFIX):
        facts.gradle_lockfiles.append(relative)
    elif name == "AndroidManifest.xml":
        facts.android_manifests.append(relative)
    elif name == "project.pbxproj" and os.path.dirname(relative).endswith(".xcodeproj"):
        facts.xcode_projects.append(os.path.dirname(relative))
    elif name == "Podfile":
        facts.podfiles.append(relative)
    elif name == "Package.swift":
        facts.swift_packages.append(relative)
    elif name in ("Podfile.lock", "Package.resolved"):
        facts.ios_lockfiles.append(relative)
    elif name == "Cartfile.resolved":
        facts.cartfiles.append(relative)
    elif name == "package.json" and _mentions(root / relative, r'"(react-native|expo)"\s*:'):
        facts.react_native.append(relative)
    elif name == "pubspec.lock":
        facts.pubspec_locks.append(relative)
    elif name == "pubspec.yaml" and _mentions(root / relative, r"sdk:\s*flutter"):
        facts.pubspecs.append(relative)


def _mentions(path: Path, pattern: str) -> bool:
    try:
        return bool(re.search(pattern, path.read_text(encoding="utf-8", errors="replace")[:20000]))
    except OSError:
        return False


def _mobile_platforms(root: Path, facts: RepoFacts) -> List[str]:
    platforms = []
    # A Gradle build alone is a JVM project; an Android app has a manifest, or the Android
    # Gradle plugin in its build files. Either way it needs a Gradle build (settings.gradle):
    # an Expo module's android/ directory has a manifest but is built inside the app's
    # generated, gitignored android/ project, and is not an app of its own.
    if facts.gradle_roots and (
        facts.android_manifests
        or any(
            _mentions(root / module / build, r"com\.android\.(application|library)|android\s*\{")
            for module in facts.gradle_modules
            for build in GRADLE_BUILD_FILES
        )
    ):
        platforms.append("android")
    if facts.xcode_projects or facts.podfiles:
        platforms.append("ios")
    if facts.pubspecs:
        platforms.append("flutter")
    if facts.react_native:
        platforms.append("react-native")
    return platforms


def _is_cloudformation(path: Path) -> bool:
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:2000]
    except OSError:
        return False
    return "AWSTemplateFormatVersion" in head


def start_hints(root: Path, compose_files: List[str]) -> List[Tuple[str, str]]:
    """
    Commands the repository itself declares for starting the application: the `start`
    script of package.json and the services of a compose file that publish a port. Only
    ever offered as a suggestion; whether the app embeds Zen and runs on the CI runner
    is for the team to say.
    """
    hints: List[Tuple[str, str]] = []
    package = root / "package.json"
    if package.is_file():
        try:
            scripts = json.loads(package.read_text(encoding="utf-8")).get("scripts") or {}
        except (OSError, ValueError, AttributeError):
            scripts = {}
        if isinstance(scripts, dict) and isinstance(scripts.get("start"), str):
            hints.append(("npm start", f"package.json: \"start\": {scripts['start']!r}"))
    for compose in compose_files:
        try:
            data = yaml.load((root / compose).read_text(encoding="utf-8"), Loader=_TolerantLoader)  # nosec B506
        except (OSError, yaml.YAMLError):
            continue
        services = data.get("services") if isinstance(data, dict) else None
        if not isinstance(services, dict):
            continue
        built, pulled = [], []
        for service_name, service in services.items():
            if isinstance(service, dict) and service.get("ports"):
                ports = ", ".join(str(p) for p in service["ports"][:3]) if isinstance(service["ports"], list) else ""
                # A service built from this repository is the application; one that only
                # pulls an image is most often its database, cache or mail catcher.
                (built if service.get("build") else pulled).append(
                    (f"docker compose -f {compose} up {service_name}", f"{compose}: service {service_name} ({ports})")
                )
        hints += built + pulled
    return hints


# --- The workflow ----------------------------------------------------------------------


class _TolerantLoader(yaml.SafeLoader):  # pylint: disable=too-many-ancestors
    """Safe loading that ignores tags such as GitLab's !reference instead of failing."""


def _ignore_tag(loader: yaml.SafeLoader, _suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)  # type: ignore[arg-type]


_TolerantLoader.add_multi_constructor("!", _ignore_tag)


@dataclass
class Workflow:
    platform: str
    path: str
    inputs: Dict[str, Any]


def find_workflow(root: Path) -> Optional[Workflow]:
    """The workflow that calls the TDxGuard template, GitHub first."""
    workflows = root / ".github" / "workflows"
    if workflows.is_dir():
        for path in sorted(workflows.iterdir()):
            if path.suffix not in (".yml", ".yaml") or not path.is_file():
                continue
            data = _load_yaml(path)
            jobs = data.get("jobs") if isinstance(data, dict) else None
            for job in (jobs or {}).values() if isinstance(jobs, dict) else []:
                uses = job.get("uses") if isinstance(job, dict) else None
                if isinstance(uses, str) and re.search(r"tdx-guard-ci/.github/workflows/tdxguard\.ya?ml", uses):
                    inputs = job.get("with") if isinstance(job.get("with"), dict) else {}
                    return Workflow(GITHUB, path.relative_to(root).as_posix(), dict(inputs))
    gitlab = root / GITLAB_CI
    if gitlab.is_file():
        data = _load_yaml(gitlab)
        if isinstance(data, dict) and _includes_tdxguard(data.get("include")):
            variables = data.get("variables") if isinstance(data.get("variables"), dict) else {}
            # A variable may be written as {value: ..., description: ...}.
            flat = {k: (v.get("value") if isinstance(v, dict) else v) for k, v in variables.items()}
            return Workflow(GITLAB, GITLAB_CI, flat)
    return None


def _includes_tdxguard(include: Any) -> bool:
    entries = include if isinstance(include, list) else [include]
    for entry in entries:
        text = json.dumps(entry) if not isinstance(entry, str) else entry
        if "tdx-guard-ci" in text or "tdxguard.yml" in text:
            return True
    return False


def _load_yaml(path: Path) -> Any:
    try:
        return yaml.load(path.read_text(encoding="utf-8"), Loader=_TolerantLoader)  # nosec B506
    except (OSError, yaml.YAMLError):
        return None


def _text(inputs: Dict[str, Any], key: str) -> str:
    value = inputs.get(key)
    if value is None or value is False:
        return ""
    return str(value).strip()


def configured_kinds(workflow: Optional[Workflow]) -> Dict[str, bool]:
    if workflow is None:
        return {kind: False for kind, _ in KINDS}
    inputs = workflow.inputs
    result = {kind: True for kind in ALWAYS_ON}
    if workflow.platform == GITHUB:
        result["image"] = bool(_text(inputs, "dockerfile") or _text(inputs, "image_ref"))
        result["iast"] = bool(_text(inputs, "app_start_command"))
        result["dast"] = bool(_text(inputs, "app_start_command") and _text(inputs, "zap_target"))
        result["mobile"] = bool(_text(inputs, "mobile_app") or _text(inputs, "mobile_source"))
    else:
        result["image"] = bool(_text(inputs, "IMAGE_REF"))
        result["iast"] = bool(_text(inputs, "APP_START_COMMAND"))
        result["dast"] = bool(_text(inputs, "ZAP_TARGET") or _text(inputs, "NUCLEI_TARGET"))
        result["mobile"] = False  # the GitLab template has no MobSF job
    return result


# --- Options and rendering -------------------------------------------------------------


@dataclass
class CIOptions:
    dockerfiles: List[str] = field(default_factory=list)  # "path" or "path context"
    image_ref: str = ""
    app_start_command: str = ""
    app_health_url: str = ""
    dast_target: str = ""
    mobile_apps: List[str] = field(default_factory=list)  # built apps, a path or a glob each
    mobile_sources: List[str] = field(default_factory=list)  # "android" or "ios:<dir>"


MOBILE_APP_PATTERN = re.compile(r"^[A-Za-z0-9_.@+/*?\[\]-]+$")
MOBILE_APP_SUFFIXES = (".apk", ".aab", ".apks", ".xapk", ".ipa")


def check_mobile_app(value: str) -> str:
    value = value.strip()
    while value.startswith("./"):
        value = value[2:]
    if not value or value.startswith("/") or re.match(r"^[A-Za-z]:", value) or ".." in value.split("/"):
        raise ConfigError(f"--mobile-app must be a path relative to the repository root: {value!r}")
    if not MOBILE_APP_PATTERN.match(value) or not value.lower().endswith(MOBILE_APP_SUFFIXES):
        raise ConfigError(
            f"--mobile-app is the built app, a path or a glob ending in {', '.join(MOBILE_APP_SUFFIXES)}: {value!r}"
        )
    return value


def check_mobile_source(value: str) -> str:
    platform, _, directory = value.strip().partition(":")
    if platform.strip().lower() not in ("android", "ios"):
        raise ConfigError(f"--mobile-source is android or ios, optionally with :<directory>: {value!r}")
    directory = directory.strip()
    if directory in ("", "."):
        return platform.strip().lower()
    return f"{platform.strip().lower()}:{_check_path(directory, 'The project directory of --mobile-source')}"


def _check_path(value: str, what: str) -> str:
    value = value.strip()
    while value.startswith("./"):
        value = value[2:]
    if not value or value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise ConfigError(f"{what} must be a path relative to the repository root: {value!r}")
    if ".." in value.split("/"):
        raise ConfigError(f"{what} must stay inside the repository: {value!r}")
    if not PATH_PATTERN.match(value):
        raise ConfigError(f"{what} may contain letters, digits and . _ - / @ + only: {value!r}")
    return value


def check_dockerfile(line: str) -> str:
    parts = line.split()
    if not parts or len(parts) > 2:
        raise ConfigError(f"--dockerfile takes a path and optionally a build context: {line!r}")
    return " ".join(
        [_check_path(parts[0], "The Dockerfile")] + [_check_path(p, "The build context") for p in parts[1:]]
    )


def check_url(value: str, what: str) -> str:
    value = value.strip()
    if not value:
        return ""
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname or re.search(r"[\s\"'`\\{}<>$]", value):
        raise ConfigError(f"{what} must be an http:// or https:// URL: {value!r}")
    return value


def check_command(value: str, what: str) -> str:
    value = value.strip()
    if any(ord(char) < 32 for char in value):
        raise ConfigError(f"{what} must be a single line")
    if value.endswith("&") and not value.endswith("&&"):
        raise ConfigError(f"{what} must not end with &: the template already runs it in the background")
    return value


def check_image_ref(value: str) -> str:
    value = value.strip()
    rest = re.sub(r"\$\{\{[^}]*\}\}", "x", value)
    if value and not re.match(r"^[A-Za-z0-9_.@:/${}-]+$", rest):
        raise ConfigError(f"--image-ref must look like registry/name:tag: {value!r}")
    return value


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _is_local(url: str) -> bool:
    return (urlsplit(url).hostname or "").lower() in LOCAL_HOSTS


ZEN_NOTE = (
    "# The application must embed Zen: `pip install aikido_zen` and call\n"
    "# `aikido_zen.protect()` on the very first line, BEFORE any other import\n"
    '# (Node: `require("@aikidosec/firewall")`). Without it IAST reports nothing.\n'
)
OWN_NOTE = "# Only scan an environment you own, and never production without approval.\n"


def suggested_inputs(platform: str, options: CIOptions) -> Dict[str, str]:
    """The optional inputs the options switch on, as {input name: YAML value text}."""
    inputs: Dict[str, str] = {}
    if platform == GITHUB:
        if len(options.dockerfiles) == 1:
            inputs["dockerfile"] = _quote(options.dockerfiles[0])
        elif options.dockerfiles:
            inputs["dockerfile"] = "|\n" + "".join(f"  {line}\n" for line in options.dockerfiles)
        if options.image_ref:
            inputs["image_ref"] = _quote(options.image_ref)
        if options.app_start_command:
            inputs["app_start_command"] = _quote(options.app_start_command)
            if options.app_health_url and options.app_health_url != DEFAULT_APP_HEALTH_URL:
                inputs["app_health_url"] = _quote(options.app_health_url)
            if options.dast_target:
                inputs["zap_target"] = _quote(options.dast_target)
        if options.mobile_apps:
            inputs["mobile_app"] = _lines_value(options.mobile_apps)
        if options.mobile_sources:
            inputs["mobile_source"] = _lines_value(options.mobile_sources)
    else:
        if options.image_ref:
            inputs["IMAGE_REF"] = _quote(options.image_ref)
        if options.app_start_command:
            inputs["RUNTIME_IMAGE"] = _quote(DEFAULT_RUNTIME_IMAGE)
            inputs["APP_START_COMMAND"] = _quote(options.app_start_command)
            if options.app_health_url and options.app_health_url != DEFAULT_APP_HEALTH_URL:
                inputs["APP_HEALTH_URL"] = _quote(options.app_health_url)
        if options.dast_target:
            inputs["ZAP_TARGET"] = _quote(options.dast_target)
    return inputs


def _lines_value(lines: List[str]) -> str:
    """One line quoted, several as a YAML block scalar."""
    if len(lines) == 1:
        return _quote(lines[0])
    return "|\n" + "".join(f"  {line}\n" for line in lines)


MOBILE_BLOCK = (
    "# --- Mobile app (MobSF) ---\n"
    "# MobSF analyses the app in a throwaway container cut off from the network. The built\n"
    "# app (.apk, .aab, .ipa) gives the most: the whole decompiled app, its libraries, the\n"
    "# signing certificate and the native binaries. mobile_app_artifact downloads it from an\n"
    "# earlier job of this workflow; mobile_source analyses the source instead.\n"
)


def _mobile_block(options: CIOptions) -> str:
    block = MOBILE_BLOCK
    if options.mobile_apps:
        block += f"mobile_app: {_lines_value(options.mobile_apps)}" + ("" if len(options.mobile_apps) > 1 else "\n")
        block += '# mobile_app_artifact: "app-release"   # the upload-artifact name of your build job\n'
    if options.mobile_sources:
        block += f"mobile_source: {_lines_value(options.mobile_sources)}" + (
            "" if len(options.mobile_sources) > 1 else "\n"
        )
    return block


def _github_blocks(options: CIOptions) -> List[str]:
    blocks = []
    if options.dockerfiles or options.image_ref:
        block = (
            "# --- Image scan ---\n"
            "# Built in the job and scanned, nothing is pushed: the base image's CVEs, its OS\n"
            "# packages and any secret baked into a layer, which `trivy fs .` cannot see.\n"
        )
        if len(options.dockerfiles) == 1:
            block += f"dockerfile: {_quote(options.dockerfiles[0])}\n"
        elif options.dockerfiles:
            block += "# One per line: the Dockerfile, then optionally its own build context.\n"
            block += "dockerfile: |\n" + "".join(f"  {line}\n" for line in options.dockerfiles)
        if options.image_ref:
            block += "# Pulled from the registry: the tag has to exist when this workflow runs.\n"
            block += f"image_ref: {_quote(options.image_ref)}\n"
        blocks.append(block)
    if options.app_start_command:
        block = (
            "# --- IAST (Aikido Zen) + DAST (ZAP) ---\n"
            "# The application is started once in the job: ZAP attacks it from the outside and\n"
            "# Zen watches from the inside.\n" + ZEN_NOTE
        )
        block += "# Runs in the background, do not append &.\n"
        block += f"app_start_command: {_quote(options.app_start_command)}\n"
        if options.app_health_url and options.app_health_url != DEFAULT_APP_HEALTH_URL:
            block += f"app_health_url: {_quote(options.app_health_url)}\n"
        block += '# traffic_command: "pytest tests/e2e"   # requests Zen observes besides ZAP\'s\n'
        if options.dast_target:
            if not _is_local(options.dast_target):
                block += OWN_NOTE
            block += f"zap_target: {_quote(options.dast_target)}\n"
            block += "# nuclei: true        # known CVEs and exposed panels on the same target\n"
        blocks.append(block)
    elif options.dast_target:
        blocks.append(
            "# --- DAST (ZAP) --- NOT ACTIVE YET\n"
            "# On GitHub, ZAP runs in the runtime job, which only starts when app_start_command\n"
            "# is set. Add the command that starts the application, then uncomment this line.\n"
            + OWN_NOTE
            + f"# zap_target: {_quote(options.dast_target)}\n"
        )
    if options.mobile_apps or options.mobile_sources:
        blocks.append(_mobile_block(options))
    return blocks


def _gitlab_blocks(options: CIOptions) -> List[str]:
    blocks = []
    if options.image_ref or options.dockerfiles:
        block = (
            "# --- Image scan ---\n"
            "# GitLab scans an image ALREADY in a registry: the project's own build job has to\n"
            "# push it first, in a stage before `scan`.\n"
        )
        if options.dockerfiles:
            block += f"# Dockerfiles in this repository: {', '.join(d.split()[0] for d in options.dockerfiles)}.\n"
            block += "# The GitLab template does not build them, and it scans ONE image.\n"
        block += (
            f"IMAGE_REF: {_quote(options.image_ref)}\n"
            if options.image_ref
            else f"# IMAGE_REF: {_quote(GITLAB_IMAGE_REF_HINT)}\n"
        )
        blocks.append(block)
    if options.app_start_command:
        block = "# --- IAST (Aikido Zen) ---\n" + ZEN_NOTE
        block += "# RUNTIME_IMAGE has to ship python3 (for the collector) and the application's runtime.\n"
        block += f"RUNTIME_IMAGE: {_quote(DEFAULT_RUNTIME_IMAGE)}\n"
        block += "# Runs in the background, do not append &.\n"
        block += f"APP_START_COMMAND: {_quote(options.app_start_command)}\n"
        if options.app_health_url and options.app_health_url != DEFAULT_APP_HEALTH_URL:
            block += f"APP_HEALTH_URL: {_quote(options.app_health_url)}\n"
        block += '# Zen only sees these requests on GitLab:\n# TRAFFIC_COMMAND: "pytest tests/e2e"\n'
        blocks.append(block)
    if options.dast_target:
        if _is_local(options.dast_target):
            raise ConfigError(
                "On GitLab ZAP runs in a job of its own and cannot reach 127.0.0.1 or localhost.",
                "Give the URL of a deployed test or staging environment with --dast-target.",
            )
        block = "# --- DAST ---\n# ZAP and Nuclei scan an ALREADY DEPLOYED environment.\n" + OWN_NOTE
        block += f"ZAP_TARGET: {_quote(options.dast_target)}\n"
        block += f"# NUCLEI_TARGET: {_quote(options.dast_target)}\n"
        blocks.append(block)
    if options.mobile_apps or options.mobile_sources:
        blocks.append(GITLAB_MOBILE_NOTE)
    return blocks


GITLAB_MOBILE_NOTE = (
    "# --- Mobile app (MobSF) --- GitHub only\n"
    "# The GitLab template has no MobSF job yet. Analyse the app with `tdxguard scan`\n"
    "# (mobile: in .tdxguard.yml, needs Docker), which uploads the result to TDxGuard.\n"
)


def _indent(text: str, spaces: int) -> str:
    prefix = " " * spaces
    return "".join(prefix + line if line.strip() else line for line in text.splitlines(keepends=True))


def render_workflow(platform: str, project: str, repository: str, options: CIOptions) -> str:
    """The CI file, as the New project page generates it (backend snippets.py)."""
    bao_role = f"ci-{project}"
    if platform == GITHUB:
        extra = "".join("\n" + _indent(block, 6) for block in _github_blocks(options))
        org = repository.split("/", 1)[0] if repository else DEFAULT_GITHUB_ORG
        if org == DEFAULT_GITHUB_ORG:
            runs_on = (
                "\n      # --- Runner (optional) ---\n"
                "      # Defaults to `Linux`, the self-hosted Linux runners of tda-corp.\n"
                "      # Set it to run elsewhere, e.g. on GitHub-hosted runners:\n"
                "      # runs_on: ubuntu-latest\n"
            )
        else:
            runs_on = (
                "\n      # --- Runner ---\n"
                "      # REQUIRED outside the tda-corp organisation: the default `Linux` self-hosted\n"
                "      # runners only serve tda-corp, a job asking for them elsewhere waits forever.\n"
                "      # Any Linux runner label works, e.g. a self-hosted one of your organisation.\n"
                "      runs_on: ubuntu-latest\n"
            )
        return (
            "# TDxGuard security scan. Commit this file as .github/workflows/tdxguard.yml\n"
            "# All optional inputs: ci-templates/examples/github-caller.yml in tdx-guard.\n"
            "\n"
            "name: tdxguard\n"
            "\n"
            "on:\n"
            "  push:\n"
            "    branches: [main]\n"
            "  pull_request:\n"
            "\n"
            "permissions:\n"
            "  contents: read\n"
            "  id-token: write          # REQUIRED - without it the CI cannot obtain an OpenBao token\n"
            "  security-events: write   # findings as inline annotations on the pull request diff\n"
            "  pull-requests: write     # the summary comment on the pull request\n"
            "  actions: read            # upload-sarif needs it on a private repository\n"
            "\n"
            "jobs:\n"
            "  tdxguard:\n"
            "    uses: tda-corp/tdx-guard-ci/.github/workflows/tdxguard.yml@v1\n"
            "    with:\n"
            f"      product: {project}\n"
            f"      bao_role: {bao_role}\n" + extra + runs_on
        )
    extra = "".join("\n" + _indent(block, 2) for block in _gitlab_blocks(options))
    return (
        "# TDxGuard security scan. Add this to the .gitlab-ci.yml of the repository.\n"
        "# All optional variables: ci-templates/examples/gitlab-caller.yml in tdx-guard.\n"
        "#\n"
        "# - If the file already has `include:` or `variables:`, add these entries to them\n"
        "#   instead of repeating the keys (a repeated key overrides the first one).\n"
        "# - If the file defines its own `stages:`, add `tools`, `scan` and `publish` to it:\n"
        '#   the TDxGuard jobs run in those stages and fail with "chosen stage does not exist"\n'
        "#   otherwise.\n"
        "# - The jobs run on the runners tagged `docker`. If this GitLab tags its Docker\n"
        "#   runners differently, set RUNNER_TAG below.\n"
        "\n"
        "include:\n"
        "  - project: tdx-product/tdx-guard-ci\n"
        "    ref: v1\n"
        "    file: /tdxguard.yml\n"
        "\n"
        "variables:\n"
        f"  PRODUCT: {project}\n"
        f"  BAO_ROLE: {bao_role}\n"
        "\n"
        "  # Off for the first runs, turn it on once the inherited findings are sorted.\n"
        '  FAIL_ON_CRITICAL: "false"\n' + extra + "\n"
        "  # --- Runner (optional) ---\n"
        '  # RUNNER_TAG: "docker"\n'
    )


def workflow_path(platform: str) -> str:
    return GITHUB_WORKFLOW if platform == GITHUB else GITLAB_CI


def input_changes(existing: Dict[str, Any], suggested: Dict[str, str]) -> List[str]:
    """A diff-like summary: + an input to add, ~ one whose value differs, = one already set."""
    lines = []
    for key, value in suggested.items():
        wanted = value if value.startswith("|") else json.loads(value)
        have = existing.get(key)
        if have is None or str(have).strip() == "":
            shown = value if not value.startswith("|") else "|  " + " / ".join(value.split("\n")[1:-1]).strip()
            lines.append(f"+ {key}: {shown}")
        elif not value.startswith("|") and str(have).strip() != str(wanted).strip():
            lines.append(f"~ {key}: {json.dumps(str(have))} -> {value}")
        else:
            lines.append(f"= {key} (already set)")
    return lines


# --- Doctor ----------------------------------------------------------------------------


NO_WORKFLOW = "No TDxGuard workflow found: nothing is scanned in CI."


@dataclass
class Row:
    kind: str
    label: str
    expected: str
    why: str
    configured: Optional[bool]
    received: str
    action: str
    detail: str = ""


def _list(paths: List[str], limit: int = 2) -> str:
    shown = ", ".join(paths[:limit])
    return shown + (f" +{len(paths) - limit}" if len(paths) > limit else "")


def received_text(scan_coverage: Optional[Dict[str, Any]], kind: str, state: str) -> str:
    """state: 'ok' (the server answered with scan_coverage), 'old', 'offline', 'unknown-product'."""
    if state == "offline":
        return "not checked"
    if state == "unknown-product":
        return "no such product"
    if state == "old" or scan_coverage is None:
        return "unknown (old server)"
    if kind not in scan_coverage:
        return "unknown (old server)"
    entry = scan_coverage.get(kind)
    last = entry.get("last_import") if isinstance(entry, dict) else None
    return str(last)[:10] if last else "never"


def diagnose(
    facts: RepoFacts,
    workflow: Optional[Workflow],
    platform: str,
    scan_coverage: Optional[Dict[str, Any]],
    server_state: str,
) -> List[Row]:
    configured = configured_kinds(workflow)
    rows: List[Row] = []
    hint = facts.start_hints[0][0] if facts.start_hints else ""
    for kind, label in KINDS:
        expected, why = _expectation(kind, facts)
        received = received_text(scan_coverage, kind, server_state)
        is_configured = configured.get(kind, False)
        if is_configured and expected != YES and kind not in ALWAYS_ON:
            expected, why = YES, "the workflow switches it on"
        action, detail = "", ""
        if workflow is None:
            action = f"tdxguard init --ci {platform}" if expected != NO else ""
            detail = NO_WORKFLOW
        elif not is_configured and expected != NO:
            action, detail = _what_to_add(kind, platform, facts, workflow, hint)
        elif is_configured and received == "never" and expected != NO:
            action = "push to the default branch"
            detail = "Configured, but TDxGuard has not received it yet: check the last pipeline run."
        # What the scanner cannot see, whatever the workflow says
        gap = _sast_gap(facts) if kind == "sast" else sca_gap(facts) if kind == "sca" else ""
        if kind == "mobile" and workflow is not None and is_configured:
            gap = _debug_build_note(str(workflow.inputs.get("mobile_app") or ""))
        if gap:
            detail = f"{detail}\n{gap}" if detail else gap
        rows.append(Row(kind, label, expected, why, is_configured, received, action, detail))
    return rows


def _debug_build_note(mobile_app: str) -> str:
    """A configured app that looks like a debug build: MobSF reports what only the debug build has."""
    debug = [
        line.strip() for line in mobile_app.splitlines() if re.search(r"(^|[/_.-])debug([/_.-]|$)", line.strip(), re.I)
    ]
    if not debug:
        return ""
    return (
        f"{debug[0]} looks like a debug build: MobSF reports android:debuggable, the debug certificate and debug-only "
        "libraries (LeakCanary) as findings of the app. Scan the release build (assembleRelease / bundleRelease)."
    )


def _expectation(kind: str, facts: RepoFacts) -> Tuple[str, str]:
    if kind == "secrets":
        return YES, "every repository"
    if kind == "sast":
        covered, uncovered = sast_languages(facts)
        if covered:
            return YES, ", ".join(covered)
        if uncovered:
            return YES, "no rules for " + ", ".join(uncovered)
        return YES, "source code"
    if kind == "sca":
        return (YES, _list(facts.manifests)) if facts.manifests else (NO, "no manifest or lockfile")
    if kind == "iac":
        return (YES, _list(facts.iac_files)) if facts.iac_files else (NO, "no IaC files")
    if kind == "image":
        return (YES, _list(facts.dockerfiles)) if facts.dockerfiles else (NO, "no Dockerfile")
    if kind == "mobile":
        return (SUGGESTED, ", ".join(facts.mobile_platforms)) if facts.mobile_platforms else (NO, "no mobile app")
    if facts.start_hints:
        return SUGGESTED, facts.start_hints[0][1]
    return NO, "no start command found"


def sast_languages(facts: RepoFacts) -> Tuple[List[str], List[str]]:
    """The repository's languages Opengrep has rules for, and those it has none for, most files first."""
    ordered = sorted(facts.source_languages, key=lambda language: (-facts.source_languages[language], language))
    return [x for x in ordered if x in RULE_LANGUAGES], [x for x in ordered if x not in RULE_LANGUAGES]


def _sast_gap(facts: RepoFacts) -> str:
    _, uncovered = sast_languages(facts)
    if not uncovered:
        return ""
    counted = ", ".join(f"{language} ({facts.source_languages[language]} files)" for language in uncovered)
    text = f"Opengrep has no rules for {counted}: SAST does not analyse that code."
    if {"swift", "objective-c"} & set(uncovered):
        text += " MobSF's mobile app analysis has rules for Swift and Objective-C."
    return text


def gradle_task(module: str, gradle_root: str = ".") -> str:
    """The dependencies task of a Gradle module directory, relative to the build's root
    (the directory of settings.gradle): app -> :app:dependencies, the root -> dependencies."""
    relative = os.path.relpath(module, gradle_root).replace(os.sep, "/")
    return "dependencies" if relative == "." else ":" + relative.replace("/", ":") + ":dependencies"


def gradle_root_of(module: str, roots: List[str]) -> str:
    """The innermost Gradle build (settings.gradle directory) a module belongs to."""
    candidates = [r for r in roots if r == "." or module == r or module.startswith(r + "/")]
    return max(candidates, key=len) if candidates else "."


def sca_gap(facts: RepoFacts) -> str:
    """What Trivy cannot see of a mobile app's dependencies, and how to fix it. Trivy reads
    lockfiles only: gradle.lockfile, Podfile.lock, Package.resolved, pubspec.lock."""
    notes: List[str] = []
    if "android" in facts.mobile_platforms or (facts.gradle_modules and "flutter" in facts.mobile_platforms):
        locked = {_directory(path) for path in facts.gradle_lockfiles}
        unlocked = [module for module in facts.gradle_modules if module not in locked]
        if unlocked:
            builds: Dict[str, List[str]] = {}
            for module in unlocked:
                builds.setdefault(gradle_root_of(module, facts.gradle_roots), []).append(module)
            commands = []
            for gradle_root, modules in list(builds.items())[:3]:
                ordered = sorted(modules, key=lambda m: (m != gradle_root, m))[:8]
                tasks = " ".join(gradle_task(m, gradle_root) for m in ordered)
                where = "" if gradle_root == "." else f"cd {gradle_root} && "
                commands.append(f"  {where}./gradlew {tasks} --write-locks")
            if not facts.gradle_lockfiles:
                first = "Trivy cannot see the Gradle dependencies: there is no gradle.lockfile, and Trivy reads"
                first += " neither build.gradle nor libs.versions.toml."
            else:
                first = f"{len(unlocked)} Gradle module(s) without gradle.lockfile ({_list(unlocked, 3)}): Trivy"
                first += " does not see their dependencies."
            notes.append(
                first + "\n"
                "Turn on dependency locking for every module, in the root build.gradle(.kts) of the build:\n"
                "  allprojects { dependencyLocking { lockAllConfigurations() } }\n"
                "then write one gradle.lockfile per module and commit them:\n" + "\n".join(commands) + "\n"
                "Run that command again whenever a dependency changes."
            )
    if facts.podfiles and not any(path.endswith("Podfile.lock") for path in facts.ios_lockfiles):
        notes.append("Podfile without Podfile.lock: Trivy reads only the lockfile. Commit Podfile.lock (pod install).")
    if facts.swift_packages and not any(path.endswith("Package.resolved") for path in facts.ios_lockfiles):
        notes.append(
            "Package.swift without Package.resolved: Trivy reads only the resolved file. Commit Package.resolved."
        )
    if facts.cartfiles:
        notes.append(
            "Carthage: Trivy does not read Cartfile.resolved, so the libraries it pins are not checked for known "
            "vulnerabilities. Few iOS libraries have advisories in any database: keep them up to date "
            "(carthage outdated)."
        )
    if facts.ios_lockfiles:
        notes.append(
            "CocoaPods and Swift packages: Trivy lists them, but few of them have advisories in the databases "
            "Trivy uses, so expect few vulnerabilities to be reported for them."
        )
    if facts.react_native and not {"android", "ios"} & set(facts.mobile_platforms):
        notes.append(
            "React Native / Expo: Trivy reads the JavaScript dependencies from package-lock.json. The native "
            "android/ and ios/ projects are generated (expo prebuild) and not in the repository, so their Gradle "
            "and CocoaPods dependencies are seen only by MobSF, on the built app."
        )
    if facts.pubspecs and not facts.pubspec_locks:
        notes.append("pubspec.yaml without pubspec.lock: Trivy reads only the lockfile. Commit pubspec.lock.")
    return "\n".join(notes)


def mobile_suggestions(facts: RepoFacts) -> List[str]:
    """mobile_source lines for the projects MobSF can analyse as source."""
    lines = []
    for manifest in facts.android_manifests:
        if manifest.endswith("app/src/main/AndroidManifest.xml"):
            directory = manifest[: -len("app/src/main/AndroidManifest.xml")].rstrip("/")
            lines.append("android" + (f":{directory}" if directory else ""))
    # A Flutter app's ios/ holds the Runner shell and no app code (MobSF says "No Code"): its
    # Dart code is analysed in the built .ipa only
    flutter_apps = [os.path.dirname(pubspec) for pubspec in facts.pubspecs]
    for project in facts.xcode_projects:
        directory = os.path.dirname(project)
        if any(directory == os.path.join(app, "ios") if app else directory == "ios" for app in flutter_apps):
            continue
        lines.append("ios" + (f":{directory}" if directory else ""))
    return list(dict.fromkeys(lines))


def _mobile_action(platform: str, facts: RepoFacts) -> Tuple[str, str]:
    sources = mobile_suggestions(facts)
    if platform != GITHUB:
        return (
            "tdxguard scan (mobile: in .tdxguard.yml)",
            "The GitLab template has no MobSF job yet: analyse the app locally with `tdxguard scan` "
            "(needs Docker), which uploads the result.",
        )
    detail = (
        "MobSF analyses the built app best (the runner needs Docker): name the .apk/.aab/.ipa your build "
        "produces, with mobile_app_artifact when an earlier job uploads it."
    )
    if sources:
        detail += f" Without a build in CI: mobile_source: {_quote(sources[0])} analyses the source."
    if facts.pubspecs:
        detail += (
            " Flutter: the app's code is Dart, which MobSF sees in the built app only (flutter build apk, "
            "flutter build ipa); the source of android/ and ios/ holds little more than the manifest."
        )
    return 'mobile_app: "<path to the built .apk or .ipa>"', detail


def _what_to_add(kind: str, platform: str, facts: RepoFacts, workflow: Workflow, hint: str) -> Tuple[str, str]:
    inputs = workflow.inputs
    if kind == "mobile":
        return _mobile_action(platform, facts)
    if kind == "image":
        if platform == GITHUB:
            if len(facts.dockerfiles) == 1:
                return f"dockerfile: {_quote(facts.dockerfiles[0])}", ""
            lines = "\n".join(f"  {d}" for d in facts.dockerfiles)
            return "dockerfile: |", f"dockerfile: |\n{lines}"
        return (
            f"IMAGE_REF: {_quote(GITLAB_IMAGE_REF_HINT)}",
            "GitLab scans an image your build job has pushed (in a stage before `scan`); it does not build "
            "Dockerfiles and takes one image.",
        )
    command = hint or "<command that starts the app>"
    if kind == "iast":
        key = "app_start_command" if platform == GITHUB else "APP_START_COMMAND"
        return (
            f"{key}: {_quote(command)}",
            'The app must embed Aikido Zen (aikido_zen.protect() first / require("@aikidosec/firewall")). '
            + ("Suggested from " + facts.start_hints[0][1] + "; check it." if hint else ""),
        )
    if platform == GITHUB:
        if not _text(inputs, "app_start_command"):
            return (
                'zap_target: "http://127.0.0.1:8000"',
                "On GitHub ZAP runs in the runtime job: it needs app_start_command as well.",
            )
        return 'zap_target: "http://127.0.0.1:8000"', "The URL of the started app (or of a test environment you own)."
    return (
        'ZAP_TARGET: "https://<staging URL>"',
        "A deployed test or staging environment you own; never production without approval.",
    )


def exit_ok(rows: List[Row]) -> bool:
    return all(row.configured for row in rows if row.expected == YES)
