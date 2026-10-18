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

from tdxguard.config import SKIPPED_DIRECTORIES, find_dockerfiles
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


def _walk(root: Path):
    count = 0
    for directory, subdirectories, files in os.walk(root):
        subdirectories[:] = sorted(d for d in subdirectories if d not in SKIPPED_DIRECTORIES and d != ".venv")
        for name in sorted(files):
            count += 1
            if count > MAX_FILES:
                return
            yield os.path.relpath(os.path.join(directory, name), root).replace(os.sep, "/"), name


def _looks_like_kubernetes(path: Path) -> bool:
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:4000]
    except OSError:
        return False
    return bool(re.search(r"^apiVersion:\s*\S+", head, re.M) and re.search(r"^kind:\s*\S+", head, re.M))


def inspect(root: Path) -> RepoFacts:
    facts = RepoFacts(dockerfiles=find_dockerfiles(root))
    for relative, name in _walk(root):
        lower = name.lower()
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
    return facts


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
        for service_name, service in services.items():
            if isinstance(service, dict) and service.get("ports"):
                ports = ", ".join(str(p) for p in service["ports"][:3]) if isinstance(service["ports"], list) else ""
                hints.append(
                    (f"docker compose -f {compose} up {service_name}", f"{compose}: service {service_name} ({ports})")
                )
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
    else:
        result["image"] = bool(_text(inputs, "IMAGE_REF"))
        result["iast"] = bool(_text(inputs, "APP_START_COMMAND"))
        result["dast"] = bool(_text(inputs, "ZAP_TARGET") or _text(inputs, "NUCLEI_TARGET"))
    return result


# --- Options and rendering -------------------------------------------------------------


@dataclass
class CIOptions:
    dockerfiles: List[str] = field(default_factory=list)  # "path" or "path context"
    image_ref: str = ""
    app_start_command: str = ""
    app_health_url: str = ""
    dast_target: str = ""


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
    return blocks


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
            detail = "No TDxGuard workflow found: nothing is scanned in CI."
        elif not is_configured and expected != NO:
            action, detail = _what_to_add(kind, platform, facts, workflow, hint)
        elif is_configured and received == "never" and expected != NO:
            action = "push to the default branch"
            detail = "Configured, but TDxGuard has not received it yet: check the last pipeline run."
        if kind == "sast" and not detail:
            detail = _sast_gap(facts)
        rows.append(Row(kind, label, expected, why, is_configured, received, action, detail))
    return rows


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
    return f"Opengrep has no rules for {counted}: SAST does not analyse that code."


def _what_to_add(kind: str, platform: str, facts: RepoFacts, workflow: Workflow, hint: str) -> Tuple[str, str]:
    inputs = workflow.inputs
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
