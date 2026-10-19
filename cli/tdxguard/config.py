""".tdxguard.yml: loading, validation, defaults, and what `tdxguard init` writes."""

from __future__ import annotations

import fnmatch
import os
import re
import subprocess  # nosec B404
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import yaml

from tdxguard.engine.scan import VENDORED_DIRS
from tdxguard.errors import ConfigError

CONFIG_FILE = ".tdxguard.yml"
TOP_LEVEL_KEYS = ("project", "repository", "engine", "exclude", "images", "mobile", "gate")
IMAGE_KEYS = ("dockerfile", "context", "name", "ref")
MOBILE_KEYS = ("app", "source", "path")
MOBILE_PLATFORMS = ("android", "ios")
ENGINES = ("auto", "docker", "native")
GATE_KEYS = ("critical", "high", "ignore_unfixed")
SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
# The scanners leave the vendored directories out (VENDORED_DIRS); a Dockerfile or a
# Package.swift found there belongs to a third-party library, not to the product.
SKIPPED_DIRECTORIES = {".git", *VENDORED_DIRS}


@dataclass
class Image:
    """A Dockerfile to build and scan, or (`remote_ref`) an image Trivy pulls from its registry."""

    name: str
    dockerfile: Optional[str] = None
    context: Optional[str] = None
    remote_ref: Optional[str] = None

    @property
    def remote(self) -> bool:
        return self.remote_ref is not None

    @property
    def ref(self) -> str:
        return self.remote_ref or f"tdxguard-local/{self.name}:scan"


@dataclass
class MobileApp:
    """A mobile app MobSF analyses: a built app (`app`, a path or a glob) or a project's source."""

    app: Optional[str] = None
    source: Optional[str] = None  # android or ios
    path: str = "."  # the project directory of a source

    @property
    def argument(self) -> str:
        """The helper's argument: --app <app> or --source <platform>:<path>."""
        return self.app if self.app else f"{self.source}:{self.path}"


@dataclass
class Config:
    project: str
    repository: Optional[str] = None
    exclude: List[str] = field(default_factory=list)
    images: List[Image] = field(default_factory=list)
    mobile: List[MobileApp] = field(default_factory=list)
    gate: Dict[str, Optional[int]] = field(default_factory=dict)
    engine: Optional[str] = None  # auto, docker or native; None: not set in the file
    # Count only vulnerabilities with a fixed version, like CI's `trivy --ignore-unfixed`.
    ignore_unfixed: bool = True


def derive_slug(dockerfile: str) -> str:
    """
    The image slug, derived exactly like the CI template (ci-templates/github/tdxguard.yml,
    image_scan) does it with tr and sed, so local and CI results carry the same names:
      docker/backend/Dockerfile -> docker-backend
      Dockerfile                -> root
      ./Dockerfile.prod         -> prod
    """
    slug = dockerfile.lower()
    if slug.startswith("./"):
        slug = slug[2:]
    slug = re.sub(r"[^a-z0-9._-]", "-", slug)
    # sed 's#-*dockerfile##' without the g flag: the first occurrence only.
    slug = re.sub(r"-*dockerfile", "", slug, count=1)
    slug = re.sub(r"^[.-]*", "", slug)
    slug = re.sub(r"[.-]*$", "", slug)
    return slug or "root"


def derive_ref_slug(ref: str) -> str:
    """
    The slug of a registry image: its last path segment and its tag.
      ghcr.io/org/app:1.2        -> app-1.2
      registry:5000/team/api     -> api
      nginx@sha256:abc...        -> nginx
    """
    name = ref.split("@", 1)[0].rsplit("/", 1)[-1]
    repository, _, tag = name.partition(":")
    slug = re.sub(r"[^a-z0-9._-]", "-", (repository + ("-" + tag if tag else "")).lower())
    slug = re.sub(r"^[.-]*", "", slug)
    return slug or "image"


def _where(path: str) -> str:
    return f"{CONFIG_FILE}: {path}" if path else CONFIG_FILE


def _check_relative_path(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{_where(path)}: must be a non-empty string")
    value = value.strip()
    if value.startswith("/") or os.path.isabs(value):
        raise ConfigError(f"{_where(path)}: must be a path relative to the repository root, not {value!r}")
    if ".." in Path(value).parts:
        raise ConfigError(f"{_where(path)}: must stay inside the repository, {value!r} leaves it")
    while value.startswith("./"):
        value = value[2:]
    return value or "."


def parse(data: Any, root: Optional[Path] = None) -> Config:
    """Validates the parsed YAML. With `root`, also checks that Dockerfiles and contexts exist."""
    if not isinstance(data, dict):
        raise ConfigError(f"{CONFIG_FILE}: must be a mapping of keys to values (project: ..., images: ...)")

    unknown = [str(k) for k in data if k not in TOP_LEVEL_KEYS]
    if unknown:
        raise ConfigError(
            f"{_where(unknown[0])}: unknown key",
            f"Allowed keys: {', '.join(TOP_LEVEL_KEYS)}.",
        )

    project = data.get("project")
    if project is None:
        raise ConfigError(f"{_where('project')}: is required (the TDxGuard product name)")
    if not isinstance(project, str) or not project.strip():
        raise ConfigError(f"{_where('project')}: must be a non-empty string")

    repository = data.get("repository")
    if repository is not None and (not isinstance(repository, str) or not repository.strip()):
        raise ConfigError(f"{_where('repository')}: must be a string such as org/repo")

    engine = data.get("engine")
    if engine is not None and engine not in ENGINES:
        raise ConfigError(f"{_where('engine')}: must be one of {', '.join(ENGINES)}, not {engine!r}")

    exclude = _parse_exclude(data.get("exclude"))
    images = _parse_images(data.get("images"), root)
    mobile = _parse_mobile(data.get("mobile"))
    gate, ignore_unfixed = _parse_gate(data.get("gate"))

    return Config(
        project=project.strip(),
        repository=repository.strip() if isinstance(repository, str) else None,
        exclude=exclude,
        images=images,
        mobile=mobile,
        gate=gate,
        engine=engine,
        ignore_unfixed=ignore_unfixed,
    )


def _parse_exclude(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise ConfigError(f"{_where('exclude')}: must be a list of paths")
    return [_check_relative_path(item, f"exclude[{i}]") for i, item in enumerate(value)]


def _parse_images(value: Any, root: Optional[Path]) -> List[Image]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ConfigError(f"{_where('images')}: must be a list of entries with a dockerfile or a ref key")

    images: List[Image] = []
    for i, entry in enumerate(value):
        where = f"images[{i}]"
        if isinstance(entry, str):
            entry = {"dockerfile": entry}
        if not isinstance(entry, dict):
            raise ConfigError(f"{_where(where)}: must be a mapping with a dockerfile or a ref key")
        unknown = [str(k) for k in entry if k not in IMAGE_KEYS]
        if unknown:
            raise ConfigError(f"{_where(where + '.' + unknown[0])}: unknown key", f"Allowed: {', '.join(IMAGE_KEYS)}.")
        if "ref" in entry:
            image = _parse_remote_image(entry, where)
            _check_unique(images, image.name, where)
            images.append(image)
            continue
        if "dockerfile" not in entry:
            raise ConfigError(
                f"{_where(where + '.dockerfile')}: is required",
                "Or give `ref:` for an image in a registry (ghcr.io/org/app:tag).",
            )

        dockerfile = _check_relative_path(entry["dockerfile"], f"{where}.dockerfile")
        if entry.get("context") is None:
            context = os.path.dirname(dockerfile) or "."
        else:
            context = _check_relative_path(entry["context"], f"{where}.context")

        if entry.get("name") is None:
            name = derive_slug(dockerfile)
        else:
            name = entry["name"]
            if not isinstance(name, str) or not SLUG_PATTERN.match(name):
                raise ConfigError(
                    f"{_where(where + '.name')}: must be a slug of lowercase letters, digits, '.', '_' and '-'"
                )

        if root is not None:
            if not (root / dockerfile).is_file():
                raise ConfigError(f"{_where(where + '.dockerfile')}: file not found: {dockerfile}")
            if not (root / context).is_dir():
                raise ConfigError(f"{_where(where + '.context')}: directory not found: {context}")

        _check_unique(images, name, where)
        images.append(Image(dockerfile=dockerfile, context=context, name=name))
    return images


def _parse_mobile(value: Any) -> List[MobileApp]:
    """`mobile:` a list of `- app: <path or glob>` and `- source: android|ios` (with `path:`)."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ConfigError(f"{_where('mobile')}: must be a list of entries with an app or a source key")
    apps: List[MobileApp] = []
    for i, entry in enumerate(value):
        where = f"mobile[{i}]"
        if not isinstance(entry, dict):
            raise ConfigError(f"{_where(where)}: must be a mapping with an app or a source key")
        unknown = [str(k) for k in entry if k not in MOBILE_KEYS]
        if unknown:
            raise ConfigError(f"{_where(where + '.' + unknown[0])}: unknown key", f"Allowed: {', '.join(MOBILE_KEYS)}.")
        if ("app" in entry) == ("source" in entry):
            raise ConfigError(
                f"{_where(where)}: give either app (a built .apk, .aab or .ipa) or source (android or ios)"
            )
        if "app" in entry:
            if "path" in entry:
                raise ConfigError(f"{_where(where + '.path')}: belongs to a source; an app entry is the path itself")
            apps.append(MobileApp(app=_check_relative_path(entry["app"], f"{where}.app")))
            continue
        platform = entry["source"]
        if platform not in MOBILE_PLATFORMS:
            raise ConfigError(f"{_where(where + '.source')}: must be android or ios, not {platform!r}")
        path = _check_relative_path(entry["path"], f"{where}.path") if entry.get("path") is not None else "."
        apps.append(MobileApp(source=platform, path=path))
    return apps


def _parse_remote_image(entry: Dict[Any, Any], where: str) -> Image:
    """`- ref: ghcr.io/org/app:tag` (name optional): scanned from the registry, nothing is built."""
    for key in ("dockerfile", "context"):
        if key in entry:
            raise ConfigError(f"{_where(where + '.' + key)}: an image with `ref` is not built; drop {key} or ref")
    ref = entry["ref"]
    if not isinstance(ref, str) or not ref.strip() or re.search(r"\s", ref.strip()):
        raise ConfigError(f"{_where(where + '.ref')}: must be an image reference such as ghcr.io/org/app:tag")
    ref = ref.strip()
    name = entry.get("name")
    if name is None:
        name = derive_ref_slug(ref)
    elif not isinstance(name, str) or not SLUG_PATTERN.match(name):
        raise ConfigError(f"{_where(where + '.name')}: must be a slug of lowercase letters, digits, '.', '_' and '-'")
    return Image(name=name, remote_ref=ref)


def _check_unique(images: List[Image], name: str, where: str) -> None:
    if any(image.name == name for image in images):
        raise ConfigError(
            f"{_where(where + '.name')}: the name {name!r} is used twice",
            "Give one of the images an explicit name.",
        )


def _parse_gate(value: Any) -> Tuple[Dict[str, Optional[int]], bool]:
    if value is None:
        return {}, True
    if not isinstance(value, dict):
        raise ConfigError(f"{_where('gate')}: must be a mapping such as {{critical: 0, high: null}}")
    gate: Dict[str, Optional[int]] = {}
    ignore_unfixed = True
    for key, limit in value.items():
        if key not in GATE_KEYS:
            raise ConfigError(f"{_where('gate.' + str(key))}: unknown key", f"Allowed: {', '.join(GATE_KEYS)}.")
        if key == "ignore_unfixed":
            if not isinstance(limit, bool):
                raise ConfigError(f"{_where('gate.ignore_unfixed')}: must be true or false")
            ignore_unfixed = limit
            continue
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit < 0):
            raise ConfigError(f"{_where('gate.' + key)}: must be a whole number >= 0, or null for no limit")
        gate[key] = limit
    return gate, ignore_unfixed


def load(root: Path) -> Config:
    path = root / CONFIG_FILE
    if not path.is_file():
        raise ConfigError(f"No {CONFIG_FILE} in {root}.", "Run `tdxguard init` to create one.")
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigError(f"{CONFIG_FILE} is not valid YAML: {e}") from e
    return parse(data, root)


# --- tdxguard init ---


def _git_files(root: Path) -> Optional[List[str]]:
    """The files git knows below root (tracked, and untracked but not ignored); None outside a git repository."""
    try:
        listed = subprocess.run(  # nosec B603 B607
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True,
            check=True,
            timeout=60,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    # A nested repository or worktree is listed as "dir/"; a tracked file deleted from the
    # working tree is still in the index.
    paths = (p for p in listed.decode("utf-8", errors="replace").split("\0") if p and not p.endswith("/"))
    return [p for p in paths if (root / p).is_file()]


def repository_files(root: Path) -> List[str]:
    """
    The repository's files, relative with forward slashes, sorted, outside SKIPPED_DIRECTORIES.

    In a git repository these are the files git knows: what CI checks out, not the ignored
    build output, caches and nested worktrees a developer's copy also holds. One such copy
    had 13 GB of Rust build output and six worktrees, and a plain walk of it never reached
    the mobile app.
    """
    files = _git_files(root)
    if files is None:
        files = []
        for directory, subdirectories, names in os.walk(root):
            subdirectories[:] = [d for d in subdirectories if d not in SKIPPED_DIRECTORIES]
            files += [os.path.relpath(os.path.join(directory, name), root).replace(os.sep, "/") for name in names]
    return sorted(p for p in files if not SKIPPED_DIRECTORIES.intersection(p.split("/")[:-1]))


def find_dockerfiles(root: Path, files: Optional[List[str]] = None) -> List[str]:
    """Dockerfile, *.Dockerfile and Dockerfile.*, outside .git and the vendored directories."""
    found = []
    for relative in repository_files(root) if files is None else files:
        lower = relative.rsplit("/", 1)[-1].lower()
        if lower == "dockerfile" or fnmatch.fnmatch(lower, "*.dockerfile") or fnmatch.fnmatch(lower, "dockerfile.*"):
            found.append(relative)
    return sorted(found, key=lambda p: (p.count("/"), p))


def product_name_from_repository(name: str) -> str:
    """TDxGuard project names are lowercase letters, digits and hyphens."""
    slug = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")
    return slug or "my-project"


def render(
    project: str, repository: Optional[str], dockerfiles: List[str], mobile_platforms: Sequence[str] = ()
) -> str:
    lines = [
        "# TDxGuard configuration for `tdxguard scan`. Reference: tdxguard --help, cli/README.md",
        "",
        "# The TDxGuard product the results go to. Created on the first upload if it does not exist.",
        f"project: {_yaml_scalar(project)}",
    ]
    if repository:
        lines += ["# Used when the project is created in TDxGuard.", f"repository: {_yaml_scalar(repository)}"]
    lines += [
        "",
        "# Paths the scanners leave out, relative to the repository root.",
        "exclude: []",
        "",
    ]
    if dockerfiles:
        lines += ["# Dockerfiles to build locally and scan (OS packages and secrets in the image layers)."]
        lines += ["images:"]
        for dockerfile in dockerfiles:
            lines += [
                f"  - dockerfile: {_yaml_scalar(dockerfile)}",
                f"    context: {_yaml_scalar(os.path.dirname(dockerfile) or '.')}",
                f"    name: {derive_slug(dockerfile)}",
            ]
    else:
        lines += [
            "# Dockerfiles to build locally and scan. None were found.",
            "images: []",
            "#  - dockerfile: Dockerfile",
            "#    context: .",
        ]
    if mobile_platforms:
        lines += [
            "",
            f"# Mobile app ({', '.join(mobile_platforms)}): MobSF analyses it in Docker, without network access.",
            "# The built app gives the most; the source works for the Android Studio and Xcode layouts.",
            "mobile: []",
            "#  - app: app/build/outputs/apk/release/app-release.apk",
            "#  - source: android      # or ios, with path: <project directory>",
        ]
    lines += [
        "",
        "# `tdxguard scan` exits with 1 when a count is exceeded; null means no limit.",
        "# ignore_unfixed: count only vulnerabilities that have a fix, like CI's Trivy gate.",
        "gate:",
        "  critical: 0",
        "  high: null",
        "  ignore_unfixed: true",
        "",
    ]
    return "\n".join(lines)


def _yaml_scalar(value: str) -> str:
    dumped = yaml.safe_dump(value, default_flow_style=True).strip()
    if dumped.endswith("\n..."):
        dumped = dumped[: -len("\n...")]
    if dumped.endswith("..."):
        dumped = dumped[: -len("...")].strip()
    return dumped
