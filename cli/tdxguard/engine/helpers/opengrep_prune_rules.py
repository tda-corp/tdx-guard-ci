#!/usr/bin/env python3
"""
opengrep-prune-rules.py — confine name-only framework rules to the code that uses the framework.

    opengrep-prune-rules.py <rules-directory> <repository-directory> [ignored-directory ...]

Most rules under a framework directory of opengrep-rules are safe anywhere: they name the
framework's module (`django.http.$ANY(...)`), follow taint from its request object, or
match a construct that is risky whatever renders it (`{{ x|safe }}`, `{{ x }}` inside
<script>, raw SQL built by concatenation). They stay as they are.

A few match on a bare method name and nothing else, and those report every unrelated call
of the same name. Measured across the eleven onboarded repositories:

  python/django avoid-query-set-extra    `$MODEL.extra(...)`: every `op.extra(...)` of
                                         tdx-agent's audit helper, a FastAPI service.
                                         Correct in tda-plane, which is Django.
  javascript/jquery (all three rules)    `$X.html(...)`, `$(...).$METHOD(...)`: Lit's
                                         html`` templates, Hono's c.html(), DOM append().
                                         None of the eleven repositories uses jQuery.
  python/flask directly-returned-format-string
                                         any helper that returns an f-string.
  php/symfony symfony-non-literal-redirect
                                         `$this->redirect(...)`: 157 controller redirects
                                         in HumHub, a Yii application that is not Symfony.

One more is confined the same way although it matches markup rather than a name:

  python/django django-no-csrf-token     every POST <form> without `{% csrf_token %}`,
                                         in any template language: Thymeleaf in Spring
                                         PetClinic (3) and WebGoat (107), where Spring
                                         Security adds the token and Django is absent.

For those rules this script finds the directories whose dependency manifest declares the
framework and restricts the rule to them with `paths.include`. A repository holds a
frontend, a backend and infrastructure side by side, so the scope is the declaring
subproject, not the repository: Django in apps/api/requirements/base.txt confines the
Django rule to apps/api/. Where no directory declares the framework the rule is removed.

Manifests are those a project declares directly (pyproject.toml, requirements*.txt and
requirements/*.txt, setup.py, setup.cfg, Pipfile, package.json, go.mod, composer.json).
Lockfiles are not read: they list transitive dependencies. Symfony counts as declared
through symfony/framework-bundle, the package that provides `$this->redirect()`; Laravel
and Yii applications pull in other symfony/* components without being Symfony. jQuery is
also detected where it is loaded the old way, as a jquery*.js file or a <script> that
names it, and is then scoped to the nearest directory above that file with a manifest.

WordPress plugin rules need nothing here: each carries `paths.include:
wp-content/plugins/**` itself.

Directories given after the repository are not searched: the full rule tree is unpacked
inside the checkout and carries a Pipfile of its own.

Standard library only: a self-hosted runner has python3, not necessarily PyYAML.
"""

# Self-hosted runners ship older Pythons (3.8 at least): without this, the `list[Path]`
# annotations are evaluated when the functions are defined and fail with
# "TypeError: 'type' object is not subscriptable" before the script does anything.
from __future__ import annotations

import re
import sys
from pathlib import Path

# Rules that match a bare method name, per framework: rule files relative to the rules
# directory, or a directory whose every rule file qualifies.
NAME_ONLY_RULES = {
    "django": [
        "python/django/security/audit/query-set-extra.yaml",
        "python/django/security/django-no-csrf-token.yaml",
    ],
    "flask": ["python/flask/security/audit/directly-returned-format-string.yaml"],
    "jquery": ["javascript/jquery/security"],
    "symfony": ["php/symfony/security/audit/symfony-non-literal-redirect.yaml"],
}
PACKAGES = {
    "django": ["django"],
    "flask": ["flask"],
    "jquery": ["jquery"],
    "symfony": ["symfony/framework-bundle"],
}

MANIFEST_PATTERNS = [
    "pyproject.toml",
    "requirements*.txt",
    "requirements/*.txt",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "package.json",
    "go.mod",
    "composer.json",
]
SKIP_DIRECTORIES = {"node_modules", ".venv", "venv", "vendor", ".git", "dist", "build"}
RULE_ID = re.compile(r"^(\s*)- id:", re.MULTILINE)


def is_skipped(path: Path, repository: Path, ignored: list[Path]) -> bool:
    if set(path.relative_to(repository).parts) & SKIP_DIRECTORIES:
        return True
    return any(directory == path or directory in path.parents for directory in ignored)


def find_manifests(repository: Path, ignored: list[Path]) -> list[Path]:
    manifests = set()
    for pattern in MANIFEST_PATTERNS:
        for path in repository.rglob(pattern):
            if path.is_file() and not is_skipped(path, repository, ignored):
                manifests.add(path)
    return sorted(manifests)


def project_directory(manifest: Path) -> Path:
    # requirements/base.txt belongs to the project one level up, not to requirements/
    return manifest.parent.parent if manifest.parent.name == "requirements" else manifest.parent


def is_declared(package: str, text: str) -> bool:
    # Bounded by anything that cannot be part of a package name: "django" does not match
    # "django-stubs", and "jquery" does not match "jquery-ui-dist".
    pattern = r"(?<![a-z0-9_.@/-])" + re.escape(package) + r"(?![a-z0-9_-])"
    return re.search(pattern, text) is not None


def jquery_loaded_directly(repository: Path, ignored: list[Path]) -> list[Path]:
    """Files that load jQuery without a package manager: a jquery*.js, or a <script> naming it."""
    files = [path for path in repository.rglob("*jquery*.js") if not is_skipped(path, repository, ignored)]
    script = re.compile(r"<script[^>]+jquery", re.IGNORECASE)
    for suffix in ("*.html", "*.htm"):
        for path in repository.rglob(suffix):
            if not is_skipped(path, repository, ignored) and script.search(path.read_text(errors="replace")):
                files.append(path)
    return files


def owning_project(path: Path, repository: Path, projects: list[Path]) -> str:
    """The nearest directory above `path` that has a manifest, relative to the repository."""
    for parent in path.parents:
        if parent in projects:
            directory = parent.relative_to(repository).as_posix()
            return "" if directory == "." else directory
        if parent == repository:
            break
    return ""


def scopes(repository: Path, ignored: list[Path]) -> dict[str, list[str]]:
    """Directories, relative to the repository, whose manifest declares each framework."""
    found: dict[str, set[str]] = {framework: set() for framework in NAME_ONLY_RULES}
    manifests = find_manifests(repository, ignored)
    for manifest in manifests:
        text = manifest.read_text(errors="replace").lower()
        directory = project_directory(manifest).relative_to(repository).as_posix()
        for framework, packages in PACKAGES.items():
            if any(is_declared(package, text) for package in packages):
                found[framework].add("" if directory == "." else directory)
    # jQuery from a CDN or a vendored file belongs to the subproject holding that file:
    # Plane's Django templates load it, its React frontend does not.
    projects = [project_directory(manifest) for manifest in manifests]
    for path in jquery_loaded_directly(repository, ignored):
        found["jquery"].add(owning_project(path, repository, projects))
    # A declaration at the root covers everything below it
    return {framework: [""] if "" in directories else sorted(directories) for framework, directories in found.items()}


def rule_files(rules: Path, framework: str) -> list[Path]:
    files: list[Path] = []
    for entry in NAME_ONLY_RULES[framework]:
        path = rules / entry
        if path.is_dir():
            files += sorted(path.rglob("*.yaml"))
        elif path.is_file():
            files.append(path)
    return files


def confine(text: str, directories: list[str]) -> str:
    # Insert `paths.include` under every `- id:` of the file, at the rule's own indent.
    out = []
    for line in text.splitlines():
        out.append(line)
        match = RULE_ID.match(line)
        if match:
            indent = match.group(1) + "  "
            out.append(f"{indent}paths:")
            out.append(f"{indent}  include:")
            out += [f'{indent}  - "{directory}/**"' for directory in directories]
    return "\n".join(out) + "\n"


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2

    rules = Path(sys.argv[1]).resolve()
    repository = Path(sys.argv[2]).resolve()
    ignored = [rules] + [Path(directory).resolve() for directory in sys.argv[3:]]

    for framework, directories in scopes(repository, ignored).items():
        files = rule_files(rules, framework)
        if not files:
            continue
        if directories == [""]:
            outcome = "whole repository"
        elif directories:
            for rule_file in files:
                rule_file.write_text(confine(rule_file.read_text(), directories))
            outcome = "only " + ", ".join(f"{directory}/" for directory in directories)
        else:
            for rule_file in files:
                rule_file.unlink()
            outcome = "removed, not used"
        print(f"opengrep-prune-rules: {framework} name-only rules ({len(files)}): {outcome}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
