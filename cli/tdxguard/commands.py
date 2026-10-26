"""The commands: login, logout, whoami, init, doctor, scan, report, tools."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket as socket_module
import sys
import urllib.parse
import webbrowser
from collections import deque
from datetime import date
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Mapping, Optional, Tuple

from tdxguard import (
    DEFAULT_OIDC_AUTHORITY,
    DEFAULT_OIDC_CLIENT_ID,
    DEFAULT_OIDC_SCOPE,
    DEFAULT_SCANNER_IMAGE,
    DEFAULT_SERVER,
    __version__,
    assessment,
    config,
    coverage,
    credentials,
    docker,
    gitinfo,
    oidc,
    reports,
    server,
)
from tdxguard.assessment import browser as report_browser
from tdxguard.engine import scan, tools
from tdxguard.engine.helpers import mobsf_scan
from tdxguard.errors import (
    EXIT_ERROR,
    EXIT_GATE,
    EXIT_OK,
    ApiError,
    AuthenticationError,
    CLIError,
    ConfigError,
    DockerError,
    LoginError,
    NetworkError,
)
from tdxguard.ui import UI

MOBSF_IMAGE = mobsf_scan.MOBSF_IMAGE

# --- login / logout / whoami ---


def cmd_login(args: argparse.Namespace, ui: UI) -> int:
    existing = credentials.load_file()
    target = credentials.normalize_server(
        args.server or os.environ.get(credentials.ENV_SERVER) or (existing.server if existing else DEFAULT_SERVER)
    )

    runtime = server.fetch_runtime_config(target)
    if runtime.get("OIDC_ENABLE", "true").lower() == "false":
        raise LoginError(
            f"{target} does not use single sign-on.",
            "Create an API token in TDxGuard and set TDXGUARD_TOKEN and TDXGUARD_SERVER instead.",
        )
    authority = (
        args.oidc_authority
        or os.environ.get("TDXGUARD_OIDC_AUTHORITY")
        or runtime.get("OIDC_AUTHORITY")
        or DEFAULT_OIDC_AUTHORITY
    )
    client_id = (
        args.client_id
        or os.environ.get("TDXGUARD_OIDC_CLIENT_ID")
        or runtime.get("OIDC_CLIENT_ID")
        or DEFAULT_OIDC_CLIENT_ID
    )
    scope = runtime.get("OIDC_SCOPE") or DEFAULT_OIDC_SCOPE
    api_url = runtime.get("API_BASE_URL") or credentials.api_url_for(target)
    ui.debug(f"identity provider {authority}, client {client_id}, API {api_url}")

    endpoints = oidc.discover(authority)
    authorization = oidc.start(endpoints, client_id, scope)

    ui.step(f"Log in to {target}")
    ui.info("Open this page and confirm the code:")
    ui.out("")
    ui.out("    " + ui.style(authorization.verification_uri_complete, "bold", "cyan"))
    ui.out("    code: " + ui.style(authorization.user_code, "bold"))
    ui.out("")
    if not args.no_browser and _open_browser(authorization.verification_uri_complete):
        ui.info("A browser window should have opened. Waiting for the confirmation ...")
    else:
        ui.info("Waiting for the confirmation ...")

    tokens = oidc.poll(endpoints, client_id, authorization)
    id_token = tokens.get("id_token")
    if not id_token:
        raise LoginError(
            "The identity provider returned no ID token.", f"Is the scope {scope!r} allowed for the client?"
        )

    label = _device_label()
    try:
        created = server.Client(api_url, bearer=id_token).create_cli_token(label)
    except AuthenticationError as e:
        raise LoginError(
            f"TDxGuard did not accept the login: {e.message}",
            "The identity provider settings of the server and the tool may not match (--client-id).",
        ) from e

    client = server.Client(api_url, token=created["token"])
    username = str(client.me().get("username", ""))

    new = credentials.Credentials(
        server=target,
        token=created["token"],
        name=created.get("name", ""),
        username=username,
        expires=str(created.get("expiration_date", "")),
        api_url=api_url if api_url.rstrip("/") != credentials.api_url_for(target) else "",
    )
    path = credentials.save(new)

    # A new login replaces the old token: revoke it instead of leaving it valid for months.
    if existing and existing.token != new.token and existing.server == new.server:
        try:
            server.Client(existing.api, token=existing.token).revoke_cli_token()
            ui.debug(f"revoked the previous token {existing.name}")
        except CLIError:
            pass

    ui.success(f"Logged in to {target} as {ui.style(username, 'bold')}.")
    ui.info(f"Token {new.name} is valid until {new.expires}, stored in {path}.")
    return EXIT_OK


def _device_label() -> str:
    return socket_module.gethostname().split(".")[0] or "device"


def _open_browser(url: str) -> bool:
    if sys.platform.startswith("linux") and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return False
    try:
        return webbrowser.open(url, new=2)
    except webbrowser.Error:
        return False


def cmd_logout(args: argparse.Namespace, ui: UI) -> int:
    stored = credentials.load_file()
    if os.environ.get(credentials.ENV_TOKEN):
        ui.warn("TDXGUARD_TOKEN is set in the environment; that token was not touched.")
    if not stored:
        ui.info("Not logged in, nothing to do.")
        return EXIT_OK
    try:
        server.Client(stored.api, token=stored.token).revoke_cli_token()
        ui.success(f"Revoked the token {stored.name} on {stored.server}.")
    except CLIError as e:
        ui.warn(f"Could not revoke the token on the server ({e.message}); it expires on {stored.expires or '?'}.")
    credentials.delete()
    ui.success("Logged out.")
    return EXIT_OK


def cmd_whoami(args: argparse.Namespace, ui: UI) -> int:
    creds = credentials.require()
    user = server.Client(creds.api, token=creds.token).me()
    info = {
        "server": creds.server,
        "username": user.get("username", ""),
        "full_name": user.get("full_name", ""),
        "token": creds.name or "(from TDXGUARD_TOKEN)",
        "expires": creds.expires or "unknown",
        "source": creds.source if creds.source == "environment" else str(credentials.credentials_path()),
    }
    if args.json:
        print(json.dumps(info, indent=2))
        return EXIT_OK
    ui.out(f"Server:   {info['server']}")
    ui.out(f"User:     {info['username']}" + (f" ({info['full_name']})" if info["full_name"] else ""))
    ui.out(f"Token:    {info['token']}, expires {info['expires']}{_expiry_note(creds.expires)}")
    ui.out(f"Source:   {info['source']}")
    return EXIT_OK


def _expiry_note(expires: str) -> str:
    try:
        days = (date.fromisoformat(expires) - date.today()).days
    except ValueError:
        return ""
    if days < 0:
        return " (expired, run `tdxguard login`)"
    if days <= 14:
        return f" (in {days} days, run `tdxguard login` to renew)"
    return ""


# --- init ---


def cmd_init(args: argparse.Namespace, ui: UI) -> int:
    root = gitinfo.find_root() or Path.cwd()
    path = root / config.CONFIG_FILE

    remote = gitinfo.remote_url(root)
    repository, repository_name = gitinfo.parse_remote(remote) if remote else ("", "")
    project = args.project or config.product_name_from_repository(repository_name or root.name)
    dockerfiles = config.find_dockerfiles(root)
    mobile_platforms = coverage.inspect(root).mobile_platforms

    # Validate the flags before anything is written.
    options = _ci_options_from_flags(args)

    if path.exists() and not args.force:
        ui.info(f"{path} exists, kept as it is (--force overwrites it).")
    else:
        path.write_text(config.render(project, repository or None, dockerfiles, mobile_platforms), encoding="utf-8")
        ui.success(f"Wrote {path}")
        ui.info(f"project: {project}" + ("" if args.project else "  (from the repository name; edit if it differs)"))
        if repository:
            ui.info(f"repository: {repository}")
        if dockerfiles:
            ui.info("images: " + ", ".join(f"{d} -> {config.derive_slug(d)}" for d in dockerfiles))
        else:
            ui.info("images: none found")

    if not args.no_ci:
        _init_ci(args, ui, root, project, repository, remote or "", options)

    creds = credentials.load()
    if creds:
        try:
            product = server.Client(creds.api, token=creds.token).find_product(project)
            if product:
                ui.info(f"The project exists in TDxGuard: {_product_url(creds.server, product)}")
            else:
                ui.info("The project does not exist in TDxGuard yet; the first `tdxguard scan` creates it.")
        except CLIError as e:
            ui.debug(f"could not look up the project: {e.message}")
    ui.out("")
    ui.info("Next: review the file, then run `tdxguard scan`.")
    return EXIT_OK


def _ci_options_from_flags(args: argparse.Namespace) -> coverage.CIOptions:
    return coverage.CIOptions(
        dockerfiles=[coverage.check_dockerfile(d) for d in (args.dockerfile or [])],
        image_ref=coverage.check_image_ref(args.image_ref or ""),
        app_start_command=coverage.check_command(args.start_command or "", "--start-command"),
        app_health_url=coverage.check_url(args.health_url or "", "--health-url"),
        dast_target=coverage.check_url(args.dast_target or "", "--dast-target"),
        mobile_apps=[coverage.check_mobile_app(a) for a in (getattr(args, "mobile_app", None) or [])],
        mobile_sources=[coverage.check_mobile_source(s) for s in (getattr(args, "mobile_source", None) or [])],
    )


def detect_platform(remote: str, workflow: Optional[coverage.Workflow]) -> str:
    if workflow is not None:
        return workflow.platform
    if not remote:
        return coverage.GITHUB
    return coverage.GITHUB if "github.com" in remote.lower() else coverage.GITLAB


def _interactive(args: argparse.Namespace) -> bool:
    if args.yes:
        return False
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _ask(ui: UI, question: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        answer = input(f"  {question}{suffix}: ").strip()
    except EOFError:
        answer = ""
    return answer or default


def _ask_yes(ui: UI, question: str) -> bool:
    return _ask(ui, question + " (Y/n)").lower() not in ("n", "no")


def _ask_until_valid(ui: UI, question: str, check: Callable[[str], str]) -> str:
    while True:
        answer = _ask(ui, question)
        try:
            return check(answer)
        except ConfigError as e:
            ui.warn(e.message)


def _complete_options_interactively(
    ui: UI, platform: str, facts: coverage.RepoFacts, options: coverage.CIOptions
) -> None:
    ui.step("What else should TDxGuard scan? (Enter skips a question)")
    if not options.dockerfiles and facts.dockerfiles:
        if platform == coverage.GITHUB:
            if _ask_yes(ui, f"Build and scan the images of {', '.join(facts.dockerfiles)} in CI?"):
                options.dockerfiles = list(facts.dockerfiles)
        else:
            options.dockerfiles = list(facts.dockerfiles)
            ui.info("GitLab scans an image your build job has already pushed; it does not build Dockerfiles.")
    if not options.image_ref and platform == coverage.GITLAB and facts.dockerfiles:
        options.image_ref = _ask_until_valid(
            ui, f"Image your build job pushes, e.g. {coverage.GITLAB_IMAGE_REF_HINT}", coverage.check_image_ref
        )
    if not options.app_start_command:
        ui.info("IAST (Aikido Zen) needs the app started in CI, with Zen embedded in it.")
        for command, source in facts.start_hints:
            ui.info(f"  found: {command}   ({source})")
        options.app_start_command = _ask_until_valid(
            ui, "Command that starts the app in CI", lambda v: coverage.check_command(v, "The start command")
        )
        if options.app_start_command and not options.app_health_url:
            options.app_health_url = _ask_until_valid(
                ui, f"URL that answers once it is up (default {coverage.DEFAULT_APP_HEALTH_URL})",
                lambda v: coverage.check_url(v, "The health URL"),
            )  # fmt: skip
    if not options.dast_target:
        ui.info("DAST: only scan an environment you own, and never production without approval.")
        question = (
            "URL for ZAP: the started app (e.g. http://127.0.0.1:8000) or a test environment"
            if platform == coverage.GITHUB
            else "URL of a deployed test or staging environment for ZAP"
        )
        options.dast_target = _ask_until_valid(ui, question, lambda v: coverage.check_url(v, "The URL"))
    if facts.mobile_platforms and platform == coverage.GITHUB and not (options.mobile_apps or options.mobile_sources):
        ui.info(f"Mobile app ({', '.join(facts.mobile_platforms)}): MobSF analyses the built app best.")
        app = _ask_until_valid(
            ui,
            "Path of the built .apk/.aab/.ipa in CI (a glob is fine)",
            lambda v: coverage.check_mobile_app(v) if v else "",
        )
        if app:
            options.mobile_apps = [app]
        else:
            for line in coverage.mobile_suggestions(facts)[:2]:
                if _ask_yes(ui, f"Analyse the source instead, mobile_source: {line}?"):
                    options.mobile_sources.append(line)


def _init_ci(
    args: argparse.Namespace,
    ui: UI,
    root: Path,
    project: str,
    repository: str,
    remote: str,
    options: coverage.CIOptions,
) -> None:
    existing = coverage.find_workflow(root)
    platform = args.ci or detect_platform(remote, existing)
    if existing is not None and existing.platform != platform:
        existing = None
    facts = coverage.inspect(root)

    if _interactive(args):
        _complete_options_interactively(ui, platform, facts, options)
    else:
        # Detected Dockerfiles become image inputs on GitHub, which builds them; GitLab
        # cannot, the snippet only names them.
        if not options.dockerfiles and facts.dockerfiles:
            options.dockerfiles = list(facts.dockerfiles)
        for command, source in facts.start_hints if not options.app_start_command else []:
            ui.info(f"Possible start command for IAST: {command}   ({source}); pass it with --start-command.")

    content = coverage.render_workflow(platform, project, repository, options)
    target = root / coverage.workflow_path(platform)
    suggested = coverage.suggested_inputs(platform, options)
    ui.out("")

    if existing is not None:
        ui.step(f"{existing.path} already runs TDxGuard ({platform})")
        changes = coverage.input_changes(existing.inputs, suggested)
        for line in changes:
            ui.info(line)
        if not changes:
            ui.info("No optional inputs to suggest; `tdxguard doctor` shows what is covered.")
        if platform == coverage.GITHUB and args.force and existing.path == coverage.GITHUB_WORKFLOW:
            target.write_text(content, encoding="utf-8")
            ui.success(f"Overwrote {target} (--force)")
        elif any(line.startswith(("+", "~")) for line in changes):
            where = "the `with:` block" if platform == coverage.GITHUB else "the `variables:` block"
            ui.info(f"Add the + lines to {where} of {existing.path}" + (
                ", or run again with --force to overwrite it." if platform == coverage.GITHUB else "."))  # fmt: skip
        return

    if platform == coverage.GITLAB and target.exists():
        # .gitlab-ci.yml is the project's whole pipeline: never overwritten, not even with --force.
        ui.step(f"Add this to {target.name} (it is not overwritten):")
        ui.out(content)
        return
    if target.exists() and not args.force:
        ui.step(f"{target} exists and does not call the TDxGuard template; it is kept (--force overwrites it).")
        ui.out(content)
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    ui.success(f"Wrote {target}")
    kinds = coverage.configured_kinds(coverage.Workflow(platform, str(target), _plain_inputs(suggested)))
    # The mobile app analysis counts only for a repository with a mobile app in it.
    applicable = [(k, label) for k, label in coverage.KINDS if k != "mobile" or facts.mobile_platforms or kinds.get(k)]
    covered = [label for kind, label in applicable if kinds.get(kind)]
    ui.info(f"CI covers {len(covered)} of {len(applicable)} kinds of scan: {', '.join(covered)}")
    ui.info("`tdxguard doctor` shows what is missing and what TDxGuard has received.")


def _plain_inputs(suggested: Dict[str, str]) -> Dict[str, Any]:
    return {key: (value if value.startswith("|") else json.loads(value)) for key, value in suggested.items()}


# --- doctor ---


def cmd_doctor(args: argparse.Namespace, ui: UI) -> int:
    root = gitinfo.find_root() or Path.cwd()
    remote = gitinfo.remote_url(root) or ""
    repository, repository_name = gitinfo.parse_remote(remote) if remote else ("", "")
    workflow = coverage.find_workflow(root)
    platform = args.ci or detect_platform(remote, workflow)
    if workflow is not None and workflow.platform != platform:
        workflow = None
    facts = coverage.inspect(root)
    project = (
        args.project
        or _doctor_project(root, workflow)
        or config.product_name_from_repository(repository_name or root.name)
    )

    scan_coverage, state = _fetch_scan_coverage(ui, project, args.offline)
    rows = coverage.diagnose(facts, workflow, platform, scan_coverage, state)
    ok = coverage.exit_ok(rows)

    if args.json:
        print(json.dumps({
            "project": project, "platform": platform, "workflow": workflow.path if workflow else None,
            "server": state, "ok": ok,
            "kinds": [{"kind": r.kind, "expected": r.expected, "why": r.why, "configured": r.configured,
                       "received": r.received, "action": r.action, "detail": r.detail} for r in rows],
        }, indent=2))  # fmt: skip
        return EXIT_OK if ok or args.no_fail else EXIT_GATE

    ui.step(f"Scan coverage of {project}")
    ui.info(f"Workflow: {workflow.path} ({platform})" if workflow else f"Workflow: none found ({platform})")
    ui.info(f"TDxGuard: {_server_state_text(state)}")
    if facts.truncated:
        ui.warn(
            f"Only the first {coverage.MAX_FILES} of {facts.truncated} files were inspected: what is in the rest "
            "is missing below."
        )
    ui.out("")
    ui.table(
        ["Kind", "Expected", "Why", "In CI", "Received", "What to do"],
        [[r.label, r.expected, r.why[:40], "yes" if r.configured else "no", r.received, r.action or "-"] for r in rows],
    )
    # The no-workflow sentence is said once, not on every row.
    details = [(r.label, [x for x in r.detail.splitlines() if x != coverage.NO_WORKFLOW]) for r in rows]
    details = [(label, lines) for label, lines in details if lines]
    if workflow is None:
        ui.out("")
        ui.info("No TDxGuard workflow found: nothing is scanned in CI. `tdxguard init` writes one.")
    if details:
        ui.out("")
        for label, lines in details:
            if len(lines) == 1:
                ui.info(f"{label}: {lines[0]}")
                continue
            ui.info(f"{label}:")
            for line in lines:
                ui.info("    " + line)
    ui.out("")
    if ok:
        ui.success("Everything expected is configured in CI.")
        return EXIT_OK
    missing = [r.label for r in rows if r.expected == coverage.YES and not r.configured]
    ui.warn(f"Expected but not configured in CI: {', '.join(missing)}.")
    return EXIT_OK if args.no_fail else EXIT_GATE


def _doctor_project(root: Path, workflow: Optional[coverage.Workflow]) -> str:
    try:
        return config.load(root).project
    except ConfigError:
        pass
    if workflow is not None:
        value = workflow.inputs.get("product") or workflow.inputs.get("PRODUCT")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _fetch_scan_coverage(ui: UI, project: str, offline: bool) -> Tuple[Optional[Dict[str, Any]], str]:
    creds = None if offline else credentials.load()
    if creds is None:
        return None, "offline"
    try:
        client = server.Client(creds.api, token=creds.token)
        product = client.find_product(project)
        # The list may leave out what the product's own page reports.
        if product is not None and "scan_coverage" not in product and product.get("id") is not None:
            product = client.product(product["id"])
    except CLIError as e:
        ui.warn(f"Could not ask TDxGuard: {e.message}")
        return None, "offline"
    if product is None:
        return None, "unknown-product"
    value = product.get("scan_coverage")
    if not isinstance(value, dict):
        return None, "old"
    return value, "ok"


def _server_state_text(state: str) -> str:
    return {
        "ok": "asked for what it received on the default branch",
        "old": "this server does not report scan coverage yet",
        "unknown-product": "no product with this name (--project to choose another)",
        "offline": "not asked (not logged in, or --offline)",
    }[state]


# --- scan ---

ENV_ENGINE = "TDXGUARD_ENGINE"


def branch_name(username: str, git_branch: str) -> str:
    """local/<username>/<git branch>: a developer's working tree never mixes with CI's branches."""
    user = re.sub(r"\s+", "-", (username or "unknown").strip()) or "unknown"
    branch = re.sub(r"\s+", "-", (git_branch or "unknown").strip()) or "unknown"
    return f"local/{user}/{branch}"


def imports_licenses(branch: str, sbom: bool) -> bool:
    """
    Whether the upload imports the components and licenses of the SBOM, not only its
    vulnerabilities. Not for a local/ branch unless --sbom: a local scan is a throwaway copy
    of the project that the branch housekeeping deletes after a few days, and the copies of
    every component on such branches are what made the database grow. A --branch outside
    local/ gets them.
    """
    return sbom or not branch.startswith("local/")


def resolve_skips(args: argparse.Namespace) -> List[str]:
    skips = list(dict.fromkeys(args.skip or []))
    if args.image_only:
        skips = ["betterleaks", "opengrep", "trivy", "zizmor", "mobile"]
    if args.no_images and "image" not in skips:
        skips.append("image")
    return skips


def resolve_engine(
    requested: Optional[str],
    environ: Mapping[str, str],
    configured: Optional[str],
    docker_available: Callable[[], bool],
) -> str:
    """
    --engine, else $TDXGUARD_ENGINE, else `engine:` in .tdxguard.yml, else auto. `auto` is
    docker when a Docker daemon answers and the scanner image can be used, native otherwise.
    """
    choice, source = "auto", "default"
    for value, where in (
        (requested, "--engine"),
        (environ.get(ENV_ENGINE), ENV_ENGINE),
        (configured, config.CONFIG_FILE),
    ):
        if value:
            choice, source = value.strip().lower(), where
            break
    if choice not in config.ENGINES:
        raise ConfigError(f"{source}: unknown engine {choice!r}.", f"Use one of {', '.join(config.ENGINES)}.")
    if choice != "auto":
        return choice
    return "docker" if docker_available() else "native"


def cache_dir() -> Path:
    return tools.cache_dir()


def _prepare_out_dir(keep: Optional[str], project: str) -> Path:
    if keep:
        out = Path(keep).expanduser().resolve()
        out.mkdir(parents=True, exist_ok=True)
        # The reports of an earlier run, of a scanner skipped now or an image or app no longer
        # scanned, would go up again with this run's; the directory's other files stay.
        for path in reports.report_files(out):
            path.unlink()
        return out
    out = cache_dir() / "reports" / re.sub(r"[^A-Za-z0-9._-]", "-", project)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    return out


class _DockerProbe:
    """Asks the Docker daemon once, and only when an answer is needed."""

    def __init__(self) -> None:
        self.answer: Optional[bool] = None

    def __call__(self) -> bool:
        if self.answer is None:
            self.answer = docker.is_available()
        return self.answer


def cmd_scan(args: argparse.Namespace, ui: UI) -> int:  # noqa: C901
    root = gitinfo.find_root()
    if root is None:
        raise ConfigError("This is not a git repository.", "Run tdxguard inside the repository you want to scan.")
    cfg = config.load(root)
    skips = resolve_skips(args)
    if args.image_only and not cfg.images:
        raise ConfigError(f"--image-only, but {config.CONFIG_FILE} lists no images.")
    if args.log_opts and args.secrets_mode != "git":
        raise ConfigError("--log-opts applies to --secrets-mode git only.")
    docker_available = _DockerProbe()
    scanner_image = os.environ.get("TDXGUARD_SCANNER_IMAGE") or DEFAULT_SCANNER_IMAGE

    def docker_engine_usable() -> bool:
        if not docker_available():
            return False
        if docker.image_usable(scanner_image):
            return True
        ui.info(f"The scanner image {scanner_image} cannot be pulled here; using the native engine instead.")
        return False

    engine = resolve_engine(getattr(args, "engine", None), os.environ, cfg.engine, docker_engine_usable)
    ui.debug(f"engine: {engine}")
    if engine == "docker" and args.secrets_mode == "git" and (root / ".git").is_file():
        # In a worktree .git is a file pointing to a path on this machine, which does not
        # exist inside the scanner container.
        raise ConfigError(
            "--secrets-mode git does not work in a git worktree with the Docker engine: the history lives "
            "outside the mounted directory.",
            "Run the scan from the main checkout, use --secrets-mode dir, or --engine native.",
        )

    # Check the login before a scan of several minutes, not after it.
    client: Optional[server.Client] = None
    creds: Optional[credentials.Credentials] = None
    username = ""
    if not args.no_upload:
        creds = credentials.require()
        client = server.Client(creds.api, token=creds.token)
        username = str(client.me().get("username", "")) or creds.username

    toolset: Optional[tools.Toolset] = None
    if engine == "docker":
        docker.ensure_available()
    else:
        toolset = _native_tools(ui)

    out = _prepare_out_dir(args.keep, cfg.project)
    excludes = list(cfg.exclude)
    try:
        relative_out = out.relative_to(root)
        excludes.append(relative_out.as_posix())  # do not scan the reports of the last run
    except ValueError:
        pass

    # 1. Build the images; registry images (`ref:`) are not built.
    images: List[Tuple[str, str]] = []
    remote_images: List[Tuple[str, str]] = []
    image_refs: Dict[str, str] = {}
    if cfg.images and "image" not in skips:
        buildable = [image for image in cfg.images if not image.remote]
        if buildable and engine == "native" and not docker_available():
            ui.warn(
                f"Docker is not available, so {len(buildable)} image(s) built from a Dockerfile are not scanned: "
                + ", ".join(f"{image.dockerfile} ({image.name})" for image in buildable)
                + ". Registry images (`ref:` in .tdxguard.yml) are scanned without Docker."
            )
            buildable = []
        if buildable:
            ui.step(f"Building {len(buildable)} image(s)")
        for image in buildable:
            ui.info(f"{image.dockerfile} -> {image.ref}")
            code, tail = docker.run(
                docker.build_command(str(image.dockerfile), str(image.context), image.ref),
                verbose=args.verbose,
                cwd=root,
            )
            if code != 0:
                _show_tail(ui, tail)
                raise DockerError(
                    f"docker build failed for {image.dockerfile} (exit {code}).",
                    "Fix the build, or skip the images with --no-images.",
                )
            images.append((image.ref, image.name))
            image_refs[image.name] = image.ref
        for image in cfg.images:
            if image.remote:
                remote_images.append((image.ref, image.name))
                image_refs[image.name] = image.ref

    # 2. Run the scanners.
    ui.step(
        f"Scanning with the {engine} engine"
        + (" (this can take a few minutes; -v shows the progress)" if not args.verbose else "")
    )
    trivy_cache = cache_dir() / "scanner"  # one Trivy DB for both engines
    trivy_cache.mkdir(parents=True, exist_ok=True)
    if engine == "docker":
        uid, gid = (os.getuid(), os.getgid()) if hasattr(os, "getuid") else (None, None)
        command = docker.scanner_command(
            image=scanner_image,
            src=str(root),
            out=str(out),
            cache=str(trivy_cache),
            uid=uid,
            gid=gid,
            socket=docker.detect_socket() if images else None,
            excludes=excludes,
            images=images,
            remote_images=remote_images,
            skips=[s for s in skips if s != "mobile"],
            secrets_mode=args.secrets_mode,
            log_opts=args.log_opts,
        )
        ui.debug(" ".join(command))
        code, tail = docker.run(command, verbose=args.verbose)
        missing_hint = f"Run with -v to see its output. Is {scanner_image} available (docker pull {scanner_image})?"
    else:
        assert toolset is not None  # nosec B101
        engine_skips = [s for s in skips if s != "mobile"]
        code, tail = _run_native(args, toolset, root, out, excludes, images, remote_images, engine_skips, trivy_cache)
        missing_hint = "Run with -v to see the scanners' output."

    summary = reports.load_summary(out)
    if summary is None:
        _show_tail(ui, tail)
        raise DockerError(f"The scanner ended (exit {code}) without a summary in {out}.", missing_hint)
    # Exit 0: the scans ran (findings are no error). 1: a scanner failed, the summary is
    # still written. 2: bad usage or an unusable /src or /out.
    scanner_errors = [_describe(e) for e in summary.get("errors") or []]
    if code != 0 and not scanner_errors:
        scanner_errors.append(f"the scanner exited with {code}")

    # 2b. The mobile app, with MobSF in Docker whatever the engine.
    if cfg.mobile and "mobile" not in skips:
        scanner_errors += _scan_mobile(ui, cfg, root, out, summary, docker_available)

    # 3. Summary.
    counts = reports.count(out, ignore_unfixed=cfg.ignore_unfixed)
    _print_summary(ui, summary, out, scanner_errors, engine)

    # 4. Upload.
    upload_result: Dict[str, Any] = {}
    upload_failed = False
    if not args.no_upload and client and creds:
        branch = args.branch or branch_name(username, gitinfo.current_branch(root))
        upload_result, upload_failed = _upload(
            ui, client, creds, cfg, root, out, image_refs, branch, imports_licenses(branch, args.sbom)
        )

    # 5. Gate.
    gate = reports.evaluate_gate(cfg.gate, counts)
    if cfg.gate:
        fixable = " (vulnerabilities without a fix not counted)" if cfg.ignore_unfixed else ""
        if gate.passed:
            ui.success(f"Local gate passed: {counts.critical} critical, {counts.high} high{fixable}.")
        else:
            for violation in gate.violations:
                ui.out(ui.style("  local gate failed: ", "red", "bold") + violation)

    if scanner_errors or upload_failed:
        exit_code = EXIT_ERROR
    elif not gate.passed:
        exit_code = EXIT_GATE
    else:
        exit_code = EXIT_OK

    if args.json:
        document = {
            "project": cfg.project,
            "engine": engine,
            "reports": str(out),
            "summary": summary,
            "counts": {"critical": counts.critical, "high": counts.high},
            "gate": {
                "passed": gate.passed,
                "limits": gate.limits,
                "ignore_unfixed": cfg.ignore_unfixed,
                "violations": gate.violations,
            },
            "upload": upload_result or None,
            "exit_code": exit_code,
        }
        print(json.dumps(document, indent=2))
    return exit_code


def _scan_mobile(
    ui: UI, cfg: config.Config, root: Path, out: Path, summary: Dict[str, Any], docker_available: Callable[[], bool]
) -> List[str]:
    """MobSF on the apps of `mobile:` in .tdxguard.yml; its rows join the scanners' summary."""
    if not docker_available():
        message = (
            f"MobSF runs in Docker, which is not available here: the mobile app (mobile: in {config.CONFIG_FILE}) "
            "is not analysed. Start Docker, or skip it with --skip mobile."
        )
        ui.warn(message)
        summary.setdefault("warnings", []).append(message)
        return []
    ui.step("Analysing the mobile app with MobSF (in Docker, without network access)")
    apps = [entry.app for entry in cfg.mobile if entry.app]
    sources = [entry.argument for entry in cfg.mobile if entry.source]
    try:
        rows = mobsf_scan.scan(root, out, apps, sources, image=os.environ.get("TDXGUARD_MOBSF_IMAGE") or MOBSF_IMAGE,
                               log=ui.info)  # fmt: skip
    except mobsf_scan.MobSFError as e:
        return [f"MobSF: {e}"]
    errors = []
    for row in rows:
        if row.get("error"):
            errors.append(f"MobSF: {row['error']}")
            continue
        if row.get("warning"):
            # Already in the log; the summary keeps it for the report
            summary.setdefault("warnings", []).append(f"MobSF: {row['warning']}")
        summary.setdefault("rows", []).append(
            {"label": row["label"], "findings": row.get("findings", "-"), "severe": row.get("severe", "-")}
        )
    return errors


def _native_tools(ui: UI) -> tools.Toolset:
    """The native engine's tools, downloaded and verified on first use."""
    platform = tools.detect_platform()
    root = tools.tools_dir()
    if any(tools.installed(tool, platform, root) is None for tool in tools.TOOLS.values()):
        ui.step(f"Installing the scanner tools into {root} (once)")
    return tools.ensure(platform, root, log=ui.info)


def _run_native(
    args: argparse.Namespace,
    toolset: tools.Toolset,
    root: Path,
    out: Path,
    excludes: List[str],
    images: List[Tuple[str, str]],
    remote_images: List[Tuple[str, str]],
    skips: List[str],
    trivy_cache: Path,
) -> Tuple[int, str]:
    environment = dict(os.environ)
    environment.setdefault("TRIVY_CACHE_DIR", str(trivy_cache))
    if images and not environment.get("DOCKER_HOST"):
        # Trivy reads locally built images from the daemon of the current Docker context
        # (OrbStack, Colima and rootless Docker need not listen on /var/run/docker.sock).
        host = docker.current_context_host()
        if host:
            environment["DOCKER_HOST"] = host
    options = scan.Options(
        src=root,
        out=out,
        excludes=excludes,
        images=[scan.ImageTarget(ref, slug) for ref, slug in images]
        + [scan.ImageTarget(ref, slug, remote=True) for ref, slug in remote_images],
        skips=skips,
        secrets_mode=args.secrets_mode or "dir",
        log_opts=args.log_opts or "",
        engine="native",
        version=__version__,
    )
    kept: Deque[str] = deque(maxlen=40)

    def show(line: str) -> None:
        kept.append(line)
        if args.verbose:
            print("    " + line, file=sys.stderr, flush=True)

    code = scan.run(options, toolset, environment, log=show, output=show)
    return code, "\n".join(kept)


def _show_tail(ui: UI, tail: str) -> None:
    if tail and not ui.verbose:
        ui.out(ui.style("  --- last lines of the output ---", "dim"))
        for line in tail.splitlines():
            ui.out("    " + line)


def _describe(error: Any) -> str:
    if isinstance(error, dict):
        parts = [str(error[k]) for k in ("scanner", "image", "message", "error") if error.get(k)]
        return ": ".join(parts) if parts else json.dumps(error)
    return str(error)


def _print_summary(ui: UI, summary: Dict[str, Any], out: Path, errors: List[str], engine: str = "") -> None:
    rows = []
    for row in summary.get("rows") or []:
        if not isinstance(row, dict):
            continue
        # `label` is the CI summary's wording, `scanner` the name --skip uses.
        label = str(row.get("label") or row.get("scanner") or "?")
        image = str(row.get("image") or "")
        if image and image not in label:
            label = f"{label} [{image}]"
        rows.append([label, str(row.get("findings", "-")), str(row.get("severe", "-"))])
    ui.out("")
    if rows:
        ui.table(["Scanner", "Findings", "Severe"], rows, align_right=(1, 2))
    else:
        ui.info("The scanner reported no results.")
    ui.out("")
    if engine:
        ui.info(f"Engine:  {_engine_description(engine, summary)}")
    ui.info(f"Reports: {out}")
    for warning in summary.get("warnings") or []:
        ui.warn(_describe(warning))
    for error in errors:
        ui.out(ui.style("  scanner error: ", "red", "bold") + error)


def _engine_description(engine: str, summary: Dict[str, Any]) -> str:
    versions = summary.get("tools") if isinstance(summary.get("tools"), dict) else {}
    names = ", ".join(
        f"{name} {versions[name]}" for name in ("betterleaks", "opengrep", "trivy", "zizmor") if versions.get(name)
    )
    where = f"scanner image {summary.get('version') or '?'}" if engine == "docker" else "tools on this machine"
    return f"{engine} ({where}{'; ' + names if names else ''})"


def _upload(
    ui: UI,
    client: server.Client,
    creds: credentials.Credentials,
    cfg: config.Config,
    root: Path,
    out: Path,
    image_refs: Dict[str, str],
    branch: str,
    licenses: bool,
) -> Tuple[Dict[str, Any], bool]:
    ui.out("")
    ui.step(f"Uploading to {creds.server}")
    product = client.find_product(cfg.project)
    if product is None:
        repository = cfg.repository or gitinfo.remote_url(root)
        if not repository:
            raise ConfigError(
                f"The project {cfg.project} does not exist in TDxGuard, and there is no repository to create it with.",
                f"Set repository: in {config.CONFIG_FILE}, or add a git remote.",
            )
        onboarding = client.onboard(cfg.project, repository)
        ui.success(f"Created the project {cfg.project} in TDxGuard (with its OpenBao secrets and CI role).")
        if onboarding.get("status") == "Failed":
            ui.warn(
                f"The project was created, but setting up OpenBao failed: {onboarding.get('last_error') or '?'}. "
                "The upload goes ahead; retry the setup on the project's onboarding page."
            )
        product = client.find_product(cfg.project) or {"id": onboarding.get("product"), "name": cfg.project}

    failed = 0
    uploaded = []
    if not licenses:
        ui.info("The components and licenses of the SBOM are not imported for a local scan (--sbom imports them).")
    for item in reports.upload_plan(out, image_refs):
        try:
            result = client.upload(str(item.path), item.fields(cfg.project, branch, licenses=licenses))
            uploaded.append({"report": item.path.name, "parser": item.parser, **(result or {})})
            new = (result or {}).get("observations_new", 0)
            resolved = (result or {}).get("observations_resolved", 0)
            ui.info(f"{item.path.name}: {new} new, {resolved} resolved")
        except AuthenticationError:
            raise
        except (ApiError, NetworkError) as e:
            failed += 1
            ui.out(ui.style("  upload failed: ", "red", "bold") + e.message)

    url = _results_url(creds.server, product, _find_branch_id(client, product, branch))
    ui.success(f"Results: {url}")
    apart = f" — {BRANCH_APART_NOTE}" if branch.startswith("local/") else ""
    ui.info(f"(branch {ui.style(branch, 'bold')}{apart})")
    if failed:
        ui.error(f"{failed} report(s) did not reach TDxGuard.")

    security_gate = _report_security_gate(ui, client, cfg.project)
    result = {
        "product": cfg.project,
        "branch": branch,
        "url": url,
        "reports": uploaded,
        "failed": failed,
        "security_gate_passed": security_gate,
    }
    return result, failed > 0


def _report_security_gate(ui: UI, client: server.Client, project: str) -> Optional[bool]:
    """
    The product's security gate in TDxGuard, the one that decides about merging. It is
    computed for the default branch, so the local branch just uploaded does not change it.
    """
    try:
        product = client.find_product(project) or {}
    except (ApiError, NetworkError):
        return None
    passed = product.get("security_gate_passed")
    note = "(this reflects the default branch, not the local branch just uploaded)"
    if passed is True:
        ui.info(f"TDxGuard security gate: {ui.style('passed', 'green')} {note}")
    elif passed is False:
        ui.info(f"TDxGuard security gate: {ui.style('failed', 'red', 'bold')} {note}")
    else:
        ui.info("TDxGuard security gate: not active for this product")
    return passed


def _product_url(server_url: str, product: Dict[str, Any]) -> str:
    return f"{server_url.rstrip('/')}/products/{product.get('id')}/show"


BRANCH_APART_NOTE = "local scans are kept apart from the main branch numbers"

# The statuses of the frontend's default observation filter (OBSERVATION_STATUS_ACTIVE)
ACTIVE_STATUSES = ["Open", "Affected", "In review"]


def _find_branch_id(client: server.Client, product: Dict[str, Any], branch: str) -> Optional[int]:
    """The id of the branch the reports went to; None when it cannot be found (the link then opens the product)."""
    if product.get("id") is None:
        return None
    try:
        found = client.find_branch(product["id"], branch)
    except (ApiError, NetworkError):
        return None
    branch_id = found.get("id") if isinstance(found, dict) else None
    return branch_id if isinstance(branch_id, int) else None


def _results_url(server_url: str, product: Dict[str, Any], branch_id: Optional[int]) -> str:
    """
    The product's open observations on the branch, the way the frontend keeps a list's filter
    in its URL (react-admin's filter query parameter, see frontend/src/core/observations/
    risk_links.ts); without the branch's id the product page.
    """
    url = _product_url(server_url, product)
    if branch_id is None:
        return url
    query = urllib.parse.urlencode(
        {
            "displayedFilters": "{}",
            "filter": json.dumps({"current_status": ACTIVE_STATUSES, "branch": branch_id}, separators=(",", ":")),
            "order": "ASC",
            "sort": "current_priority",
        }
    )
    return f"{url}?{query}"


# --- report ---


def cmd_report(args: argparse.Namespace, ui: UI) -> int:
    """The security assessment report: fetch, render HTML, print to PDF with a local browser."""
    creds: Optional[credentials.Credentials] = None
    if args.from_data:
        data = assessment.load_data(args.from_data)
        product = str(data["product"].get("name") or args.product or "product")
        creds = credentials.load()
    else:
        product = args.product or _report_project()
        # Before the fetch, so that a missing login fails at once.
        creds = credentials.require()

    branch = getattr(args, "branch", None) or ""
    options = assessment.Options(
        product=product,
        branch=branch,
        all_branches=args.all_branches,
        lang=args.lang,
        period_days=args.period_days,
        prepared_for=args.prepared_for or "",
        prepared_by=args.prepared_by or "",
        classification=args.classification,
        ui_url=creds.server if creds else "",
    )
    base = assessment.output_base(args.out, product, args.lang)
    if base.parent and not base.parent.is_dir():
        raise ConfigError(f"The directory {base.parent} does not exist.", "Create it, or choose another --out.")
    # Looked up before the fetch: a wrong TDXGUARD_BROWSER should not cost a minute of waiting.
    found = None if args.no_pdf else report_browser.find_browser()

    if creds is not None and not args.from_data:
        scope = "all branches" if args.all_branches else (f"branch {branch}" if branch else "the default branch")
        ui.step(f"Fetching the findings of {product} ({scope}) from {creds.server}")
        ui.info("This takes 10 to 60 seconds on a large product.")
        watch = assessment.Stopwatch()
        data = assessment.fetch(creds, options, lambda stage: ui.info(f"{watch.seconds():5.1f} s  {stage}"))
        fetched = data.get("branch") or {}
        ui.success(
            f"Fetched {len(data.get('active') or [])} open and {len(data.get('decided') or [])} decided "
            f"observations"
            + (f" of branch {fetched.get('name')}" if fetched.get("name") else "")
            + f" in {data.get('requests', '?')} requests ({watch.text()})."
        )
        if args.save_data:
            try:
                Path(args.save_data).write_text(json.dumps(data), encoding="utf-8")
            except OSError as e:
                raise CLIError(f"Cannot write {args.save_data}: {e.strerror or e}") from e
            ui.info(f"Data saved to {args.save_data} (render it again with --from-data).")
    for warning in assessment.warnings_of(data):
        ui.warn(warning)

    ui.step(f"Writing the report ({args.lang})")
    written = assessment.render(data, options, base, markdown=args.markdown, csv=args.csv)
    ui.info(f"{written.observations} open observations, {written.findings} findings, verdict: {written.verdict}")
    for path in (written.html, written.markdown, written.csv):
        if path is not None:
            ui.success(f"Wrote {path}")

    opened = written.html
    if not args.no_pdf:
        pdf = base.with_name(base.name + ".pdf")
        if found is None:
            ui.warn("No Chrome, Chromium or Edge found, so no PDF was written.")
            again = "." if args.open else ", or run again with --open."
            ui.info(f"Open {written.html} and print it to PDF (A4, without headers and footers){again}")
            ui.info(f"Or set {report_browser.ENV_BROWSER} to the browser's path.")
        else:
            ui.step(f"Printing to PDF with {found.name}")
            ui.debug(f"browser: {found.path}")
            watch = assessment.Stopwatch()
            report_browser.print_to_pdf(found, written.html, pdf)
            pages = report_browser.page_count(pdf)
            details = [f"{pages} pages"] if pages else []
            ui.success(f"Wrote {pdf} ({', '.join(details + [watch.text()])})")
            opened = pdf

    if args.open and not _open_browser(opened.resolve().as_uri()):
        ui.warn(f"Could not open a browser; the report is {opened}.")
    return EXIT_OK


def _report_project() -> str:
    root = gitinfo.find_root() or Path.cwd()
    project = _doctor_project(root, coverage.find_workflow(root))
    if not project:
        raise ConfigError(
            f"Which product? There is no {config.CONFIG_FILE} here.",
            "Pass --product NAME, or run the command inside a repository that has one (`tdxguard init`).",
        )
    return project


# --- tools ---


def cmd_tools(args: argparse.Namespace, ui: UI) -> int:
    """The native engine's tools: list, install (prefetch), clean."""
    root = tools.tools_dir()
    action = getattr(args, "tools_command", None) or "list"
    platform = getattr(args, "platform", None) or tools.detect_platform()

    if action == "clean":
        removed = tools.clean(root, unused_only=args.unused)
        if not removed:
            ui.info(f"Nothing to remove in {root}.")
        for path in removed:
            ui.success(f"Removed {path}")
        return EXIT_OK

    if action == "install":
        if args.force:
            for tool in tools.TOOLS.values():
                shutil.rmtree(tools.install_dir(tool, root), ignore_errors=True)
        ui.step(f"Installing the scanner tools for {tools.PLATFORMS[platform]} into {root}")
        tools.ensure(platform, root, log=ui.info)
        ui.success("All tools are installed and verified.")
        return EXIT_OK

    rows = []
    missing = 0
    for entry in tools.status(platform, root):
        if entry.asset is None:
            state = "no build for this platform"
            missing += 1
        elif entry.path is None:
            state = "missing"
            missing += 1
        else:
            state = "installed"
        rows.append([entry.tool.name, entry.tool.version[:12], state, entry.asset.name if entry.asset else "-"])
    if args.json:
        print(json.dumps({"directory": str(root), "platform": platform, "tools": [
            {"tool": r[0], "version": tools.TOOLS[r[0]].version, "state": r[2], "asset": r[3]} for r in rows
        ]}, indent=2))  # fmt: skip
        return EXIT_OK
    ui.info(f"Tools directory: {root}")
    ui.info(f"Platform:        {tools.PLATFORMS[platform]}")
    ui.out("")
    ui.table(["Tool", "Version", "State", "Asset"], rows)
    if missing:
        ui.out("")
        ui.info("`tdxguard scan --engine native` downloads the missing tools; `tdxguard tools install` does it now.")
    return EXIT_OK


COMMANDS = {
    "login": cmd_login,
    "logout": cmd_logout,
    "whoami": cmd_whoami,
    "init": cmd_init,
    "doctor": cmd_doctor,
    "coverage": cmd_doctor,
    "scan": cmd_scan,
    "report": cmd_report,
    "tools": cmd_tools,
}
