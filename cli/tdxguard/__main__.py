"""Entry point: `tdxguard <command>`."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from tdxguard import __version__, assessment, commands, frozen
from tdxguard.config import ENGINES
from tdxguard.engine.scan import SCANNERS
from tdxguard.engine.tools import PLATFORMS
from tdxguard.errors import EXIT_ERROR, CLIError
from tdxguard.ui import UI

DESCRIPTION = """\
Scan a repository with the TDxGuard scanners and send the results to TDxGuard.

  tdxguard login     sign in with TDxSSO in the browser
  tdxguard init      write .tdxguard.yml and the CI workflow for this repository
  tdxguard doctor    what is scanned, what is missing and what TDxGuard received
  tdxguard scan      scan, upload and check the gate
  tdxguard report    the security assessment report of the project (HTML and PDF)
  tdxguard tools     the scanner tools of the native engine (list, install, clean)
"""

EPILOG = """\
exit codes: 0 ok, 1 the gate in .tdxguard.yml was exceeded (doctor: an expected scan is not in CI),
            2 error (scanner, upload, login, config)
environment: TDXGUARD_TOKEN and TDXGUARD_SERVER replace the login (CI);
             TDXGUARD_ENGINE picks the engine (auto, docker, native);
             TDXGUARD_SCANNER_IMAGE overrides the scanner image (docker engine);
             TDXGUARD_TOOLS_DIR moves the tools cache (native engine);
             TDXGUARD_BROWSER is the browser that prints the report to PDF; NO_COLOR disables colours
"""


def build_parser() -> argparse.ArgumentParser:
    # -v works before and after the command. SUPPRESS keeps the subcommand's default from
    # overwriting a -v given before it.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-v", "--verbose", action="store_true", default=argparse.SUPPRESS, help="show docker's output and more detail"
    )

    parser = argparse.ArgumentParser(
        prog="tdxguard",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="show docker's output and more detail")
    parser.add_argument("--version", action="version", version=frozen.version_line(__version__))
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    login = sub.add_parser("login", parents=[common], help="sign in with TDxSSO (OAuth device flow)")
    login.add_argument("--server", help="TDxGuard address (default: https://guard.tdadevelop.com)")
    login.add_argument("--client-id", help="OIDC client id (default: the one the server's frontend uses)")
    login.add_argument("--oidc-authority", help="identity provider (default: the one the server's frontend uses)")
    login.add_argument("--no-browser", action="store_true", help="do not try to open a browser")

    sub.add_parser("logout", parents=[common], help="revoke the token and delete the stored credentials")

    whoami = sub.add_parser("whoami", parents=[common], help="show the server, the user and the token expiry")
    whoami.add_argument("--json", action="store_true", help="print JSON")

    init = sub.add_parser(
        "init",
        parents=[common],
        help="write .tdxguard.yml and the CI workflow for this repository",
        description="Writes .tdxguard.yml (local scans) and the TDxGuard CI workflow with what it detects: "
        "Dockerfiles become the image scan; a start command (asked, or --start-command) switches on IAST, "
        "a target URL DAST. Asks on a terminal; flags and --yes for scripts. An existing workflow is not "
        "overwritten: the inputs to add are listed instead.",
    )
    init.add_argument("--project", help="TDxGuard product name (default: the repository name)")
    init.add_argument(
        "--force", action="store_true", help="overwrite an existing .tdxguard.yml and GitHub workflow file"
    )
    init.add_argument("--ci", choices=("github", "gitlab"), help="CI platform (default: from the git remote)")
    init.add_argument("--no-ci", action="store_true", help="write .tdxguard.yml only, no CI workflow")
    init.add_argument(
        "--dockerfile",
        action="append",
        metavar="PATH",
        help='Dockerfile to build and scan in CI, optionally with its context: "web/Dockerfile web" '
        "(repeatable; default: every Dockerfile found)",
    )
    init.add_argument("--image-ref", metavar="REF", help="image in a registry to scan (GitLab: the one CI pushed)")
    init.add_argument("--start-command", metavar="CMD", help="command that starts the app in CI (IAST)")
    init.add_argument("--health-url", metavar="URL", help="URL that answers once the app is up")
    init.add_argument("--dast-target", metavar="URL", help="URL for ZAP: the started app or a test environment")
    init.add_argument("--yes", action="store_true", help="ask nothing, use the flags and what is detected")

    for name, aliases in (("doctor", ["coverage"]),):
        doctor = sub.add_parser(
            name,
            aliases=aliases,
            parents=[common],
            help="what this repository should be scanned for, what CI scans, what TDxGuard received",
            description="Inspects the repository (Dockerfiles, IaC files, manifests and lockfiles, the CI "
            "workflow and its inputs) and, when logged in, the product's scan coverage in TDxGuard. Exit "
            "code 0 when every expected kind of scan is configured in CI, 1 otherwise (--no-fail: always 0).",
        )
        doctor.add_argument("--project", help="TDxGuard product name (default: .tdxguard.yml, the workflow)")
        doctor.add_argument("--ci", choices=("github", "gitlab"), help="CI platform (default: detected)")
        doctor.add_argument("--offline", action="store_true", help="do not ask TDxGuard")
        doctor.add_argument("--no-fail", action="store_true", help="exit 0 even when something is missing")
        doctor.add_argument("--json", action="store_true", help="print JSON")

    scan = sub.add_parser(
        "scan",
        parents=[common],
        help="scan, upload to TDxGuard and check the gate",
        description="Builds the images of .tdxguard.yml, runs the scanners (in the scanner image, or "
        "natively without Docker), uploads the reports and checks the gate.",
    )
    scan.add_argument(
        "--engine",
        choices=ENGINES,
        help="docker: the scanner image; native: the tools on this machine, downloaded on first use; "
        "auto (default): docker when a Docker daemon answers, else native. Also TDXGUARD_ENGINE, "
        "or engine: in .tdxguard.yml",
    )
    scan.add_argument("--no-upload", action="store_true", help="scan only; nothing is sent to TDxGuard")
    scan.add_argument("--branch", help="branch name in TDxGuard (default: local/<user>/<git branch>)")
    scan.add_argument(
        "--skip", action="append", choices=SCANNERS, metavar="SCANNER", help=f"skip a scanner: {', '.join(SCANNERS)}"
    )
    images = scan.add_mutually_exclusive_group()
    images.add_argument("--image-only", action="store_true", help="scan only the images")
    images.add_argument("--no-images", action="store_true", help="do not build or scan images")
    scan.add_argument(
        "--secrets-mode",
        choices=("dir", "git"),
        help="secrets in the working tree (dir) or in the git history (git); default: the scanner's",
    )
    scan.add_argument(
        "--log-opts",
        metavar="OPTS",
        help='git log options for --secrets-mode git, e.g. --log-opts="--since=2025-01-01" (note the =)',
    )
    scan.add_argument("--keep", metavar="DIR", help="write the reports to DIR (default: ~/.cache/tdxguard/reports)")
    scan.add_argument("--json", action="store_true", help="print the result as JSON on stdout")

    report = sub.add_parser(
        "report",
        parents=[common],
        help="the security assessment report of the project, as HTML and PDF",
        description="Fetches the product's findings, decisions and scan history from TDxGuard (with your "
        "permissions) and writes the security assessment report: <out>.html, and <out>.pdf when Chrome, "
        "Chromium or Edge is installed (printed headless; TDXGUARD_BROWSER picks another). Fetching takes "
        "10 to 60 seconds on a large product.",
    )
    report.add_argument("--product", help="TDxGuard product name (default: project of .tdxguard.yml)")
    report_branch = report.add_mutually_exclusive_group()
    report_branch.add_argument("--branch", help="branch to report on (default: the product's default branch)")
    report_branch.add_argument("--all-branches", action="store_true", help="report on all branches together")
    report.add_argument(
        "--lang", choices=assessment.LANGUAGES, default="vi", help="language of the report (default: vi)"
    )
    report.add_argument(
        "--out",
        metavar="PATH",
        help="file name without extension, or a directory: --out report writes report.html and report.pdf "
        "(default: <product>-security-report-<lang>)",
    )
    report.add_argument("--open", action="store_true", help="open the PDF (or the HTML) when it is written")
    report.add_argument("--no-pdf", action="store_true", help="write the HTML only")
    report.add_argument("--markdown", action="store_true", help="also write <out>.md")
    report.add_argument("--csv", action="store_true", help="also write every finding as <out>.csv")
    report.add_argument(
        "--period-days",
        type=int,
        choices=assessment.PERIODS,
        default=30,
        help="reporting period of the changes and the trend (default: 30)",
    )
    report.add_argument("--prepared-for", metavar="TEXT", help="recipient, e.g. the customer's security team")
    report.add_argument("--prepared-by", metavar="TEXT", help="who prepared it (default: TDA security team)")
    report.add_argument(
        "--classification", metavar="TEXT", help="marking on the cover and every page (default: Confidential)"
    )
    report.add_argument("--save-data", metavar="FILE", help="also save the fetched data as JSON")
    report.add_argument(
        "--from-data", metavar="FILE", help="render data saved with --save-data again, without the network"
    )

    tools = sub.add_parser(
        "tools",
        parents=[common],
        help="the scanner tools of the native engine",
        description="Betterleaks, Opengrep (with its rules) and Trivy for `tdxguard scan --engine native`, "
        "pinned and checksum-verified, in ~/.cache/tdxguard/tools (TDXGUARD_TOOLS_DIR).",
    )
    tools_sub = tools.add_subparsers(dest="tools_command", metavar="<action>")
    tools_list = tools_sub.add_parser("list", parents=[common], help="show what is required and installed")
    tools_list.add_argument("--json", action="store_true", help="print JSON")
    tools_install = tools_sub.add_parser("install", parents=[common], help="download and verify the tools now")
    tools_install.add_argument("--force", action="store_true", help="download again even if installed")
    # For preparing another machine's cache (and testing every pinned checksum).
    tools_install.add_argument("--platform", choices=sorted(PLATFORMS), help=argparse.SUPPRESS)
    tools_clean = tools_sub.add_parser("clean", parents=[common], help="delete the tools cache")
    tools_clean.add_argument("--unused", action="store_true", help="delete only versions that are no longer pinned")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    # Hidden: the standalone executable runs the engine's helper scripts through itself.
    if arguments[:1] == [frozen.HELPER_COMMAND]:
        return frozen.run_helper(arguments[1:])
    parser = build_parser()
    args = parser.parse_args(arguments)
    if not args.command:
        parser.print_help()
        return EXIT_ERROR
    ui = UI(verbose=getattr(args, "verbose", False), json_mode=getattr(args, "json", False))
    if args.command == "tools" and not getattr(args, "json", None):
        args.json = False
    try:
        return commands.COMMANDS[args.command](args, ui)
    except CLIError as e:
        ui.error(e.message, e.hint)
        return e.exit_code
    except KeyboardInterrupt:
        ui.error("Interrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
