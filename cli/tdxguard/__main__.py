"""Entry point: `tdxguard <command>`."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from tdxguard import __version__, commands, frozen
from tdxguard.config import ENGINES
from tdxguard.engine.scan import SCANNERS
from tdxguard.engine.tools import PLATFORMS
from tdxguard.errors import EXIT_ERROR, CLIError
from tdxguard.ui import UI

DESCRIPTION = """\
Scan a repository with the TDxGuard scanners and send the results to TDxGuard.

  tdxguard login     sign in with TDxSSO in the browser
  tdxguard init      write .tdxguard.yml for this repository
  tdxguard scan      scan, upload and check the gate
  tdxguard tools     the scanner tools of the native engine (list, install, clean)
"""

EPILOG = """\
exit codes: 0 ok, 1 the gate in .tdxguard.yml was exceeded, 2 error (scanner, upload, login, config)
environment: TDXGUARD_TOKEN and TDXGUARD_SERVER replace the login (CI);
             TDXGUARD_ENGINE picks the engine (auto, docker, native);
             TDXGUARD_SCANNER_IMAGE overrides the scanner image (docker engine);
             TDXGUARD_TOOLS_DIR moves the tools cache (native engine); NO_COLOR disables colours
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

    init = sub.add_parser("init", parents=[common], help="write .tdxguard.yml for this repository")
    init.add_argument("--project", help="TDxGuard product name (default: the repository name)")
    init.add_argument("--force", action="store_true", help="overwrite an existing .tdxguard.yml")

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
