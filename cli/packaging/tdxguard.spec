# PyInstaller spec of the standalone `tdxguard` executable: one file, console, no Python
# needed on the target machine. Build it through build.py, which also names the result.
#
# - The engine's helper scripts are data files: the executable runs them through itself
#   (`tdxguard __helper <name>`, see tdxguard/frozen.py), so they must be inside the bundle
#   byte for byte as in the package.
# - `X utf8`: the interpreter starts in UTF-8 mode, as `python3 -X utf8` does for the
#   helpers when they run from the package; frozen.run_helper refuses to run without it.
# - The report generator (tdxguard/assessment/compliance_report.py) is an ordinary module that
#   `tdxguard report` imports; it is listed below as well so that it can never be left out.

from pathlib import Path

CLI = Path(SPECPATH).resolve().parent  # noqa: F821 (SPECPATH is defined by PyInstaller)
HELPERS = CLI / "tdxguard" / "engine" / "helpers"

a = Analysis(  # noqa: F821
    [str(CLI / "packaging" / "entry.py")],
    pathex=[str(CLI)],
    datas=[
        (str(HELPERS / "sarif_enrich.py"), "tdxguard/engine/helpers"),
        (str(HELPERS / "opengrep_prune_rules.py"), "tdxguard/engine/helpers"),
    ],
    # The helpers run from the data files above, which PyInstaller does not analyse; importing
    # them as modules pulls in the standard library modules they need (html, fnmatch, ...).
    hiddenimports=[
        "tdxguard.engine.helpers.sarif_enrich",
        "tdxguard.engine.helpers.opengrep_prune_rules",
        "tdxguard.assessment.compliance_report",
    ],
    # Nothing the tool uses; keeps the executable small.
    excludes=["tkinter", "_tkinter", "pydoc_data", "lib2to3", "idlelib", "ensurepip"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)  # noqa: F821
exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [("X utf8", None, "OPTION")],
    name="tdxguard",
    console=True,
    debug=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
