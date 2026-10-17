"""
The scan engine: runs Betterleaks, Opengrep and Trivy the way the CI templates do and
writes the reports and summary.json.

One implementation for both places it runs:

- natively, inside `tdxguard scan --engine native`, with the tools from `tdxguard.engine.tools`
- inside the scanner image (ci-templates/scanner), whose entrypoint `tdxguard-scan` is a
  thin wrapper around `python3 -m tdxguard.engine`

Standard library only (plus PyYAML through the rest of the package, which the engine itself
does not import), so that it runs on any machine with Python 3.9 or newer.
"""
