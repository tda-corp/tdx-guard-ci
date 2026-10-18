# The standalone executables

`tdxguard` is also shipped as one file per platform, built with PyInstaller, so that machines
without Python (Windows especially) can run it. The executables are published as GitHub
Release assets of the public repository
[tda-corp/tdx-guard-ci](https://github.com/tda-corp/tdx-guard-ci), whose GitHub-hosted runners
(macOS and Windows included) are free.

| File | What it is |
|---|---|
| `tdxguard.spec` | the PyInstaller spec: one file, console, the helper scripts as data, UTF-8 mode |
| `entry.py` | the executable's entry point |
| `build.py` | builds the executable of this machine and names it like the release asset |
| `build-linux.sh` | the Linux build, run inside AlmaLinux 8 (glibc 2.28) |
| `requirements-build.in`, `requirements-build.txt` | PyInstaller and PyYAML, pinned with hashes |
| `smoke.py` | the test every build must pass on its own OS (see below) |
| `install.sh`, `install.ps1` | the installers; they live at the root of tdx-guard-ci |
| `tdx-guard-ci/.github/workflows/cli-release.yml` | the release workflow of tdx-guard-ci |
| `tdx-guard-ci/.github/actionlint.yaml` | declares `macos-15-intel` for actionlint < 1.7.8 |

## Layout in tdx-guard-ci

```
tdx-guard-ci/
  .github/workflows/cli-release.yml   <- cli/packaging/tdx-guard-ci/.github/workflows/cli-release.yml
  .github/actionlint.yaml             <- cli/packaging/tdx-guard-ci/.github/actionlint.yaml
  cli/                                <- cli/ (the package, packaging/ included)
  install.sh                          <- cli/packaging/install.sh
  install.ps1                         <- cli/packaging/install.ps1
```

The installers download from `https://github.com/tda-corp/tdx-guard-ci/releases/download/cli-v<version>/`.
The repository has other tags (`v1`, `v1.11`, ... for the CI template); the installers and
the workflow only look at tags that start with `cli-v`.

## Cutting a release

1. In this repository, bump the version in both `cli/pyproject.toml` and
   `cli/tdxguard/__init__.py` (`tests/test_frozen.py` fails when they differ), and merge.
2. Copy `cli/` and the files above into tdx-guard-ci, commit and push to `main`.
3. Optional, but recommended: run the workflow by hand first (below).
4. Tag in tdx-guard-ci and push the tag:

   ```
   git tag cli-v0.2.0 && git push origin cli-v0.2.0
   ```

The tag must be `cli-v` + the package version, or the build fails at its first step. The
workflow then builds and tests the five executables and creates the release `cli-v0.2.0`
with the five files and `checksums.txt` (sha256, the `sha256sum` format). The installers
pick the newest non-prerelease `cli-v*` release, so the new version is live as soon as the
release exists. A broken release is withdrawn by deleting it (the installers then fall back
to the previous one) or by marking it as a prerelease.

## What the workflow does

`build` runs on five GitHub-hosted runners:

| Asset | Runner | Built with |
|---|---|---|
| `tdxguard-<v>-darwin-arm64` | `macos-15` | python.org-style Python 3.12 from `actions/setup-python` |
| `tdxguard-<v>-darwin-x86_64` | `macos-15-intel` | the same, on Intel |
| `tdxguard-<v>-linux-x86_64` | `ubuntu-24.04` | AlmaLinux 8.10 container, its `python3.12` |
| `tdxguard-<v>-linux-arm64` | `ubuntu-24.04-arm` | the same, on arm64 |
| `tdxguard-<v>-windows-x86_64.exe` | `windows-2022` | Python 3.12 from `actions/setup-python` |

Each leg then tests what it built, on that OS:

1. Linux only: `--version` and `tools list` in the AlmaLinux 8 image (glibc 2.28, no
   Python on PATH), which proves the minimum glibc.
2. `smoke.py`: `--version`; `tools install` into an empty tools directory (downloads and
   verifies Betterleaks, Opengrep with its rules and Trivy for that platform); then
   `tdxguard scan --engine native --no-upload --keep <dir>` on a fixture repository made in
   the job (a vulnerable `requirements.txt`, Python code the Opengrep security rules flag, a
   Dockerfile with misconfigurations, a GitHub-token-shaped secret generated at run time).
   Every report must exist, `summary.json` must have no errors and each of Betterleaks,
   Opengrep, Trivy IaC and Trivy dependencies must have findings. `python`, `python3` and
   `py` on the executable's PATH are traps: the test fails if the executable starts one.
   Then `report --help`, and `report --from-data` renders the security assessment report of a
   small saved product (HTML only, no network and no browser), which proves that the report
   generator is in the bundle.
3. Windows only: the same assertions again in PowerShell.
4. The unit tests of `cli/` with the runner's Python (`python -m unittest`), also when the
   smoke test failed, so that Windows path handling gets real coverage.
5. The executable is uploaded as a workflow artifact (kept 3 days).

`release` (tags only, the only job with `contents: write`) downloads the five artifacts,
writes `checksums.txt` and creates the release with `gh release create --verify-tag`.

Every action is pinned to a full commit SHA; the Linux build image is pinned by digest.

### Testing without a release

Actions -> "tdxguard CLI release" -> "Run workflow" (any branch). It builds and tests the
five executables and keeps them as workflow artifacts for 3 days; nothing is released.

## Building locally

```
cd cli
python3.12 -m venv /tmp/tdxguard-build
/tmp/tdxguard-build/bin/pip install --require-hashes -r packaging/requirements-build.txt
/tmp/tdxguard-build/bin/python packaging/build.py --out dist
python3 packaging/smoke.py dist/tdxguard-<version>-<os>-<arch> --tools-dir /tmp/empty-tools
```

The Python that builds must have a shared libpython (python.org and `actions/setup-python`
builds do; a default pyenv build does not). Linux, from `cli/`:

```
docker run --rm -v "$PWD":/cli -w /cli -e BUILD_UID="$(id -u)" -e BUILD_GID="$(id -g)" \
  almalinux:8.10 sh packaging/build-linux.sh --out dist
```

To refresh the pinned build tools, edit `requirements-build.in` and run the `uv pip compile`
command at its top.

## Design notes

**No Python at run time.** A frozen executable has no `python` to run scripts with. The
engine's helper scripts (`tdxguard/engine/helpers/*.py`, byte-identical to the copies the CI
templates embed) are bundled as data files, and the engine runs them as
`<executable> __helper <name> <args>` (`tdxguard/frozen.py`): a hidden command that executes
the bundled script as `__main__` in a new process, with no working-directory entry on the
module path and the interpreter in UTF-8 mode (`X utf8` in the spec) - the equivalent of
`python3 -I -X utf8 <script>`. From the package nothing changes: the helpers still run as
`python3 -I -X utf8 <script>`. The child process reuses the parent's unpacked directory, so a
helper call costs no second unpacking. `tests/test_frozen.py` runs a whole scan as a pretend
executable and asserts that no process it starts is Python.

**The report generator.** `tdxguard report` imports `tdxguard/assessment/compliance_report.py`,
a byte-identical copy of `ci-templates/compliance-report.py`, as an ordinary module (it is in
the spec's `hiddenimports` as well); it runs in-process, so it needs no helper command. The
PDF is printed by a browser already installed on the machine, never by one in the bundle.

**TLS.** The bundled OpenSSL looks for CA certificates where the build machine keeps them
(`/etc/pki/tls` for AlmaLinux, the python.org prefix on macOS). Frozen, the tool therefore
also loads the system bundle (`/etc/ssl/certs/ca-certificates.crt`,
`/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/ca-bundle.pem` or `/etc/ssl/cert.pem`, the first
that exists); Windows uses its certificate store anyway. `TDXGUARD_CA_BUNDLE` still wins.

**glibc 2.28.** A Linux executable needs the glibc it was linked against or newer;
everything else (libpython, OpenSSL, libffi, zlib) is inside it. The build runs in
AlmaLinux 8 because its `python3.12` has a shared libpython (PyInstaller needs one; the
manylinux images' Pythons are static) and glibc 2.28 covers Debian 10+, Ubuntu 20.04+,
RHEL 8+ and Amazon Linux 2023. Alpine (musl) cannot run it; the installer says so and
points to pipx and `--engine docker`.

**Windows on ARM64.** No native build: Windows 11 on ARM64 runs the x86_64 executable and
the x86_64 scanners under its x64 emulation, so `install.ps1` installs the x86_64 build there
with a warning (untested). Windows 10 on ARM64 has no x64 emulation and is refused.

**macOS.** The executables are ad-hoc signed by PyInstaller, not notarized. The installers
download with curl, `Invoke-WebRequest` or wget, which set no quarantine attribute, and
remove it anyway. A file downloaded with a browser needs
`xattr -d com.apple.quarantine tdxguard-*` before macOS runs it.

**Size.** About 8 MB (macOS arm64) to 9 MB (Linux); no UPX, no strip.
