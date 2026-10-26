# tdxguard: scan a repository from the command line

`tdxguard` runs the same scanners as the TDxGuard CI templates on your machine and sends the
results to [TDxGuard](https://guard.tdadevelop.com), the way `sonar-scanner` does for SonarQube.
It runs them in the scanner image when Docker is there, and directly on the machine when it
is not (see [Engines](#engines-docker-or-native)).

```
tdxguard login        # sign in with TDxSSO in the browser
tdxguard init         # write .tdxguard.yml and the CI workflow for this repository
tdxguard doctor       # what CI scans, what is missing, what TDxGuard received
tdxguard scan         # scan, upload to TDxGuard, check the gate
tdxguard report       # the security assessment report, as HTML and PDF
```

## Install

There are two ways: the standalone executable, which needs nothing else (no Python), or the
Python package through pipx. Docker is optional either way: without it, `tdxguard scan`
downloads the scanners once into `~/.cache/tdxguard/tools` and runs them natively. Only
building images from Dockerfiles needs Docker.

### Standalone executable (recommended)

macOS and Linux:

```
curl -fsSL https://raw.githubusercontent.com/tda-corp/tdx-guard-ci/main/install.sh | sh
```

Windows (PowerShell 5.1 or 7):

```
irm https://raw.githubusercontent.com/tda-corp/tdx-guard-ci/main/install.ps1 | iex
```

The installers take the newest `cli-v*` release of
[tda-corp/tdx-guard-ci](https://github.com/tda-corp/tdx-guard-ci/releases), verify the
download against the release's `checksums.txt` (sha256) and refuse it on a mismatch. They
never need root or administrator rights. Run the same command again to update.

| | macOS / Linux (`install.sh`) | Windows (`install.ps1`) |
|---|---|---|
| Installs to | `~/.local/bin/tdxguard` | `%LOCALAPPDATA%\Programs\tdxguard\tdxguard.exe` |
| PATH | prints the line to add if the directory is not on PATH | adds the directory to the user PATH (new terminals see it) |
| Other directory | `TDXGUARD_INSTALL_DIR=...` | `$env:TDXGUARD_INSTALL_DIR = '...'` |
| Pin a version | `TDXGUARD_VERSION=0.2.0` | `$env:TDXGUARD_VERSION = '0.2.0'` |

You can also download the file for your platform from the release page and check it
against `checksums.txt` yourself: `tdxguard-<version>-<os>-<arch>` (`.exe` on Windows).

| Platform | Executable | Notes |
|---|---|---|
| macOS arm64 (Apple Silicon) | `darwin-arm64` | the installer picks it under Rosetta too |
| macOS x86_64 (Intel) | `darwin-x86_64` | |
| Linux x86_64, arm64 | `linux-x86_64`, `linux-arm64` | glibc 2.28 or newer: Debian 10+, Ubuntu 20.04+, RHEL/Rocky/Alma 8+, Amazon Linux 2023. **Not Alpine/musl**: use pipx there, or `--engine docker` |
| Windows x86_64 | `windows-x86_64.exe` | Windows 10 and 11 |
| Windows 11 on ARM64 | `windows-x86_64.exe` | runs under the x64 emulation of Windows 11, untested; the installer warns. Windows 10 on ARM64 cannot run it |

Notes:

- The executable unpacks itself into a temporary directory on every start. On macOS the
  system checks the unpacked libraries each time, so a command can take a few seconds to
  start (about 3 s measured on an Apple Silicon Mac, against 0.15 s on Linux); the scan
  itself is not slower.
- **Windows**: the scanners (Betterleaks, Opengrep, Trivy) are Windows executables too and
  are downloaded on the first native scan; nothing needs WSL. Antivirus software may slow the
  first start or the first scan. Behind a TLS-intercepting proxy, set `TDXGUARD_CA_BUNDLE` to
  the proxy's CA file (PEM).
- The executable finds CA certificates in the system store on Windows and in the system
  bundle on macOS (`/etc/ssl/cert.pem`) and Linux (`/etc/ssl/certs/ca-certificates.crt` and the
  like; install the `ca-certificates` package on minimal images). A certificate that exists
  only in the macOS keychain is not seen: export it and set `TDXGUARD_CA_BUNDLE`.
- `tdxguard --version` prints the version and the platform, and says `standalone` for the
  executable and the Python version for the package.

### Python package (pipx)

Python 3.9 or newer; the only Python dependency is PyYAML. This works wherever Python does,
including Alpine/musl and Windows on ARM64.

```
pipx install "git+https://github.com/tda-corp/tdx-guard-ci#subdirectory=cli"
```

From a checkout: `pipx install ./cli` (or `pip install ./cli` in a virtual environment).
How the executables are built and released: [packaging/README.md](packaging/README.md).

## Log in

```
$ tdxguard login
> Log in to https://guard.tdadevelop.com
  Open this page and confirm the code:

    https://sso.tdadevelop.com/device?user_code=EB74MH1N
    code: EB74MH1N

  A browser window should have opened. Waiting for the confirmation ...
  ok Logged in to https://guard.tdadevelop.com as jane.doe.
  Token tdxguard-cli jane-laptop is valid until 2027-01-15, stored in /home/jane/.config/tdxguard/credentials.json.
```

Login uses the OAuth 2.0 device authorization grant against TDxSSO. The identity provider,
client id and scope are read from the server (`<server>/runtime-env.js`, the file the
TDxGuard frontend reads), so nothing about TDxSSO is configured in the tool. The ID token
is exchanged for a TDxGuard API token (`POST /api/authentication/cli_token/`). That token
is named `tdxguard-cli <hostname>` and is valid for 90 days. Logging in again replaces it and
revokes the old one.

The API token is stored in `~/.config/tdxguard/credentials.json`, or under `$XDG_CONFIG_HOME`
if that is set. The file has mode 0600 and its directory 0700. The tool never prints the token.

| Command | |
|---|---|
| `tdxguard login [--server URL] [--no-browser]` | `--client-id` and `--oidc-authority` override what the server announces |
| `tdxguard whoami [--json]` | server, user, token name and expiry |
| `tdxguard logout` | revokes the token on the server and deletes the file |

## Configure: `.tdxguard.yml`

`tdxguard init` writes the file at the root of the git repository. The product name comes
from the git remote, and the tool lists every Dockerfile it finds (`Dockerfile`,
`*.Dockerfile`, `Dockerfile.*`, outside `node_modules`, `.git` and `vendor`). It does not
overwrite an existing file unless you pass `--force`. Pass `--project NAME` to choose the
product name yourself.

`init` then writes the CI workflow too (see [Full coverage](#full-coverage-init-and-doctor)).

```yaml
project: tdx-scribe                # TDxGuard product name (required)
repository: tda-corp/tdx-scribe    # optional; used when the project is created
engine: auto                       # optional; auto (default), docker or native
exclude: [mobile/, agents/eval/]   # paths the scanners leave out
images:                            # images to scan; optional
  - dockerfile: Dockerfile         # built locally (needs Docker)
    context: .                     # default: the Dockerfile's directory
    name: root                     # slug; default derived from the path, as in CI
  - ref: ghcr.io/tda-corp/tdx-scribe-api:1.4   # pulled from its registry by Trivy, not built
    name: api                      # optional; default: last path segment and tag (tdx-scribe-api-1.4)
mobile:                            # a mobile app MobSF analyses (needs Docker); optional
  - app: app/build/outputs/apk/release/*.apk   # the built .apk/.aab/.ipa; a glob is fine
  - source: ios                    # or the source: android or ios
    path: ios                      # the project directory; default: the repository root
gate:                              # optional; `tdxguard scan` exits 1 when exceeded
  critical: 0
  high: null                       # null = no limit
  ignore_unfixed: true             # default true, as in CI's Trivy gate
```

| Key | Type | Notes |
|---|---|---|
| `project` | string | Required. If the product does not exist, the first upload creates it. |
| `repository` | string | `org/repo`, a group path, or a clone URL. Defaults to the git remote. Used only when the project is created. |
| `engine` | string | `auto`, `docker` or `native`; see [Engines](#engines-docker-or-native). `--engine` and `TDXGUARD_ENGINE` take precedence. |
| `exclude` | list of paths | Relative to the repository root. **Betterleaks has no path exclusion, so secrets are still searched in excluded paths.** |
| `images[].dockerfile` | path | An image to build and scan. Each entry has either `dockerfile` or `ref`. |
| `images[].context` | path | Defaults to the Dockerfile's directory. Note that CI builds from the repository root. |
| `images[].ref` | image reference | An image in a registry, such as `ghcr.io/org/app:tag`. Nothing is built: Trivy pulls it from the registry (`trivy image --image-src remote`), with or without Docker. Private registries use Trivy's usual credentials (`docker login`, or `TRIVY_USERNAME`/`TRIVY_PASSWORD`). |
| `images[].name` | slug | `[a-z0-9][a-z0-9._-]*`. The default is derived like the CI template: `docker/backend/Dockerfile` becomes `docker-backend`, `Dockerfile` becomes `root`, `Dockerfile.prod` becomes `prod`; for a `ref`, the last path segment and the tag (`ghcr.io/org/app:1.2` becomes `app-1.2`). |
| `mobile[].app` | path or glob | A built app, `.apk`, `.aab`, `.apks`, `.xapk` or `.ipa`, matching exactly one file. Gives far more than the source: MobSF decompiles the whole app, its libraries included, and checks the certificate and native binaries. See [Mobile apps](#mobile-apps-mobsf). |
| `mobile[].source`, `mobile[].path` | `android` or `ios`, directory | The project's source, zipped and analysed. Android needs the Android Studio layout (`app/src/main/AndroidManifest.xml`), and only that app module is analysed. |
| `gate.critical`, `gate.high` | int >= 0 or null | The highest allowed count. |
| `gate.ignore_unfixed` | bool | Ignores vulnerabilities that have no fixed version. |

The tool rejects unknown keys and wrong types, and the message names the key path, for example
`.tdxguard.yml: images[1].dockerfile: file not found: web/Dockerfile`.

## Full coverage: `init` and `doctor`

Without optional inputs the CI runs three scans: secrets, code (SAST), and dependencies plus
infrastructure as code (Trivy). Container images, IAST (Aikido Zen), DAST (ZAP, Nuclei) and a
mobile app (MobSF) need inputs in the workflow. Two commands make that visible.

**`tdxguard init`** writes the CI workflow next to `.tdxguard.yml`:
`.github/workflows/tdxguard.yml` on GitHub, or prints the block for `.gitlab-ci.yml` on GitLab.
Every Dockerfile found becomes the image scan (GitHub builds them; GitLab only scans an image
your build job pushed, `--image-ref`). A `start` script in `package.json` or a compose service
with a port is shown as a possible start command, never written on its own. On a terminal it
asks; in scripts pass flags and `--yes`.

| Flag | |
|---|---|
| `--ci github\|gitlab` | default: from the git remote |
| `--dockerfile PATH [CONTEXT]` | repeatable; default: every Dockerfile found |
| `--image-ref REF` | an image in a registry (GitLab: `$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA` when your build job pushes it) |
| `--start-command CMD`, `--health-url URL` | start the app in CI: IAST, and on GitHub the in-job ZAP scan |
| `--dast-target URL` | URL for ZAP. Only an environment you own, never production without approval |
| `--mobile-app PATH`, `--mobile-source PLATFORM[:DIR]` | the built app (or the source) MobSF analyses in CI; repeatable; GitHub only |
| `--yes`, `--no-ci`, `--force` | ask nothing; skip the workflow; overwrite the files |

An existing workflow is not overwritten without `--force`; `init` lists the inputs to add
instead (`+` new, `~` different, `=` already set). `.gitlab-ci.yml` is never overwritten.

**`tdxguard doctor`** (alias `coverage`) prints one row per kind of scan: whether the
repository needs it and why (Dockerfiles, IaC files, manifests and lockfiles, a start command),
whether the workflow configures it, what TDxGuard received for the default branch (when logged
in and the server reports `scan_coverage`), and the exact line to add.

```
$ tdxguard doctor
  Kind                    Expected   Why                    In CI  Received    What to do
  Container images        yes        Dockerfile             no     never       dockerfile: "Dockerfile"
  Runtime (IAST)          suggested  package.json: "start"  no     never       app_start_command: "npm start"
```

The code (SAST) row names the repository's languages that Opengrep has security rules for,
most files first. Opengrep loads the security rules of opengrep-rules for Python, JavaScript,
TypeScript, Go, PHP, Java, Kotlin, Scala, Ruby, C# and C, plus language-independent
patterns (`RULE_LANGUAGES` in `tdxguard/engine/tools.py`). Code in any other language, Rust,
Swift, Dart or C++ for example, is not analysed, and doctor says so under the table:

```
Code (SAST): Opengrep has no rules for rust (42 files): SAST does not analyse that code.
```

Doctor recognises mobile apps: Android (an `AndroidManifest.xml`, or the Android Gradle plugin),
iOS (an `.xcodeproj` or a `Podfile`), Flutter (`pubspec.yaml` with `sdk: flutter`) and React
Native. It suggests the mobile app analysis for them, and under the dependencies row it says what
Trivy cannot see. Trivy reads lockfiles only: `gradle.lockfile` (one per module, plus
`buildscript-gradle.lockfile` and `settings-gradle.lockfile`), `Podfile.lock`,
`Package.resolved`, `pubspec.lock` — not `build.gradle`, `libs.versions.toml`, `Podfile`,
`Package.swift` or `pubspec.yaml`. For an Android project without lockfiles:

```
Dependencies (SCA):
    Trivy cannot see the Gradle dependencies: there is no gradle.lockfile, and Trivy reads neither build.gradle nor libs.versions.toml.
    Turn on dependency locking for every module, in the root build.gradle(.kts) of the build:
      allprojects { dependencyLocking { lockAllConfigurations() } }
    then write one gradle.lockfile per module and commit them:
      ./gradlew dependencies :app:dependencies :core:network:dependencies --write-locks
    Run that command again whenever a dependency changes.
```

Exit code 0 when every kind marked `yes` is configured in CI, 1 otherwise, 2 on an error.
`--no-fail` always exits 0; `--offline` does not ask TDxGuard; `--json` prints JSON.
IAST, DAST and the mobile app are `suggested`, not required: they need the app to embed Zen, a
target the team owns, or a built app.

The same questions, with a live preview, are on the **New project** page and on each product's
**Integration** tab in TDxGuard.

## Scan

```
$ tdxguard scan
> Building 1 image(s)
  docker/api/Dockerfile -> tdxguard-local/docker-api:scan
> Scanning with the docker engine (this can take a few minutes; -v shows the progress)

  Scanner                                        Findings  Severe
  ---------------------------------------------  --------  ------
  Betterleaks (secrets)                                 0       0
  Opengrep (SAST)                                       3       1
  Trivy (IaC)                                           4       2
  Trivy (dependencies)                                 12       1
  Trivy (image `tdxguard-local/docker-api:scan`)       31       4
  Trivy (image secrets) [docker-api]                    0       0

  Engine:  docker (scanner image v1.1.0; betterleaks 1.9.0, opengrep 1.31.0, trivy 0.76.0)
  Reports: /home/jane/.cache/tdxguard/reports/tdx-scribe

> Uploading to https://guard.tdadevelop.com
  betterleaks.json: 0 new, 0 resolved
  opengrep.sarif: 3 new, 0 resolved
  ...
  ok Results: https://guard.tdadevelop.com/products/42/show?displayedFilters=%7B%7D&filter=...%22branch%22%3A118%7D&...
  (branch local/jane.doe/feature/login — local scans are kept apart from the main branch numbers)
  TDxGuard security gate: passed (this reflects the default branch, not the local branch just uploaded)
  local gate failed: 2 critical finding(s), the gate allows 0
```

The scan runs these steps:

1. It reads `.tdxguard.yml` from the git root and picks the engine.
2. It builds each Dockerfile image with `docker build -f <dockerfile> -t tdxguard-local/<name>:scan <context>`.
   Registry images (`ref:`) are not built.
3. It runs Betterleaks, Opengrep and Trivy, zizmor where the repository has GitHub Actions
   workflows, and Trivy again for each image: in the scanner
   image `ghcr.io/tda-corp/tdxguard-scanner:v1` with the repository mounted read-only (docker
   engine), or as programs on this machine (native engine). Both run the same code.
4. It prints the summary, the engine that ran and where the reports are.
5. It uploads every report to TDxGuard, like CI does: SARIF, CycloneDX and Betterleaks, and
   image reports with `docker_image_name_tag`. If the project does not exist, the tool creates
   it through the onboarding API, which also sets up its OpenBao secrets and CI role. External
   users cannot create projects.
6. It checks the gate from `.tdxguard.yml`.

Between steps 3 and 4 it analyses the apps of `mobile:` with MobSF, see
[Mobile apps](#mobile-apps-mobsf).

### Mobile apps (MobSF)

With `mobile:` in `.tdxguard.yml`, `tdxguard scan` analyses the app with MobSF (Mobile Security
Framework), whatever the engine: MobSF runs from its official image
(`opensecurity/mobile-security-framework-mobsf:v4.5.3`, about 1 GB to download, 2.3 GB unpacked)
as a throwaway container, so it needs Docker; without Docker the scan says so and goes on with
the other scanners. The container is cut off from the network before the app is copied in, so
neither the app nor anything found in it leaves the machine; it needs the network only while it
starts, to download its decompiler, which takes one to three minutes on every scan. Each entry
writes `mobsf-<slug>.json`, uploaded with the MobSF parser; the findings are of the kind
"Mobile app" in TDxGuard. `--skip mobile` leaves it out; `TDXGUARD_MOBSF_IMAGE` replaces the
image (a mirror, for example). The same script runs in the GitHub template's `mobile` job.

MobSF's findings do not count in the local gate, as they do not fail CI either; their high
findings count in the product's security gate in TDxGuard.

The results go to the branch `local/<username>/<git branch>`, so a working tree with
uncommitted changes never mixes with the results of the real branches. To choose another
branch, pass `--branch NAME`.

On a `local/` branch TDxGuard imports the vulnerabilities of the CycloneDX SBOMs, but not
their components and licenses (`suppress_licenses`), like the CI templates on a pull
request. A local scan is a throwaway copy of the project: TDxGuard deletes it after
`branch_housekeeping_keep_inactive_days_ephemeral` days (3 by default) without an upload,
and a copy of every component per developer and branch is what made the database grow.
The findings, the gate and the SCA coverage are the same either way. Pass `--sbom` to
import the components too; a `--branch` outside `local/` always gets them.

| Option | |
|---|---|
| `--no-upload` | scan only; nothing leaves the machine and no login is needed |
| `--engine auto\|docker\|native` | where the scanners run; see [Engines](#engines-docker-or-native) |
| `--branch NAME` | the branch name in TDxGuard |
| `--sbom` | also import the components and licenses of the SBOMs on a `local/` branch |
| `--skip SCANNER` | `betterleaks`, `opengrep`, `trivy`, `image` or `mobile`; can be repeated |
| `--image-only` / `--no-images` | scan only the images, or skip building and scanning them |
| `--secrets-mode dir\|git` | search for secrets in the working tree (`dir`) or in the git history (`git`). With the docker engine, `git` does not work in a git worktree. |
| `--log-opts="..."` | `git log` options for `--secrets-mode git`; write it with `=` |
| `--keep DIR` | write the reports to DIR instead of `~/.cache/tdxguard/reports/<project>/` (that directory is emptied on every scan). The reports of an earlier run in DIR are deleted first, so that only this run's go up; other files in DIR stay |
| `--json` | print a JSON document on stdout; messages go to stderr |
| `-v` | stream the output of `docker build` and of the scanners |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | the scan ran; findings within the gate |
| 1 | the gate in `.tdxguard.yml` was exceeded |
| 2 | a scanner failed, an upload failed, or the tool could not run (login, config, Docker) |

### How the local gate counts

The local gate counts CRITICAL and HIGH findings in the reports:

- CycloneDX (dependencies and images): each vulnerability counts once, at its highest rating.
  With `ignore_unfixed: true`, only vulnerabilities with a fix count. Trivy marks these with
  a `recommendation` ("Upgrade x to version y").
- SARIF (Trivy IaC, image secrets, Opengrep): a rule's `security-severity` of 9.0 or more is
  critical and 7.0 or more is high. If a rule has no score, a CRITICAL or HIGH tag counts. If
  it has neither, level `error` counts as high.
- Betterleaks: every secret counts as high.

This gate is not CI's gate. CI fails on `trivy --severity CRITICAL,HIGH --ignore-unfixed` and
on Opengrep `--severity=ERROR`. The gate that decides about merging is the product's security
gate in TDxGuard. After an upload the tool prints that gate's result. The result reflects the
default branch, not the `local/...` branch you just uploaded. The local gate also counts IaC
misconfigurations and image secrets, so it can be stricter than CI.

## Report

`tdxguard report` writes the security assessment report of a product: the executive summary,
scope and methodology, the standards mapping (ISO/IEC 27001, NIST SSDF, OWASP Top 10), the
findings by kind, the decisions and the control mapping. It is the same document CI writes with
`ci-templates/compliance-report.py` (the CLI carries a byte-identical copy of that generator), in
Vietnamese or English.

```
tdxguard report                                          # project of .tdxguard.yml, default branch, Vietnamese
tdxguard report --lang en --branch develop --out report  # report.html and report.pdf
tdxguard report --product tdx-scribe --open              # opens the PDF when it is written
```

```
$ tdxguard report --product tdx-scribe
> Fetching the findings of tdx-scribe (the default branch) from https://guard.tdadevelop.com
  This takes 10 to 60 seconds on a large product.
    0.8 s  observations (active)
    6.8 s  observations (decided)
   10.6 s  vulnerability checks
   10.8 s  observation logs
  ok Fetched 6437 open and 4240 decided observations of branch main in 25 requests (12.3 s).
> Writing the report (vi)
  6437 open observations, 1259 findings, verdict: action required
  ok Wrote tdx-scribe-security-report-vi.html
> Printing to PDF with Google Chrome
  ok Wrote tdx-scribe-security-report-vi.pdf (29 pages, 1.3 s)
```

It uses the login of `tdxguard login` (or `TDXGUARD_TOKEN`), and the API applies your
permissions: you get the report of a product you are a member of.

**The PDF** is printed by a Chromium-based browser that is already installed, headless and with
a profile of its own (an open browser window is not touched); nothing is downloaded. The report's
print CSS sets A4 and the page numbers. The browser is looked up in this order:

| System | Where |
|---|---|
| all | `TDXGUARD_BROWSER` (a path, or a program on PATH) |
| macOS | Google Chrome, Microsoft Edge, Chromium, Brave in `/Applications` or `~/Applications`; then `chromium`, `google-chrome` on PATH |
| Windows | `chrome.exe`, `msedge.exe`, Chromium, Brave under `%ProgramFiles%`, `%ProgramFiles(x86)%`, `%LocalAppData%`; then `chrome`, `msedge` on PATH (Edge is part of Windows 10 and 11) |
| Linux | `google-chrome`, `google-chrome-stable`, `chromium`, `chromium-browser`, `microsoft-edge`, `microsoft-edge-stable`, `brave-browser` on PATH |

Without a browser the tool writes the HTML and says so (exit code 0): open it and print it to
PDF (A4, without headers and footers), or pass `--open`. When the browser fails or takes more
than three minutes, the HTML stays and the command exits with 2. As root on Linux (containers)
the browser runs with `--no-sandbox`. The snap package of Chromium cannot write outside your
home directory: write the report there, or set `TDXGUARD_BROWSER` to another browser.

| Option | |
|---|---|
| `--product NAME` | default: `project` of `.tdxguard.yml`, or the product of the CI workflow |
| `--branch NAME` / `--all-branches` | default: the product's default branch |
| `--lang vi\|en` | default `vi` |
| `--out PATH` | file name without extension (`.html`/`.pdf` are ignored), or a directory; default `<product>-security-report-<lang>` |
| `--open` | open the PDF, or the HTML without a PDF |
| `--no-pdf`, `--markdown`, `--csv` | HTML only; also `<out>.md`; also every finding as `<out>.csv` |
| `--period-days 7\|30\|90\|365` | reporting period of the changes and the trend (default 30) |
| `--prepared-for`, `--prepared-by`, `--classification` | cover page and page footer |
| `--save-data FILE`, `--from-data FILE` | save the fetched data as JSON; render it again later without the network (another language, for example) |

## Engines: Docker or native

| Engine | Where the scanners run | Needs |
|---|---|---|
| `docker` | in the scanner image `ghcr.io/tda-corp/tdxguard-scanner:v1` | a running Docker daemon |
| `native` | on this machine, from `~/.cache/tdxguard/tools` | nothing (the standalone executable, or Python with pipx); the network once, for the first download |
| `auto` (default) | `docker` when a Docker daemon answers and the scanner image is present or can be pulled, otherwise `native` | |

Choose with `--engine`, else `TDXGUARD_ENGINE`, else `engine:` in `.tdxguard.yml`. Both
engines run the same Python code (the scanner image installs this package and calls
`tdxguard.engine`), the same tool versions and the same rules, so they write the same
reports and the same counts. The summary and `summary.json` (`"engine"`) say which one ran.

**Without Docker** the native engine scans everything except images built from a Dockerfile:
those `images:` entries are skipped with a warning, and the scan goes on. Registry images
(`ref:`) are scanned without Docker. When Docker is there, the native engine still builds
the Dockerfile images and Trivy reads them from the daemon.

**The tools cache.** On first use the native engine downloads Betterleaks 1.9.0, Opengrep
1.31.0 with its rules (opengrep-rules at a pinned commit, only the security directories of
the languages listed under `doctor` above, as in CI), Trivy 0.76.0 and zizmor 1.31.1 into
`~/.cache/tdxguard/tools/<tool>/<version>/` (or `$TDXGUARD_TOOLS_DIR`), about 250 MB. The
rules' install records that language list: when an upgrade changes it (0.1.3 added PHP, Java,
Kotlin, Scala, Ruby, C# and C), the 1 MB rules archive is downloaded and extracted again. Every download is checked against a sha256 pinned in the
package (`tdxguard/engine/tools.py`, the same table the scanner image is built from) before
anything is unpacked, and moved into place only when complete. On Linux, Opengrep's musl
build is used on Alpine and its glibc (manylinux) build elsewhere. zizmor has no musl build:
on Alpine the scan runs without it and says so in its warnings. Trivy's database is shared
with the docker engine in `~/.cache/tdxguard/scanner`.

| Command | |
|---|---|
| `tdxguard tools list [--json]` | the pinned tools, and which are installed |
| `tdxguard tools install [--force]` | download and verify them now, for example before going offline |
| `tdxguard tools clean [--unused]` | delete the tools cache, or only versions that are no longer pinned |

**Platforms.** macOS (arm64, x86_64), Linux (x86_64, aarch64; glibc or musl) and Windows
(x86_64). The code avoids bash, jq, `/tmp`, POSIX paths and executable bits (arguments as
lists, `tempfile`, `pathlib`, `.exe` binaries). The release workflow of the standalone
executables (see [packaging/README.md](packaging/README.md)) runs the unit tests and a full
native scan of a fixture repository on Windows x86_64, macOS (arm64, x86_64) and Linux
(x86_64, arm64) before every release. If the native engine misbehaves on your machine, use
`--engine docker` and please report it.

## CI and scripts

In CI and scripts, skip the login and set the token in the environment:

```
export TDXGUARD_TOKEN=api_token_...          # a TDxGuard API token
export TDXGUARD_SERVER=https://guard.tdadevelop.com
tdxguard scan --branch "$CI_COMMIT_REF_NAME"
```

`TDXGUARD_TOKEN` takes precedence over the credentials file. The CI templates in
`ci-templates/` remain the recommended way to scan in pipelines. They get the token from
OpenBao and need no stored secret.

| Variable | |
|---|---|
| `TDXGUARD_TOKEN`, `TDXGUARD_SERVER` | credentials without `tdxguard login` |
| `TDXGUARD_ENGINE` | `auto`, `docker` or `native` |
| `TDXGUARD_SCANNER_IMAGE` | another scanner image, for example one built locally (docker engine) |
| `TDXGUARD_TOOLS_DIR` | where the native engine keeps its tools (default `~/.cache/tdxguard/tools`) |
| `TDXGUARD_DOCKER_SOCKET` | the Docker socket as the Docker daemon sees it (see below) |
| `TDXGUARD_OIDC_AUTHORITY`, `TDXGUARD_OIDC_CLIENT_ID` | override the server's OIDC settings for `login` |
| `TDXGUARD_CA_BUNDLE` (or `SSL_CERT_FILE`) | a CA bundle for TLS-intercepting proxies |
| `TDXGUARD_BROWSER` | the browser that prints `tdxguard report` to PDF |
| `XDG_CONFIG_HOME`, `XDG_CACHE_HOME` | where credentials and caches live |
| `NO_COLOR` / `FORCE_COLOR` | colours; by default they are used only on a terminal |

## Troubleshooting

**"You are not logged in"**: run `tdxguard login`, or set `TDXGUARD_TOKEN`.

**"TDxGuard rejected the token"**: the token expired after 90 days or was revoked. Run
`tdxguard login` again. `tdxguard whoami` shows the expiry date.

**"Docker is not installed / not running"**: you chose the docker engine (`--engine docker`,
`TDXGUARD_ENGINE` or `engine:`). Start Docker Desktop, OrbStack or Colima, or the Docker
service on Linux; if you get "permission denied" on Linux, add your user to the `docker`
group. Or use `--engine native`.

**"Download failed" on the first native scan**: the tools are downloaded once, from GitHub.
Run `tdxguard tools install` when you are online. Behind a TLS-intercepting proxy, set
`TDXGUARD_CA_BUNDLE`; `HTTPS_PROXY` is honoured.

**"Checksum mismatch"**: the download did not match the pinned sha256, so nothing was
installed. Try again; if it persists, do not work around it, report it.

**The scanner ends without a summary**: run with `-v`. The scanner image may be missing
(`docker pull ghcr.io/tda-corp/tdxguard-scanner:v1`), or the Docker disk may be full
(`docker system df`). Trivy keeps its vulnerability database in `~/.cache/tdxguard/scanner`.

**Image scans cannot reach Docker**: the scanner container talks to the Docker daemon
through its socket. On Linux, the tool takes the socket from `docker context inspect` and
passes its group with `--group-add`. On macOS and Windows, the daemon runs in a VM where the
socket is `/var/run/docker.sock` and belongs to root (group 0). If your setup differs, set
`TDXGUARD_DOCKER_SOCKET` to the socket path as the daemon sees it.

**`--secrets-mode git` refuses to run in a worktree**: in a git worktree, `.git` is a file
that points to a directory outside the repository, and the scanner container cannot see that
directory. Scan from the main checkout instead, or use `--engine native`, which reads the
history where it is.

**"You may not create the project"**: external users can scan only existing projects. Ask a
TDxGuard user to create the project, or use the name of an existing one.

**A brand-new product shows the local branch as its default branch**: TDxGuard makes the
first branch it sees the default branch. To avoid this, let CI scan the real default branch
first, or change the default branch in the product settings.

## Development

```
cd cli
python3 -m unittest              # or, from the repository root: python3 -m unittest discover -s cli/tests -t cli
uvx ruff check . && uvx black --check .
```

The tests use no network and no Docker. `tests/test_counts.py` also runs the jq filters of
`ci-templates/tdxguard-lib.sh` against the Python counts when `jq` is installed (it is skipped
otherwise; the tool itself never needs jq). `tests/test_helpers_in_sync.py` checks that the CI
templates embed exactly `tdxguard/engine/helpers/*.py`, and `tests/test_assessment.py` that
`tdxguard/assessment/compliance_report.py` is identical to `ci-templates/compliance-report.py`
(after changing the script, copy it: `cp ci-templates/compliance-report.py
cli/tdxguard/assessment/compliance_report.py`).
