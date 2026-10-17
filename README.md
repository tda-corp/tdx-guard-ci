# tdx-guard-ci

The reusable TDxGuard security pipeline for GitHub Actions.

**This repository is a publishing target, not the source of truth.** The pipeline
is developed and reviewed in [`tda-corp/tdx-guard`](https://github.com/tda-corp/tdx-guard)
under `ci-templates/github/tdxguard.yml`, alongside the TDxGuard instance that
receives its results. Edit it there and republish; a change made directly here
will be overwritten.

## Using it

Projects do not copy the pipeline. They add a short caller at
`.github/workflows/tdxguard.yml`:

```yaml
name: tdxguard
on: [push, pull_request]

permissions:
  contents: read
  id-token: write        # without this the CI cannot obtain an OpenBao token
  security-events: write # findings as annotations on the pull request diff
  pull-requests: write   # the summary comment on the pull request

jobs:
  tdxguard:
    uses: tda-corp/tdx-guard-ci/.github/workflows/tdxguard.yml@v1
    with:
      product: <product name in TDxGuard>
      bao_role: ci-<project>
```

All four permissions are required. A called workflow may not request more than its
caller grants, and this pipeline declares all four — leave one out and GitHub refuses
the run before it starts, reporting `startup_failure` with no logs to read.

`bao_role` is handed out by the platform team when the project is onboarded with
`openbao-stack/bootstrap/onboard-project.sh`. The pipeline holds no static secret:
it trades the CI's own OIDC identity for a short-lived OpenBao token and reads the
TDxGuard API token from there.

See `ci-templates/README.md` in tdx-guard for every input and for the local runner
that reproduces the same scans on a workstation.

## The `tdxguard` command line tool

`cli/` holds the same tool as `cli/` in `tda-corp/tdx-guard`, published here so it can be
installed without access to that repository. It runs the pipeline's scans on a developer's
machine and uploads the results to TDxGuard, with or without Docker:

```sh
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/tda-corp/tdx-guard-ci/main/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/tda-corp/tdx-guard-ci/main/install.ps1 | iex
```

Or with Python: `pipx install "git+https://github.com/tda-corp/tdx-guard-ci#subdirectory=cli"`.

```sh
tdxguard login     # TDxSSO in the browser
tdxguard init      # writes .tdxguard.yml
tdxguard scan      # scans and uploads to TDxGuard
```

See [`cli/README.md`](cli/README.md). A release is cut by pushing a `cli-vX.Y.Z` tag
matching the package version: `.github/workflows/cli-release.yml` builds the standalone
executables for macOS, Linux and Windows, tests each on its own OS, and publishes them
with a `checksums.txt`.
