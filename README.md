# tdxguard-ci

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
    uses: tda-corp/tdxguard-ci/.github/workflows/tdxguard.yml@v1
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
