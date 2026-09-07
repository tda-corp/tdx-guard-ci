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

jobs:
  tdxguard:
    uses: tda-corp/tdxguard-ci/.github/workflows/tdxguard.yml@v1
    with:
      product: <product name in TDxGuard>
      bao_role: ci-<project>
```

`bao_role` is handed out by the platform team when the project is onboarded with
`openbao-stack/bootstrap/onboard-project.sh`. The pipeline holds no static secret:
it trades the CI's own OIDC identity for a short-lived OpenBao token and reads the
TDxGuard API token from there.

See `ci-templates/README.md` in tdx-guard for every input and for the local runner
that reproduces the same scans on a workstation.
