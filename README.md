# security-workflows

One reusable GitHub Actions workflow that security-scans a repository, private
ones included, with open-source tools only: no account, no token, no line limit.

| Job | Tool | Finds | Fails the job on |
|---|---|---|---|
| `semgrep` | [Semgrep CE](https://github.com/semgrep/semgrep) | Insecure code (SAST): TS/JS, React, Next.js, Python, Dockerfiles | `CRITICAL`, `HIGH`, `ERROR` (configurable) |
| `trivy` | [Trivy](https://github.com/aquasecurity/trivy) | Known vulnerabilities in lock files, misconfigured Dockerfiles | `CRITICAL` with a fixed version available |
| `gitleaks` | [Gitleaks](https://github.com/gitleaks/gitleaks) | Secrets anywhere in the git history | any finding |

Everything else is still listed in the job log and the run's summary page, and
each job uploads its raw JSON report as an artifact (kept 14 days).

Results do not appear in the repo's Security tab: uploading SARIF there needs
GitHub Advanced Security on private repos. Dependabot alerts and security
updates do not, and complement this; keep them enabled.

## Use

`.github/workflows/security.yml` in the repo to scan:

```yaml
name: Security

on:
  pull_request:
  push:
    branches: [master]
  # New CVEs are published against code that has not changed.
  schedule:
    - cron: "23 5 * * 1"
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: security-${{ github.ref }}
  cancel-in-progress: true

jobs:
  scan:
    uses: sebiweise/security-workflows/.github/workflows/scan.yml@<commit-sha> # v1.0.0
```

Pin the commit SHA like any other action; the repo's Dependabot
`github-actions` entry then bumps it on every new release tag here.

This repo is public, so any repo, private or not and under any account, can
call it. To change the rules for your own repos, fork it and point `uses:` at
the fork.

### Inputs

| Input | Default | |
|---|---|---|
| `semgrep`, `trivy`, `gitleaks` | `true` | Set to `false` to skip a job, e.g. `gitleaks: false` where it already runs elsewhere. |
| `semgrep-rules` | `p/default p/owasp-top-ten p/typescript p/react p/nextjs p/python p/dockerfile` | [Registry](https://semgrep.dev/explore) rulesets. |
| `semgrep-fail-on` | `CRITICAL HIGH ERROR` | Semgrep severities that fail the job. |

### False positives

| Tool | Suppress with |
|---|---|
| Semgrep | `// nosemgrep: <rule-id>` on the line, or a path in `.semgrepignore` |
| Trivy | The finding's ID (e.g. `CVE-2026-12345`) on a line of `.trivyignore` |
| Gitleaks | The fingerprint from the log on a line of `.gitleaksignore`. A real leaked secret has to be rotated; ignoring it does not un-leak it. |

## Maintenance

The three tools run from their official images, pinned by tag and digest in
`scan.yml`. Dependabot does not see those, so bump them by hand:

```sh
docker buildx imagetools inspect semgrep/semgrep:<version>
docker buildx imagetools inspect ghcr.io/aquasecurity/trivy:<version>
docker buildx imagetools inspect ghcr.io/gitleaks/gitleaks:<version>
```

Then tag a release (`v1.0.1`, ...) so the calling repos get a Dependabot PR.
