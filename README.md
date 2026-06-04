# MEBlabs Security Workflow

[![quality](https://github.com/meblabs/security-workflow/actions/workflows/quality.yml/badge.svg)](https://github.com/meblabs/security-workflow/actions/workflows/quality.yml)
![type](https://img.shields.io/badge/github-Reusable%20Workflow-purple?logo=github)
[![](https://img.shields.io/static/v1?label=MEBlabs&message=%E2%9D%A4&logo=GitHub&color=%23fe8e86)](https://github.com/sponsors/meblabs)

Reusable GitHub Actions workflow for the MEBlabs open-source security gate.

This repository is designed to be used after [meblabs/npm-pull-request-action](https://github.com/meblabs/npm-pull-request-action), but it is independent from that composite action. The npm quality action remains responsible for checkout, Node setup, `npm ci`, Prettier, lockfile audit remediation, ESLint, Jest, and downstream coordination outputs. This workflow only runs security checks against the exact ref passed by the caller.

## Coverage

The workflow currently covers:

- Semgrep CE SAST.
- Gitleaks OSS secret scanning.
- Trivy filesystem SCA for OS and library vulnerabilities.
- Trivy config scanning for IaC, Dockerfile, and workflow misconfiguration.
- `cfn-lint` for AWS SAM and CloudFormation templates.
- `zizmor` for GitHub Actions workflow and action security.
- Optional Docker image build and Trivy image vulnerability scan.
- Filesystem and Docker image CycloneDX SBOM generation.
- Dependency license report.
- One consolidated pull request security summary with failure details.
- `security-reports` artifact upload.
- Final security gate after all reports are collected.

## Security Checks

The workflow checks out the caller repository at the exact `ref` provided by the caller before running any scanner. It does not run `npm ci`, does not modify caller files, and does not commit changes. Scanner failures are collected first; the job fails only at the final security gate.

### Semgrep CE SAST

Semgrep runs on every invocation and performs static application security testing on source files. It uses the Docker image configured by `semgrep-version` and the rulesets configured by `security-config`.

By default `security-config` is `auto`, so Semgrep chooses relevant community rules based on the repository contents. Callers can pass a space-separated ruleset list such as `p/javascript p/typescript p/owasp-top-ten`.

The `security-severity-threshold` input controls which Semgrep severities are considered blocking:

- `low` or `info` includes INFO, WARNING, and ERROR.
- `medium` or `warning` includes WARNING and ERROR.
- `high`, `error`, or `critical` includes ERROR only.

The workflow writes `security-reports/semgrep.sarif`. If Semgrep fails on a pull request, the workflow posts SARIF findings using the bot `token`. Semgrep is a blocking check.

### Gitleaks Secret Scanning

Gitleaks runs on every invocation and scans for committed secrets such as API keys, tokens, private keys, credentials, and high-confidence secret patterns.

The workflow intentionally scans only files tracked by git. It creates a temporary archive from `git ls-files` and scans that isolated directory. This avoids false positives from generated files, local caches, scanner output, dependency folders, and other untracked working-directory content.

The workflow writes `security-reports/gitleaks.sarif` with redacted findings. If Gitleaks fails on a pull request, the workflow posts SARIF findings using the bot `token`. Gitleaks is a blocking check.

### Trivy Filesystem SCA

Trivy filesystem SCA runs on every invocation and scans dependency and OS package metadata present in the repository. It checks manifests and lockfiles without installing dependencies, so it avoids duplicating the npm quality gate.

The scan uses:

- `scanners: vuln`
- `vuln-type: os,library`
- `ignore-unfixed: true`
- severities from `security-vulnerability-severities`, defaulting to `HIGH,CRITICAL`
- skipped directories from `security-skip-dirs`

The workflow writes `security-reports/trivy-fs.sarif`. If Trivy finds blocking vulnerabilities on a pull request, the workflow posts SARIF findings using the bot `token`. Trivy filesystem SCA is a blocking check.

### Trivy Config And IaC Misconfiguration

Trivy config scan runs on every invocation and checks infrastructure and configuration files for misconfigurations. This includes supported IaC formats, Dockerfiles, Kubernetes manifests, Terraform files, CloudFormation/SAM files, and GitHub Actions workflow files when Trivy recognizes them.

The scan uses severities from `security-vulnerability-severities`, skips directories from `security-skip-dirs`, and writes `security-reports/trivy-config.sarif`.

This check is broad and always runs. Dedicated `cfn-lint` and `zizmor` checks still run separately when their specific target files exist. Trivy config scan is a blocking check.

### cfn-lint SAM And CloudFormation Validation

`cfn-lint` runs only when the repository contains `template.yaml` or `template.yml` outside skipped dependency and git directories.

It validates AWS SAM and CloudFormation templates for structural errors, invalid resource properties, unsupported values, and template issues that CloudFormation would reject or warn about. The workflow installs `cfn-lint[sarif]` in a temporary Python virtual environment and runs it with `--non-zero-exit-code error`.

The workflow writes textual output to `security-reports/cfn-lint.txt` and includes the first 200 lines in the GitHub Step Summary. `cfn-lint` is a blocking check only when templates are detected; otherwise it is reported as `NA`.

### zizmor GitHub Actions Security

`zizmor` runs only when the repository contains GitHub Actions workflow or action files:

- `.github/workflows/*.yml`
- `.github/workflows/*.yaml`
- `action.yml`
- `action.yaml`

It scans workflow and action definitions for security issues such as unsafe permissions, risky trigger patterns, script injection surfaces, untrusted checkout/use patterns, and other GitHub Actions hardening findings.

When `github-token` is available, the workflow passes it as `GH_TOKEN` so `zizmor` can perform API-backed checks. Otherwise it can run in offline mode, but in this workflow `github-token` is required by the reusable workflow contract.

By default, the workflow runs `zizmor` with a generated config that relaxes `unpinned-uses` for common trusted action namespaces:

```yml
rules:
  unpinned-uses:
    config:
      policies:
        meblabs/*: ref-pin
        actions/*: ref-pin
        aws-actions/*: ref-pin
```

Set `zizmor-config` in the reusable workflow, or pass `--zizmor-config PATH` locally, to replace this built-in config with a repository-specific `zizmor.yml`.

The workflow writes `security-reports/zizmor.txt` and includes the first 200 lines in the GitHub Step Summary. Exit code `3` is treated as reportable findings rather than a blocking failure according to the current operational policy. `zizmor` is a blocking check only when workflow/action files are detected; otherwise it is reported as `NA`.

### Docker Image Build

The Docker image build runs only when the configured `dockerfile-path` exists, defaulting to `Dockerfile`.

The workflow builds a local image using:

- `dockerfile-path`
- `docker-build-context`
- optional newline-separated `docker-build-args`
- local tag `${{ inputs.docker-image-name }}:${{ github.sha }}`

The resulting image reference is written to `security-reports/docker-image-ref.txt`. The build is a blocking check when the configured Dockerfile exists. If no configured Dockerfile exists, Docker image build and image scanning are reported as `NA`.

### Trivy Docker Image Vulnerability Scan

Trivy image scan runs only when the configured Dockerfile exists and the Docker image build succeeds.

It scans the locally built image for OS and library vulnerabilities using the same severity threshold as filesystem SCA. The scan uses `ignore-unfixed: true` and writes `security-reports/trivy-image.sarif`.

If Trivy finds blocking image vulnerabilities on a pull request, the workflow posts SARIF findings using the bot `token`. Trivy Docker image scan is a blocking check only when image build applies and succeeds.

### Trivy License Report

The license report runs on every invocation and uses Trivy's license scanner over the repository filesystem.

It records dependency license information in `security-reports/trivy-license.txt`. This output is informational and does not fail the final security gate.

### Filesystem SBOM

The filesystem SBOM runs on every invocation and uses Trivy to generate a CycloneDX SBOM for repository dependencies and detected components.

The workflow writes `security-reports/sbom-fs.cdx.json`. SBOM generation is informational and does not fail the final security gate.

### Docker Image SBOM

The Docker image SBOM runs only when the configured Dockerfile exists and the Docker image build succeeds.

It generates a CycloneDX SBOM for the locally built image and writes `security-reports/sbom-image.cdx.json`. Docker image SBOM generation is informational and does not fail the final security gate.

### Pull Request Reporting

When the workflow runs on a pull request, it publishes one consolidated summary comment using the bot `token`. The comment is marked with `<!-- meblabs-security-workflow:summary -->`.

The consolidated comment includes the check table and expandable details for scanner failures. SARIF-producing scanners are summarized from their SARIF files, including rule, level, source location, message, and help link where available. `cfn-lint` and `zizmor` text output is also included in expandable sections.

The consolidated comment is idempotent: the workflow updates the previous marked comment instead of creating a new one on every run. Its table has only `Check` and `Outcome` columns. Outcomes are rendered as green `PASS`, red `FAIL`, or grey `NA` badges. `NA` means that the check was not applicable to the scanned repository, for example Docker image scanning when the configured Dockerfile does not exist.

GitHub issue comments have a maximum body size. The workflow includes failure details directly in the PR comment under normal report sizes and truncates oversized sections with a note if needed. The comment links the uploaded `security-reports` artifact so the full files remain one click away.

### Artifact And Step Summary

The workflow always prepares `security-reports/security-summary.md` and writes a security table to the GitHub Step Summary. The Step Summary uses the same `PASS`, `FAIL`, and `NA` outcomes as the PR comment. When `upload-artifact` is enabled, it uploads the full `security-reports` directory as the `security-reports` artifact and links it from the PR comment.

Artifact upload and PR comments are non-blocking. They use `continue-on-error: true` so report publication problems do not hide scanner outcomes.

## Inputs

| Input | Required | Default | Description |
|---|---:|---|---|
| `ref` | yes | n/a | Git ref, branch, tag, or SHA to scan. The workflow checks out this ref explicitly. |
| `node-version` | no | `22.x` | Node.js version used when npm metadata is needed. |
| `security-config` | no | `auto` | Semgrep config/rulesets. Use `auto` or a space-separated list such as `p/javascript p/typescript p/owasp-top-ten`. |
| `security-severity-threshold` | no | `high` | Minimum Semgrep severity that fails the gate: `low`, `medium`, or `high` and aliases `info`, `warning`, `error`, `critical`. |
| `security-vulnerability-severities` | no | `HIGH,CRITICAL` | Comma-separated Trivy severities that fail the gate. |
| `security-skip-dirs` | no | `node_modules,.git,.security-workflow,security-reports,coverage,dist,build,.next,.nuxt` | Directories skipped by Trivy filesystem and config scans. |
| `semgrep-version` | no | `latest` | Semgrep Docker image tag. |
| `trivy-version` | no | `v0.71.0` | Trivy CLI version used by the local Trivy Docker image. |
| `gitleaks-version` | no | `v8.30.1` | Gitleaks Docker image tag. |
| `zizmor-version` | no | `v1.25.2` | zizmor Docker image tag. |
| `zizmor-config` | no | built-in MEBlabs policy | Optional repository-relative zizmor config file replacing the built-in policy. |
| `dockerfile-path` | no | `Dockerfile` | Dockerfile path used for optional Docker image build and scan. |
| `docker-build-context` | no | `.` | Docker build context used for optional Docker image build and scan. |
| `docker-build-args` | no | empty | Optional newline-separated Docker build args in `KEY=VALUE` format. |
| `docker-image-name` | no | `meblabs-security-scan` | Local Docker image name used for security scanning. |
| `post-pr-comment` | no | `true` | Post or update a consolidated security summary comment on pull requests. |
| `upload-artifact` | no | `true` | Upload security reports as a workflow artifact. |
| `artifact-retention-days` | no | `14` | Retention days for the `security-reports` artifact. |

## Tokens And Secrets

This workflow uses two reusable workflow secrets with separate responsibilities:

| Purpose | Secret | Required | Recommended value |
|---|---|---:|---|
| Consolidated PR summary comments | `token` | yes | `${{ secrets.MEBBOT }}` |
| Checkout and read/API-backed scanner checks such as authenticated `zizmor` runs | `github-token` | yes | `${{ secrets.GITHUB_TOKEN }}` |

Use the same bot fine-grained PAT or GitHub App token used by `meblabs/npm-pull-request-action` for `token`. Use the default `GITHUB_TOKEN` for `github-token`, because checkout and read-oriented scanner API calls do not need the bot PAT.

## Required Permissions

The caller should grant permissions compatible with the reusable workflow:

```yml
permissions:
  contents: read
  actions: read
```

These are the caller job permissions for `GITHUB_TOKEN`. The `MEBBOT` token must also have matching repository access for the PR comment API calls it performs.

Minimum recommended fine-grained PAT repository permissions for `MEBBOT` in this security workflow:

| Permission | Access | Used for |
|---|---|---|
| Metadata | Read | Required by GitHub for repository access. |
| Pull requests | Read and write | Read pull request metadata when needed by the bot token. |
| Issues | Read and write | Create or update the consolidated PR summary comment, because PR conversation comments use the Issues API. |

This workflow does not need the `MEBBOT` PAT to have access to contents, actions, commit statuses, checks, discussions, merge queues, repository advisories, secrets, workflows, administration, or security events. `security-events: write` is only needed if a future version uploads SARIF into GitHub code scanning instead of only storing SARIF as artifacts and summarizing it in the PR comment.

## Local Usage From An Application Repository

The same scanner and gate logic can run locally before opening a pull request. The recommended setup for an application repository is to commit only a small bootstrap script and cache this repository under a gitignored internal directory.

Add the local cache directory to the application repository `.gitignore`:

```gitignore
.security-workflow/
```

Add a bootstrap script, for example `security-workflow.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

VERSION="${SECURITY_WORKFLOW_VERSION:-v1}"
CACHE_ROOT="${SECURITY_WORKFLOW_CACHE_DIR:-.security-workflow}"
INSTALL_DIR="${CACHE_ROOT}"
VERSION_FILE="${INSTALL_DIR}/VERSION"
ARCHIVE_URL="https://github.com/meblabs/security-workflow/archive/refs/tags/${VERSION}.tar.gz"

if [[ ! -x "${INSTALL_DIR}/bin/security-workflow" ]] || [[ ! -f "${VERSION_FILE}" ]] || [[ "$(cat "${VERSION_FILE}")" != "${VERSION}" ]]; then
  rm -rf "${INSTALL_DIR}"
  mkdir -p "${INSTALL_DIR}"

  curl -fsSL "${ARCHIVE_URL}" \
    | tar -xz -C "${INSTALL_DIR}" --strip-components=1

  echo "${VERSION}" > "${VERSION_FILE}"
fi

exec "${INSTALL_DIR}/bin/security-workflow" \
  --repo "$PWD" \
  --ref "${SECURITY_WORKFLOW_REF:-HEAD}" \
  --reports-dir "${CACHE_ROOT}/security-reports" \
  "$@"
```

`--repo "$PWD"` can point either to a Git repository root or to a subdirectory inside a Git worktree. The scan scope remains the path passed with `--repo`.

Add an npm script:

```json
{
  "scripts": {
    "security": "bash security-workflow.sh"
  }
}
```

Run the local security gate:

```bash
npm run security
```

Console results use green `PASS`, red `FAIL`, and yellow `SKIP` labels by default. Set `NO_COLOR=1` or `SECURITY_WORKFLOW_COLOR=never` to disable colors.

Pass CLI options after `--`:

```bash
npm run security -- --security-severity-threshold medium
npm run security -- --zizmor-config zizmor.yml
```

Run only selected local checks while iterating on a specific class of findings:

```bash
npm run security -- --only semgrep,gitleaks
npm run security -- --only trivy-fs,trivy-config
npm run security -- --only docker
npm run security -- --skip docker,sbom,license
```

`--only` and `--skip` accept comma-separated check names or groups:

| Selector | Runs or skips |
|---|---|
| `semgrep` | Semgrep SAST |
| `gitleaks` | Gitleaks secrets |
| `trivy-fs` | Trivy filesystem vulnerability scan |
| `trivy-config` | Trivy IaC/config misconfiguration scan |
| `cfn-lint` | AWS SAM/CloudFormation validation |
| `zizmor` | GitHub Actions security scan |
| `docker-build` | Docker image build |
| `trivy-image` | Trivy Docker image vulnerability scan |
| `license` | Trivy license report |
| `sbom` | Filesystem and Docker image SBOM |
| `docker` | Docker build, image scan, and image SBOM |
| `trivy` | All Trivy-backed checks and reports |
| `all` | Every local check |

When a check is excluded by `--only` or `--skip`, it is reported as `NA` and does not fail the local gate. GitHub Actions does not pass these options, so pull requests still run the full security gate.

Use the same tag locally and in GitHub Actions. For example, if the pull request workflow uses:

```yml
uses: meblabs/security-workflow/.github/workflows/security.yml@v1
```

then local runs should use:

```bash
SECURITY_WORKFLOW_VERSION=v1 npm run security
```

The local CLI writes reports inside the gitignored cache directory:

```text
.security-workflow/security-reports/
```

This does not affect the GitHub Action. The reusable workflow does not pass `--reports-dir`, so it keeps using the default `security-reports/` path required by artifact upload and PR comments.

Local requirements are `git`, `docker`, `curl`, and `tar`. `node` generates the SARIF findings overview, and `jq` normalizes SARIF metadata when available. `python3` is required only when `cfn-lint` applies because the repository contains SAM or CloudFormation templates.

In GitHub Actions, the reusable workflow checks out its own CLI scripts from the same repository and ref used by the caller's `uses: meblabs/security-workflow/.github/workflows/security.yml@...` line. No extra input is needed to keep the workflow YAML and local CLI scripts aligned.

## Usage Standalone

```yml
name: Security

on:
  pull_request:
    branches: [release, staging, dev]

jobs:
  security:
    name: Security Gate
    uses: meblabs/security-workflow/.github/workflows/security.yml@v1
    permissions:
      contents: read
      actions: read
    with:
      ref: ${{ needs.quality.outputs.current-head-sha }}
      repository: ${{ github.repository }}
      pr-number: ${{ github.event.pull_request.number }}
      head-ref: ${{ github.head_ref }}
    secrets:
      token: ${{ secrets.MEBBOT }}
      github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Usage With `meblabs/npm-pull-request-action`

Use the quality action first. Invoke this security workflow only when the quality action did not modify formatting or audit lockfiles, and pass the `current-head-sha` output as `ref`.

```yml
name: PullRequest

on:
  pull_request:
    branches: [release, staging, dev]

jobs:
  quality:
    name: Quality Gate
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      checks: write
      pull-requests: write
      contents: write
      issues: write
    outputs:
      prettier-changed: ${{ steps.quality.outputs.prettier-changed }}
      audit-changed: ${{ steps.quality.outputs.audit-changed }}
      current-head-sha: ${{ steps.quality.outputs.current-head-sha }}
    steps:
      - id: quality
        name: NPM pull request quality gate
        uses: meblabs/npm-pull-request-action@v4
        with:
          token: ${{ secrets.MEBBOT }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
          node-version: 22.x
          prettier: true
          eslint: true
          audit: true
          audit-level: high
          test: true

  security:
    name: Security Gate
    needs: quality
    if: |
      needs.quality.outputs.prettier-changed != 'true' &&
      needs.quality.outputs.audit-changed != 'true'
    uses: meblabs/security-workflow/.github/workflows/security.yml@v1
    permissions:
      contents: read
      actions: read
    with:
      ref: ${{ needs.quality.outputs.current-head-sha }}
      repository: ${{ github.repository }}
      pr-number: ${{ github.event.pull_request.number }}
      head-ref: ${{ github.head_ref }}
    secrets:
      token: ${{ secrets.MEBBOT }}
      github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Reports And Artifacts

The workflow creates `security-reports/security-summary.md` on every run. When enabled, it uploads the whole `security-reports` directory as the `security-reports` artifact.

Typical files include:

- `security-summary.md`
- `semgrep.sarif`
- `gitleaks.sarif`
- `trivy-fs.sarif`
- `trivy-config.sarif`
- `trivy-image.sarif`
- `trivy-license.txt`
- `sbom-fs.cdx.json`
- `sbom-image.cdx.json`
- `cfn-lint.txt`
- `zizmor.txt`
- `zizmor.yml`
- `docker-image-ref.txt`

The GitHub Step Summary receives the same security table as the artifact summary. On pull requests, the workflow updates a single consolidated PR comment marked with:

```text
<!-- meblabs-security-workflow:summary -->
```

Scanner details are included in that single consolidated comment. SARIF files are parsed into `security-reports/sarif-findings-summary.md`, and text reports such as `cfn-lint.txt` and `zizmor.txt` are attached as expandable sections.

## Failure Policy

Blocking checks run with `continue-on-error: true` so every scanner can finish and publish reports. The job fails only in the final `Fail security gate if blocking checks failed` step when an applicable blocking check failed, was cancelled, was skipped unexpectedly, or produced an unknown outcome.

Blocking checks:

- Semgrep SAST.
- Gitleaks secrets.
- Trivy filesystem SCA.
- Trivy IaC/config scan.
- `cfn-lint`, only when `template.yaml` or `template.yml` files exist.
- `zizmor`, only when GitHub workflow or action files exist.
- Docker image build, only when the configured Dockerfile exists.
- Trivy Docker image scan, only when the configured Dockerfile exists and the image build succeeds.

Non-blocking outputs:

- Trivy license report.
- Filesystem SBOM.
- Docker image SBOM.
- PR comments and artifact upload.

Missing optional targets are reported as `NA`, not as failures.

## Troubleshooting

If the workflow scans the wrong commit, check the caller's `ref` input. With `meblabs/npm-pull-request-action`, pass `needs.quality.outputs.current-head-sha` and run this workflow only when `prettier-changed` and `audit-changed` are not `true`.

If PR comments are missing, verify that `token` is passed from `${{ secrets.MEBBOT }}` and that the bot PAT has Pull requests read/write and Issues read/write. Reusable workflows called from non-PR events do not post PR comments.

If using a fine-grained PAT, the current broad permission set with read access to metadata and secrets plus read/write access to actions, code, commit statuses, discussions, issues, merge queues, pull requests, repository advisories, security events, and workflows is sufficient for this workflow. It is broader than needed. For this workflow alone, reduce `MEBBOT` to Metadata read, Pull requests read/write, and Issues read/write.

If Docker scanning is skipped, confirm that `dockerfile-path` points to an existing file in the scanned ref. The image scan only runs after a successful local Docker build.

If `cfn-lint` is skipped, confirm the templates are named `template.yaml` or `template.yml`. Other CloudFormation filenames are still covered by Trivy config scanning, but they do not trigger the dedicated `cfn-lint` step.

If `zizmor` is skipped, confirm the repository contains `.github/workflows/*.yml`, `.github/workflows/*.yaml`, `action.yml`, or `action.yaml`.

If a scanner reports findings but later steps still run, that is expected. The workflow collects all reports first and applies the final gate at the end.
