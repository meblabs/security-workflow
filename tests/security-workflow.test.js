#!/usr/bin/env node

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { repositoryRoot, runBash, shellQuote } = require('./test-helpers');

test('SARIF summary separates accepted suppressions from active findings', (t) => {
  const reportsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'security-workflow-sarif-'));
  t.after(() => fs.rmSync(reportsDir, { recursive: true, force: true }));

  const sarif = {
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'Semgrep',
          rules: [
            { id: 'active-rule', shortDescription: { text: 'Active' } },
            { id: 'suppressed-rule', shortDescription: { text: 'Suppressed' } },
            { id: 'rejected-rule', shortDescription: { text: 'Rejected' } },
            { id: 'review-rule', shortDescription: { text: 'Under review' } },
          ],
        },
      },
      results: [
        { ruleId: 'active-rule', level: 'error', message: { text: 'Active finding' } },
        {
          ruleId: 'suppressed-rule',
          level: 'warning',
          message: { text: 'Suppressed finding' },
          suppressions: [{ kind: 'inSource', justification: 'Accepted risk' }],
        },
        {
          ruleId: 'rejected-rule',
          level: 'error',
          message: { text: 'Rejected suppression' },
          suppressions: [{ kind: 'external', status: 'rejected' }],
        },
        {
          ruleId: 'review-rule',
          level: 'warning',
          message: { text: 'Suppression under review' },
          suppressions: [{ kind: 'external', status: 'underReview' }],
        },
      ],
    }],
  };

  fs.writeFileSync(path.join(reportsDir, 'semgrep.sarif'), JSON.stringify(sarif));

  const result = spawnSync(process.execPath, [
    path.join(repositoryRoot, 'scripts/sarif-findings-summary.js'),
    '--reports-dir',
    reportsDir,
  ], { encoding: 'utf8' });

  assert.equal(result.status, 0, result.stderr);
  const summary = fs.readFileSync(path.join(reportsDir, 'sarif-findings-summary.md'), 'utf8');
  assert.match(summary, /\| Scanner \| Status \| Active \| Suppressed \|/);
  assert.match(summary, /\| Semgrep SAST \| findings \| 3 \| 1 \|/);
  assert.match(summary, /Active findings: 3/);
  assert.match(summary, /Suppressed findings: 1/);
  assert.match(summary, /inSource: Accepted risk/);
});

test('SARIF summary reports clean when every finding is suppressed', (t) => {
  const reportsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'security-workflow-sarif-clean-'));
  t.after(() => fs.rmSync(reportsDir, { recursive: true, force: true }));

  fs.writeFileSync(path.join(reportsDir, 'gitleaks.sarif'), JSON.stringify({
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'Gitleaks' } },
      results: [{
        ruleId: 'ignored-secret',
        suppressions: [{ kind: 'external', status: 'accepted' }],
      }],
    }],
  }));

  const result = spawnSync(process.execPath, [
    path.join(repositoryRoot, 'scripts/sarif-findings-summary.js'),
    '--reports-dir',
    reportsDir,
  ], { encoding: 'utf8' });

  assert.equal(result.status, 0, result.stderr);
  const summary = fs.readFileSync(path.join(reportsDir, 'sarif-findings-summary.md'), 'utf8');
  assert.match(summary, /\| Gitleaks secrets \| clean \| 0 \| 1 \|/);
});

test('Trivy blocking scans pass the repository YAML ignore file explicitly', (t) => {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'security-workflow-trivy-'));
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));

  const fakeBin = path.join(fixtureRoot, 'bin');
  const repo = path.join(fixtureRoot, 'repo');
  const reports = path.join(fixtureRoot, 'reports');
  const dockerArgs = path.join(fixtureRoot, 'docker-args.txt');
  fs.mkdirSync(fakeBin);
  fs.mkdirSync(repo);
  fs.mkdirSync(reports);
  fs.mkdirSync(path.join(repo, 'nested/build'), { recursive: true });
  fs.mkdirSync(path.join(repo, 'deploy/.aws-sam'), { recursive: true });
  fs.writeFileSync(path.join(repo, '.trivyignore.yaml'), 'vulnerabilities: []\n');
  fs.writeFileSync(path.join(fakeBin, 'docker'), [
    '#!/usr/bin/env bash',
    '{',
    "  printf '%s\\n' '---'",
    "  printf '%s\\n' \"$@\"",
    '} >> "$DOCKER_ARGS_FILE"',
  ].join('\n'));
  fs.chmodSync(path.join(fakeBin, 'docker'), 0o755);

  runBash([
    'set -euo pipefail',
    `source ${shellQuote(path.join(repositoryRoot, 'lib/security-workflow/common.sh'))}`,
    `source ${shellQuote(path.join(repositoryRoot, 'lib/security-workflow/scanners.sh'))}`,
    'security_workflow_trivy_fs',
    'security_workflow_trivy_config',
    'security_workflow_trivy_image',
  ].join('\n'), {
    cwd: repo,
    env: {
      DOCKER_ARGS_FILE: dockerArgs,
      PATH: `${fakeBin}:${process.env.PATH}`,
      SECURITY_WORKFLOW_DOCKER_IMAGE_REF: 'fixture:image',
      SECURITY_WORKFLOW_REPORTS_DIR: reports,
      SECURITY_WORKFLOW_REPO: repo,
      SECURITY_WORKFLOW_SECURITY_SKIP_DIRS: 'build,**/build,.aws-sam,**/.aws-sam',
      SECURITY_WORKFLOW_SECURITY_VULNERABILITY_SEVERITIES: 'HIGH,CRITICAL',
      SECURITY_WORKFLOW_TRIVY_VERSION: 'v0.71.0',
    },
  });

  const calls = fs.readFileSync(dockerArgs, 'utf8').split('---\n').filter(Boolean);
  assert.equal(calls.length, 3);
  for (const call of calls) {
    assert.match(call, /--ignorefile\n\/\.trivyignore\.yaml\n/);
    assert.match(call, new RegExp(`${repo.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/\\.trivyignore\\.yaml:\\/\\.trivyignore\\.yaml:ro`));
  }
  assert.match(calls[0], /--skip-dirs\n\*\*\/\.aws-sam\n/);
  assert.match(calls[1], /--skip-dirs\n\*\*\/build\n/);
});

test('SAM target detection ignores root and nested .aws-sam build output', (t) => {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'security-workflow-targets-'));
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));

  const reports = path.join(fixtureRoot, 'reports');
  fs.mkdirSync(reports);
  fs.writeFileSync(path.join(reports, 'security-summary.md'), '');
  fs.writeFileSync(path.join(fixtureRoot, 'template.yaml'), 'Resources: {}\n');
  fs.mkdirSync(path.join(fixtureRoot, '.aws-sam/build'), { recursive: true });
  fs.writeFileSync(path.join(fixtureRoot, '.aws-sam/build/template.yaml'), 'Resources: {}\n');
  fs.mkdirSync(path.join(fixtureRoot, 'deploy/.aws-sam/build'), { recursive: true });
  fs.writeFileSync(path.join(fixtureRoot, 'deploy/.aws-sam/build/template.yml'), 'Resources: {}\n');

  const output = runBash([
    'set -euo pipefail',
    `source ${shellQuote(path.join(repositoryRoot, 'lib/security-workflow/targets.sh'))}`,
    'security_workflow_detect_targets',
    "printf '%s:%s\\n' \"$SAM_TEMPLATES_COUNT\" \"$SAM_TEMPLATES\"",
  ].join('\n'), {
    cwd: fixtureRoot,
    env: {
      SECURITY_WORKFLOW_DOCKERFILE_PATH: 'Dockerfile',
      SECURITY_WORKFLOW_REPORTS_DIR: reports,
    },
  });

  assert.equal(output.trim(), '1:true');
});

test('cfn-lint virtualenv health requires executable, import, and exact version', (t) => {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'security-workflow-cfn-'));
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));

  const binDir = path.join(fixtureRoot, 'bin');
  fs.mkdirSync(binDir);
  fs.writeFileSync(path.join(binDir, 'python'), [
    '#!/usr/bin/env bash',
    '[[ "${FAKE_CFN_IMPORT_OK:-false}" == "true" ]] || exit 1',
    'printf "%s\\n" "${FAKE_CFN_VERSION:-}"',
  ].join('\n'));
  fs.writeFileSync(path.join(binDir, 'cfn-lint'), [
    '#!/usr/bin/env bash',
    '[[ "${FAKE_CFN_CLI_OK:-false}" == "true" ]]',
  ].join('\n'));
  fs.chmodSync(path.join(binDir, 'python'), 0o755);
  fs.chmodSync(path.join(binDir, 'cfn-lint'), 0o755);

  const healthCommand = [
    'set -euo pipefail',
    `source ${shellQuote(path.join(repositoryRoot, 'lib/security-workflow/scanners.sh'))}`,
    `security_workflow_cfn_lint_venv_healthy ${shellQuote(fixtureRoot)}`,
  ].join('\n');

  runBash(healthCommand, {
    env: {
      FAKE_CFN_CLI_OK: 'true',
      FAKE_CFN_IMPORT_OK: 'true',
      FAKE_CFN_VERSION: '1.53.3',
      SECURITY_WORKFLOW_CFN_LINT_VERSION: '1.53.3',
    },
  });

  const mismatch = spawnSync('/bin/bash', ['-c', healthCommand], {
    encoding: 'utf8',
    env: {
      ...process.env,
      FAKE_CFN_CLI_OK: 'true',
      FAKE_CFN_IMPORT_OK: 'true',
      FAKE_CFN_VERSION: '1.53.2',
      SECURITY_WORKFLOW_CFN_LINT_VERSION: '1.53.3',
    },
  });
  assert.notEqual(mismatch.status, 0);

  fs.rmSync(path.join(binDir, 'cfn-lint'));
  const missingExecutable = spawnSync('/bin/bash', ['-c', healthCommand], {
    encoding: 'utf8',
    env: {
      ...process.env,
      FAKE_CFN_CLI_OK: 'true',
      FAKE_CFN_IMPORT_OK: 'true',
      FAKE_CFN_VERSION: '1.53.3',
      SECURITY_WORKFLOW_CFN_LINT_VERSION: '1.53.3',
    },
  });
  assert.notEqual(missingExecutable.status, 0);
});

test('cfn-lint uses a durable user cache outside temporary directories locally', () => {
  const output = runBash([
    'set -euo pipefail',
    'unset RUNNER_TEMP XDG_CACHE_HOME TMPDIR',
    'HOME=/Users/example',
    `source ${shellQuote(path.join(repositoryRoot, 'lib/security-workflow/scanners.sh'))}`,
    'security_workflow_cfn_lint_cache_base',
  ].join('\n'));

  assert.equal(output.trim(), '/Users/example/.cache/security-workflow');
});
