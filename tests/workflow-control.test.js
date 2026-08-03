#!/usr/bin/env node

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const {
  repositoryRoot,
  runBash,
  runBashResult,
  runCommandResult,
  shellQuote,
} = require('./test-helpers');

test('check selectors expand groups and add Docker build dependencies', () => {
  const output = runBash([
    'set -euo pipefail',
    `source ${shellQuote(path.join(repositoryRoot, 'lib/security-workflow/common.sh'))}`,
    'SECURITY_WORKFLOW_ONLY_CHECKS_EXPANDED=()',
    'SECURITY_WORKFLOW_SKIP_CHECKS_EXPANDED=()',
    'security_workflow_parse_check_selectors "trivy-image" SECURITY_WORKFLOW_ONLY_CHECKS_EXPANDED',
    'security_workflow_parse_check_selectors "docker" SECURITY_WORKFLOW_SKIP_CHECKS_EXPANDED',
    'security_workflow_add_implicit_check_dependencies',
    'printf "only=%s\\n" "${SECURITY_WORKFLOW_ONLY_CHECKS_EXPANDED[*]}"',
    'printf "skip=%s\\n" "${SECURITY_WORKFLOW_SKIP_CHECKS_EXPANDED[*]}"',
    'if security_workflow_check_enabled docker-build; then echo docker-build=enabled; else echo docker-build=disabled; fi',
    'if security_workflow_check_enabled trivy-image; then echo trivy-image=enabled; else echo trivy-image=disabled; fi',
    'if security_workflow_check_enabled semgrep; then echo semgrep=enabled; else echo semgrep=disabled; fi',
  ].join('\n'));

  assert.match(output, /^only=trivy-image docker-build$/m);
  assert.match(output, /^skip=docker-build trivy-image sbom-image$/m);
  assert.match(output, /^docker-build=disabled$/m);
  assert.match(output, /^trivy-image=disabled$/m);
  assert.match(output, /^semgrep=disabled$/m);
});

test('unknown check selectors are rejected with exit status 2', () => {
  const result = runBashResult([
    'set -euo pipefail',
    `source ${shellQuote(path.join(repositoryRoot, 'lib/security-workflow/common.sh'))}`,
    'SECURITY_WORKFLOW_ONLY_CHECKS_EXPANDED=()',
    'SECURITY_WORKFLOW_SKIP_CHECKS_EXPANDED=()',
    'security_workflow_parse_check_selectors "unknown-check" SECURITY_WORKFLOW_ONLY_CHECKS_EXPANDED',
    'security_workflow_validate_check_selectors',
  ].join('\n'));

  assert.equal(result.status, 2);
  assert.match(result.stderr, /Unknown check selector: unknown-check/);
});

test('security gate accepts NA selections and rejects applicable skipped checks', () => {
  const commonSetup = [
    'set -uo pipefail',
    'export NO_COLOR=1',
    `source ${shellQuote(path.join(repositoryRoot, 'lib/security-workflow/common.sh'))}`,
    `source ${shellQuote(path.join(repositoryRoot, 'lib/security-workflow/gate.sh'))}`,
    'GITLEAKS_OUTCOME=na',
    'TRIVY_FS_OUTCOME=na',
    'TRIVY_CONFIG_OUTCOME=na',
    'CFN_LINT_OUTCOME=skipped',
    'ZIZMOR_OUTCOME=skipped',
    'DOCKER_BUILD_OUTCOME=skipped',
    'TRIVY_IMAGE_OUTCOME=skipped',
    'SAM_TEMPLATES=false',
    'GITHUB_ACTIONS_FILES=false',
    'ROOT_DOCKERFILE=false',
  ];

  const selectedOut = runBash([
    ...commonSetup,
    'SEMGREP_OUTCOME=na',
    'security_workflow_gate',
    'printf "outcome=%s\\n" "$SECURITY_GATE_OUTCOME"',
  ].join('\n'));
  assert.match(selectedOut, /PASS: Security gate passed\./);
  assert.match(selectedOut, /outcome=success/);

  const skipped = runBash([
    ...commonSetup,
    'SEMGREP_OUTCOME=skipped',
    'set +e',
    'security_workflow_gate',
    'status=$?',
    'set -e',
    'printf "status=%s outcome=%s\\n" "$status" "$SECURITY_GATE_OUTCOME"',
  ].join('\n'));
  assert.match(skipped, /FAIL: Semgrep SAST was skipped but is applicable\./);
  assert.match(skipped, /status=1 outcome=failure/);
});

test('target detection distinguishes configured Docker, SAM, and GitHub Actions inputs', (t) => {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'security-workflow-all-targets-'));
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));

  const reportsDir = path.join(fixtureRoot, 'reports');
  fs.mkdirSync(reportsDir);
  fs.writeFileSync(path.join(reportsDir, 'security-summary.md'), '');
  fs.mkdirSync(path.join(fixtureRoot, 'deploy'));
  fs.writeFileSync(path.join(fixtureRoot, 'deploy/Dockerfile'), 'FROM scratch\n');
  fs.mkdirSync(path.join(fixtureRoot, 'services'));
  fs.writeFileSync(path.join(fixtureRoot, 'services/api.Dockerfile'), 'FROM scratch\n');
  fs.mkdirSync(path.join(fixtureRoot, '.github/workflows'), { recursive: true });
  fs.writeFileSync(path.join(fixtureRoot, '.github/workflows/security.yml'), 'name: Security\n');
  fs.mkdirSync(path.join(fixtureRoot, 'custom-action'));
  fs.writeFileSync(path.join(fixtureRoot, 'custom-action/action.yaml'), 'name: Fixture\n');
  fs.mkdirSync(path.join(fixtureRoot, 'node_modules/ignored'), { recursive: true });
  fs.writeFileSync(path.join(fixtureRoot, 'node_modules/ignored/action.yml'), 'name: Ignored\n');

  const output = runBash([
    'set -euo pipefail',
    `source ${shellQuote(path.join(repositoryRoot, 'lib/security-workflow/targets.sh'))}`,
    'security_workflow_detect_targets',
    'printf "root=%s docker=%s:%s sam=%s:%s actions=%s:%s\\n" "$ROOT_DOCKERFILE" "$DOCKERFILES" "$DOCKERFILES_COUNT" "$SAM_TEMPLATES" "$SAM_TEMPLATES_COUNT" "$GITHUB_ACTIONS_FILES" "$GITHUB_ACTIONS_FILES_COUNT"',
  ].join('\n'), {
    cwd: fixtureRoot,
    env: {
      SECURITY_WORKFLOW_DOCKERFILE_PATH: 'deploy/Dockerfile',
      SECURITY_WORKFLOW_REPORTS_DIR: reportsDir,
    },
  });

  assert.equal(output.trim(), 'root=true docker=true:2 sam=false:0 actions=true:2');
});

test('status reporting emits valid JSON and GitHub outputs', (t) => {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'security-workflow-status-'));
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));

  const reportsDir = path.join(fixtureRoot, 'reports');
  const githubOutput = path.join(fixtureRoot, 'github-output.txt');
  fs.mkdirSync(reportsDir);

  runBash([
    'set -euo pipefail',
    `source ${shellQuote(path.join(repositoryRoot, 'lib/security-workflow/common.sh'))}`,
    `source ${shellQuote(path.join(repositoryRoot, 'lib/security-workflow/reports.sh'))}`,
    'security_workflow_write_status_files',
    'security_workflow_write_github_outputs',
  ].join('\n'), {
    env: {
      CFN_LINT_OUTCOME: 'na',
      DOCKERFILES: 'true',
      DOCKERFILES_COUNT: '2',
      DOCKER_BUILD_OUTCOME: 'success',
      GITHUB_ACTIONS_FILES: 'false',
      GITHUB_ACTIONS_FILES_COUNT: '0',
      GITHUB_OUTPUT: githubOutput,
      GITLEAKS_OUTCOME: 'success',
      ROOT_DOCKERFILE: 'true',
      SAM_TEMPLATES: 'false',
      SAM_TEMPLATES_COUNT: '0',
      SECURITY_GATE_OUTCOME: 'success',
      SECURITY_WORKFLOW_COMMIT: 'abc123',
      SECURITY_WORKFLOW_REF: 'feature/"quoted"\\branch',
      SECURITY_WORKFLOW_REPORTS_DIR: reportsDir,
      SEMGREP_OUTCOME: 'success',
      TRIVY_CONFIG_OUTCOME: 'success',
      TRIVY_FS_OUTCOME: 'success',
      TRIVY_IMAGE_OUTCOME: 'success',
      TRIVY_IMAGE_SBOM_OUTCOME: 'success',
      TRIVY_LICENSE_OUTCOME: 'success',
      TRIVY_SBOM_OUTCOME: 'success',
      ZIZMOR_OUTCOME: 'na',
    },
  });

  const status = JSON.parse(fs.readFileSync(path.join(reportsDir, 'security-status.json'), 'utf8'));
  assert.equal(status.scannedRef, 'feature/"quoted"\\branch');
  assert.equal(status.targets.dockerfilesCount, 2);
  assert.equal(status.targets.rootDockerfile, true);
  assert.equal(status.checks.find((check) => check.id === 'trivy_image').outcome, 'success');
  assert.equal(status.checks.find((check) => check.id === 'cfn_lint').applicable, false);
  assert.equal(status.gate.outcome, 'success');

  const outputs = fs.readFileSync(githubOutput, 'utf8');
  assert.match(outputs, /^dockerfiles_count=2$/m);
  assert.match(outputs, /^security_gate_outcome=success$/m);
});

test('CLI completes end-to-end with every check intentionally excluded', (t) => {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'security-workflow-cli-'));
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));

  const repo = path.join(fixtureRoot, 'repo');
  const reportsDir = path.join(fixtureRoot, 'reports');
  fs.mkdirSync(repo);
  const init = runCommandResult('git', ['init', '-q', repo]);
  assert.equal(init.status, 0, init.stderr);
  fs.writeFileSync(path.join(repo, 'README.md'), '# Fixture\n');
  const add = runCommandResult('git', ['-C', repo, 'add', 'README.md']);
  assert.equal(add.status, 0, add.stderr);
  const commit = runCommandResult('git', [
    '-C', repo,
    '-c', 'user.name=Security Workflow Tests',
    '-c', 'user.email=security-workflow@example.invalid',
    '-c', 'commit.gpgSign=false',
    'commit', '-qm', 'test fixture',
  ]);
  assert.equal(commit.status, 0, commit.stderr);

  const result = runCommandResult(path.join(repositoryRoot, 'bin/security-workflow'), [
    '--repo', repo,
    '--reports-dir', reportsDir,
    '--skip', 'all',
  ], {
    env: { NO_COLOR: '1' },
  });

  assert.equal(result.status, 0, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  assert.match(result.stdout, /PASS: Security gate passed\./);

  const status = JSON.parse(fs.readFileSync(path.join(reportsDir, 'security-status.json'), 'utf8'));
  assert.equal(status.gate.outcome, 'success');
  assert.ok(status.checks.every((check) => check.outcome === 'na'));

  const summary = fs.readFileSync(path.join(reportsDir, 'security-summary.md'), 'utf8');
  assert.match(summary, /- Skip: all/);
});
