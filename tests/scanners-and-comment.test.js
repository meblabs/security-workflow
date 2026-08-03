#!/usr/bin/env node

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const postSecurityComment = require('../scripts/post-pr-comment');
const {
  repositoryRoot,
  runBash,
  runCommandResult,
  shellQuote,
} = require('./test-helpers');

test('Gitleaks scans tracked files only and mounts repository config explicitly', (t) => {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'security-workflow-gitleaks-'));
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));

  const fakeBin = path.join(fixtureRoot, 'bin');
  const repo = path.join(fixtureRoot, 'repo');
  const reports = path.join(fixtureRoot, 'reports');
  const dockerArgs = path.join(fixtureRoot, 'docker-args.txt');
  const scanFiles = path.join(fixtureRoot, 'scan-files.txt');
  fs.mkdirSync(fakeBin);
  fs.mkdirSync(repo);
  fs.mkdirSync(reports);
  fs.mkdirSync(path.join(repo, 'nested'));
  fs.writeFileSync(path.join(repo, 'nested/tracked.txt'), 'tracked\n');
  fs.writeFileSync(path.join(repo, 'untracked.txt'), 'untracked\n');
  fs.writeFileSync(path.join(repo, '.gitleaks.toml'), '[allowlist]\n');

  const init = runCommandResult('git', ['init', '-q', repo]);
  assert.equal(init.status, 0, init.stderr);
  const add = runCommandResult('git', ['-C', repo, 'add', 'nested/tracked.txt']);
  assert.equal(add.status, 0, add.stderr);

  fs.writeFileSync(path.join(fakeBin, 'docker'), [
    '#!/usr/bin/env bash',
    'scan_dir=""',
    'for argument in "$@"; do',
    '  case "$argument" in',
    '    *:/scan:ro) scan_dir="${argument%:/scan:ro}" ;;',
    '  esac',
    'done',
    'printf "%s\\n" "$@" > "$DOCKER_ARGS_FILE"',
    'if [[ -n "$scan_dir" ]]; then',
    '  (cd "$scan_dir" && find . -type f -print | LC_ALL=C sort) > "$SCAN_FILES_FILE"',
    'fi',
  ].join('\n'));
  fs.chmodSync(path.join(fakeBin, 'docker'), 0o755);

  runBash([
    'set -euo pipefail',
    `source ${shellQuote(path.join(repositoryRoot, 'lib/security-workflow/common.sh'))}`,
    `source ${shellQuote(path.join(repositoryRoot, 'lib/security-workflow/scanners.sh'))}`,
    'security_workflow_gitleaks',
  ].join('\n'), {
    cwd: repo,
    env: {
      DOCKER_ARGS_FILE: dockerArgs,
      PATH: `${fakeBin}:${process.env.PATH}`,
      SCAN_FILES_FILE: scanFiles,
      SECURITY_WORKFLOW_GITLEAKS_VERSION: 'v8.30.1',
      SECURITY_WORKFLOW_REPORTS_DIR: reports,
      SECURITY_WORKFLOW_REPO: repo,
    },
  });

  assert.equal(fs.readFileSync(scanFiles, 'utf8'), './nested/tracked.txt\n');
  const args = fs.readFileSync(dockerArgs, 'utf8');
  assert.match(args, new RegExp(`${repo.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/\\.gitleaks\\.toml:/gitleaks\\.toml:ro`));
  assert.match(args, /--config\n\/gitleaks\.toml\n/);
  assert.doesNotMatch(args, /untracked\.txt/);
});

test('zizmor treats findings status 3 as reportable and propagates execution errors', (t) => {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'security-workflow-zizmor-'));
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));

  const fakeBin = path.join(fixtureRoot, 'bin');
  const repo = path.join(fixtureRoot, 'repo');
  const reports = path.join(fixtureRoot, 'reports');
  fs.mkdirSync(fakeBin);
  fs.mkdirSync(repo);
  fs.mkdirSync(reports);
  fs.writeFileSync(path.join(fakeBin, 'docker'), [
    '#!/usr/bin/env bash',
    'exit "${FAKE_DOCKER_STATUS:-0}"',
  ].join('\n'));
  fs.chmodSync(path.join(fakeBin, 'docker'), 0o755);

  const output = runBash([
    'set -uo pipefail',
    `source ${shellQuote(path.join(repositoryRoot, 'lib/security-workflow/common.sh'))}`,
    `source ${shellQuote(path.join(repositoryRoot, 'lib/security-workflow/scanners.sh'))}`,
    'export FAKE_DOCKER_STATUS=3',
    '(security_workflow_zizmor)',
    'findings_status=$?',
    'export FAKE_DOCKER_STATUS=2',
    '(security_workflow_zizmor)',
    'error_status=$?',
    'printf "findings=%s error=%s\\n" "$findings_status" "$error_status"',
  ].join('\n'), {
    cwd: repo,
    env: {
      GH_TOKEN: '',
      PATH: `${fakeBin}:${process.env.PATH}`,
      SECURITY_WORKFLOW_GITHUB_TOKEN: '',
      SECURITY_WORKFLOW_REPORTS_DIR: reports,
      SECURITY_WORKFLOW_REPO: repo,
      SECURITY_WORKFLOW_ROOT_DIR: repositoryRoot,
      SECURITY_WORKFLOW_ZIZMOR_CONFIG: '',
      SECURITY_WORKFLOW_ZIZMOR_VERSION: 'v1.25.2',
    },
  });

  assert.match(output, /findings=0 error=2/);
});

test('PR comment reporting updates the marked comment and creates one when absent', async (t) => {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'security-workflow-comment-'));
  const originalCwd = process.cwd();
  const environmentKeys = [
    'COMMENT_REPOSITORY',
    'PR_NUMBER',
    'SCANNED_REF',
    'HEAD_REF',
    'UPLOAD_ARTIFACT',
    'SECURITY_REPORTS_ARTIFACT_URL',
    'WORKFLOW_RUN_URL',
  ];
  const previousEnvironment = new Map(environmentKeys.map((key) => [key, process.env[key]]));
  t.after(() => {
    process.chdir(originalCwd);
    for (const [key, value] of previousEnvironment) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(fixtureRoot, { recursive: true, force: true });
  });

  const reports = path.join(fixtureRoot, 'security-reports');
  fs.mkdirSync(reports);
  fs.writeFileSync(path.join(reports, 'security-status.json'), JSON.stringify({
    scannedRef: 'abc123',
    checks: [
      { name: 'Semgrep SAST', outcome: 'failure', blocking: true, applicable: true },
      { name: 'cfn-lint', outcome: 'skipped', blocking: true, applicable: false },
      { name: 'License report', outcome: 'failure', blocking: false, applicable: true },
    ],
  }));
  fs.writeFileSync(path.join(reports, 'cfn-lint.txt'), 'cfn details\n');
  fs.writeFileSync(path.join(reports, 'sarif-findings-summary.md'), '## Active findings\n\nOne finding\n');

  process.chdir(fixtureRoot);
  Object.assign(process.env, {
    COMMENT_REPOSITORY: 'meblabs/example',
    PR_NUMBER: '17',
    SCANNED_REF: 'fallback-ref',
    HEAD_REF: 'feature/security',
    UPLOAD_ARTIFACT: 'true',
    SECURITY_REPORTS_ARTIFACT_URL: 'https://example.invalid/artifact',
    WORKFLOW_RUN_URL: 'https://example.invalid/run',
  });

  const calls = { created: [], failed: [], listed: [], updated: [] };
  let existingComments = [{ id: 41, body: '<!-- meblabs-security-workflow:summary --> old' }];
  const github = {
    paginate: async (_method, args) => {
      calls.listed.push(args);
      return existingComments;
    },
    rest: {
      issues: {
        listComments: async () => [],
        updateComment: async (args) => calls.updated.push(args),
        createComment: async (args) => calls.created.push(args),
      },
    },
  };
  const core = { setFailed: (message) => calls.failed.push(message) };

  await postSecurityComment({ github, core });
  assert.equal(calls.failed.length, 0);
  assert.equal(calls.updated.length, 1);
  assert.equal(calls.updated[0].comment_id, 41);
  assert.equal(calls.created.length, 0);
  assert.equal(calls.listed[0].issue_number, 17);
  assert.match(calls.updated[0].body, /One or more security checks failed/);
  assert.match(calls.updated[0].body, /status-FAIL-red/);
  assert.match(calls.updated[0].body, /status-NA-lightgrey/);
  assert.match(calls.updated[0].body, /cfn details/);
  assert.match(calls.updated[0].body, /## Active findings/);
  assert.match(calls.updated[0].body, /https:\/\/example\.invalid\/artifact/);

  existingComments = [];
  await postSecurityComment({ github, core });
  assert.equal(calls.created.length, 1);
  assert.equal(calls.created[0].issue_number, 17);
  assert.match(calls.created[0].body, /<!-- meblabs-security-workflow:summary -->/);
});
