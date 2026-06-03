const fs = require('node:fs');

module.exports = async ({ github, core }) => {
  const [owner, repo] = process.env.COMMENT_REPOSITORY.split('/');
  const issue_number = Number(process.env.PR_NUMBER);

  if (!owner || !repo || !Number.isInteger(issue_number) || issue_number <= 0) {
    core.setFailed(`Invalid pull request comment target: repository=${process.env.COMMENT_REPOSITORY}, pr-number=${process.env.PR_NUMBER}`);
    return;
  }

  const status = JSON.parse(fs.readFileSync('security-reports/security-status.json', 'utf8'));
  const marker = '<!-- meblabs-security-workflow:summary -->';

  const badge = (value) => {
    const normalized = ['PASS', 'FAIL', 'NA', 'UNKNOWN'].includes(value) ? value : normalize(value);
    const badges = {
      PASS: '![PASS](https://img.shields.io/badge/status-PASS-brightgreen?style=flat-square)',
      FAIL: '![FAIL](https://img.shields.io/badge/status-FAIL-red?style=flat-square)',
      NA: '![NA](https://img.shields.io/badge/status-NA-lightgrey?style=flat-square)',
      UNKNOWN: '![UNKNOWN](https://img.shields.io/badge/status-UNKNOWN-lightgrey?style=flat-square)',
    };
    return badges[normalized] ?? badges.UNKNOWN;
  };

  function normalize(outcome, applicable = true) {
    if (!applicable) return 'NA';
    if (outcome === 'success') return 'PASS';
    if (outcome === 'na') return 'NA';
    if (outcome === 'failure') return 'FAIL';
    if (outcome === 'skipped') return 'FAIL';
    if (outcome === 'cancelled') return 'FAIL';
    return 'UNKNOWN';
  }

  const rows = status.checks.map((check) => [
    check.name,
    normalize(check.outcome, check.applicable),
    Boolean(check.blocking),
  ]);

  const hasBlockingFailure = status.checks.some((check) => {
    if (!check.blocking) return false;
    return normalize(check.outcome, check.applicable) === 'FAIL';
  });

  const COMMENT_BODY_LIMIT = 64000;
  const artifactUrl = process.env.SECURITY_REPORTS_ARTIFACT_URL || '';
  const workflowRunUrl = process.env.WORKFLOW_RUN_URL || '';

  const artifactLine = () => {
    if (artifactUrl) {
      return `Security reports artifact: [security-reports](${artifactUrl})`;
    }

    if (process.env.UPLOAD_ARTIFACT !== 'true') {
      return 'Security reports artifact: upload disabled for this run.';
    }

    if (workflowRunUrl) {
      return `Security reports artifact: direct artifact URL was not returned; open the [workflow run artifacts](${workflowRunUrl}) section.`;
    }

    return 'Security reports artifact: direct artifact URL was not returned by the upload step.';
  };

  const details = (title, file, options = {}) => {
    if (!fs.existsSync(file)) return [];
    const content = fs.readFileSync(file, 'utf8').trim();
    if (!content) return [];
    const maxChars = options.maxChars ?? 20000;
    const truncated = content.length > maxChars;
    const excerpt = truncated ? `${content.slice(0, maxChars)}\n\n[Output truncated to keep the GitHub comment under its size limit.]` : content;
    return [
      '',
      `<details><summary>${title}</summary>`,
      '',
      ...(options.markdown ? [] : ['```text']),
      excerpt,
      ...(options.markdown ? [] : ['```']),
      '</details>',
    ];
  };

  const bodyParts = [
    marker,
    '# Security',
    '',
    `Scanned ref: \`${status.scannedRef || process.env.SCANNED_REF || ''}\``,
    ...(process.env.HEAD_REF ? [`Head ref: \`${process.env.HEAD_REF}\``] : []),
    artifactLine(),
    '',
    hasBlockingFailure
      ? 'One or more security checks failed. Review the failure details in this comment.'
      : 'All applicable blocking security checks passed.',
    '',
    '| Check | Outcome |',
    '|---|---:|',
    ...rows.map(([name, outcome]) => `| ${name} | ${badge(outcome)} |`),
    '',
    'Detailed output is included below. The `security-reports` artifact contains the same reports for download or audit retention.',
    ...details('cfn-lint output', 'security-reports/cfn-lint.txt'),
    ...details('zizmor output', 'security-reports/zizmor.txt'),
    ...details('SARIF findings overview', 'security-reports/sarif-findings-summary.md', { markdown: true, maxChars: 40000 }),
  ].join('\n');

  const body = bodyParts.length > COMMENT_BODY_LIMIT
    ? `${bodyParts.slice(0, COMMENT_BODY_LIMIT - 180)}\n\n[Comment truncated because GitHub limits issue comment size. See the \`security-reports\` artifact for the full output.]`
    : bodyParts;

  const comments = await github.paginate(github.rest.issues.listComments, {
    owner,
    repo,
    issue_number,
    per_page: 100,
  });

  const previous = comments.find((comment) => comment.body?.includes(marker));

  if (previous) {
    await github.rest.issues.updateComment({
      owner,
      repo,
      comment_id: previous.id,
      body,
    });
  } else {
    await github.rest.issues.createComment({
      owner,
      repo,
      issue_number,
      body,
    });
  }
};
