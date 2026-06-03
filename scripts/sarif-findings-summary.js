#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');

const args = process.argv.slice(2);
const options = {
  reportsDir: 'security-reports',
  repository: '',
  sourceRef: 'HEAD',
  serverUrl: 'https://github.com',
};

for (let index = 0; index < args.length; index += 1) {
  const arg = args[index];
  if (arg === '--reports-dir') options.reportsDir = args[++index];
  else if (arg === '--repository') options.repository = args[++index] || '';
  else if (arg === '--source-ref') options.sourceRef = args[++index] || 'HEAD';
  else if (arg === '--server-url') options.serverUrl = args[++index] || 'https://github.com';
}

const reports = [
  ['Semgrep SAST', 'semgrep.sarif'],
  ['Gitleaks secrets', 'gitleaks.sarif'],
  ['Trivy filesystem SCA', 'trivy-fs.sarif'],
  ['Trivy IaC/config misconfiguration', 'trivy-config.sarif'],
  ['Trivy Docker image scan', 'trivy-image.sarif'],
];

const getRule = (run, ruleId) => run?.tool?.driver?.rules?.find((rule) => rule.id === ruleId) ?? {};
const oneLine = (value) => String(value ?? '').replace(/\s+/g, ' ').trim();
const tableCell = (value) => oneLine(value).replace(/\|/g, '\\|');
const encodePath = (artifact) => artifact.split('/').map(encodeURIComponent).join('/');

const sourceBase = options.repository
  ? `${options.serverUrl}/${options.repository}/blob/${options.sourceRef}`
  : '';

const sourceLink = (artifact, region = {}) => {
  if (!artifact || /^[a-z]+:\/\//i.test(artifact)) return tableCell(artifact);

  const startLine = region.startLine;
  const endLine = region.endLine;
  const lineSuffix = startLine ? `#L${startLine}${endLine && endLine !== startLine ? `-L${endLine}` : ''}` : '';
  const label = `${artifact}${startLine ? `:${startLine}` : ''}`;

  if (!sourceBase) return tableCell(label);
  return `[${tableCell(label)}](${sourceBase}/${encodePath(artifact)}${lineSuffix})`;
};

const rows = [];
const sections = [];

for (const [label, relativeFile] of reports) {
  const file = path.join(options.reportsDir, relativeFile);
  if (!fs.existsSync(file)) {
    rows.push(`| ${label} | no SARIF file | 0 |`);
    continue;
  }

  let sarif;
  try {
    sarif = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    rows.push(`| ${label} | invalid SARIF | 0 |`);
    continue;
  }

  const findings = [];
  for (const run of sarif.runs ?? []) {
    for (const result of run.results ?? []) {
      const rule = getRule(run, result.ruleId);
      const location = result.locations?.[0]?.physicalLocation;
      const artifact = location?.artifactLocation?.uri ?? '';
      const region = location?.region ?? {};
      const message = oneLine(result.message?.text || rule.shortDescription?.text || result.ruleId || 'Finding');
      const help = result.helpUri || rule.helpUri || rule.help?.markdown || rule.fullDescription?.text || '';
      findings.push({
        ruleId: result.ruleId ?? rule.id ?? '',
        level: result.level ?? '',
        location: sourceLink(artifact, region),
        message,
        help,
      });
    }
  }

  rows.push(`| ${label} | ${findings.length > 0 ? 'findings' : 'clean'} | ${findings.length} |`);

  if (findings.length > 0) {
    sections.push(`### ${label}`);
    sections.push('');
    sections.push(`Total findings: ${findings.length}`);
    sections.push('');
    sections.push('| Rule | Level | Location | Message | Help |');
    sections.push('|---|---|---|---|---|');
    for (const finding of findings) {
      const help = /^https?:\/\//i.test(finding.help) ? `[link](${finding.help})` : tableCell(finding.help);
      sections.push(`| ${tableCell(finding.ruleId)} | ${tableCell(finding.level)} | ${finding.location} | ${tableCell(finding.message)} | ${help} |`);
    }
    sections.push('');
  }
}

const content = [
  '## SARIF findings overview',
  '',
  '| Scanner | Status | Findings |',
  '|---|---:|---:|',
  ...rows,
  '',
  ...sections,
].join('\n');

fs.writeFileSync(path.join(options.reportsDir, 'sarif-findings-summary.md'), content);

if (process.env.GITHUB_STEP_SUMMARY) {
  fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `\n${content}\n`);
}
