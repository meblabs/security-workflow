const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const repositoryRoot = path.resolve(__dirname, '..');

const shellQuote = (value) => `'${String(value).replace(/'/g, `'"'"'`)}'`;

const runBashResult = (script, { cwd = repositoryRoot, env = {} } = {}) => spawnSync(
  '/bin/bash',
  ['-c', script],
  {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, ...env },
  },
);

const runBash = (script, options = {}) => {
  const result = runBashResult(script, options);

  if (result.status !== 0) {
    assert.fail(`bash exited ${result.status}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  }

  return result.stdout;
};

const runCommandResult = (command, args, { cwd = repositoryRoot, env = {} } = {}) => spawnSync(
  command,
  args,
  {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, ...env },
  },
);

module.exports = {
  repositoryRoot,
  runBash,
  runBashResult,
  runCommandResult,
  shellQuote,
};
