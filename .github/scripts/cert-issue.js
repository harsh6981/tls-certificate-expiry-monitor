// Opens/updates a GitHub issue while any certificate is unhealthy and closes it
// again once everything is OK. Called from actions/github-script.
const fs = require('fs');

const LABEL = 'cert-monitor';
const TITLE = 'TLS certificate alert';

module.exports = async ({ github, context, core }) => {
  if (!fs.existsSync('reports/report.json')) {
    core.warning('reports/report.json not found (checker did not finish); leaving issues untouched.');
    return;
  }
  const report = JSON.parse(fs.readFileSync('reports/report.json', 'utf8'));
  const table = fs.readFileSync('reports/report.md', 'utf8');
  const { owner, repo } = context.repo;
  const runUrl = `${context.serverUrl}/${owner}/${repo}/actions/runs/${context.runId}`;
  const body = `${table}\n[Workflow run #${context.runNumber}](${runUrl}) · this issue is managed automatically and closes itself when all certificates are healthy.\n`;

  // Make sure the label exists.
  try {
    await github.rest.issues.getLabel({ owner, repo, name: LABEL });
  } catch (err) {
    if (err.status !== 404) throw err;
    await github.rest.issues.createLabel({
      owner, repo, name: LABEL, color: 'b60205',
      description: 'Automated TLS certificate expiry alerts',
    });
  }

  const { data: open } = await github.rest.issues.listForRepo({
    owner, repo, labels: LABEL, state: 'open', per_page: 20,
  });
  const existing = open.find((i) => !i.pull_request);
  const healthy = report.overall === 'ok';

  if (!healthy) {
    if (existing) {
      await github.rest.issues.update({ owner, repo, issue_number: existing.number, body });
      core.info(`Updated issue #${existing.number}`);
    } else {
      const { data } = await github.rest.issues.create({
        owner, repo, title: TITLE, body, labels: [LABEL],
      });
      core.info(`Opened issue #${data.number}`);
    }
  } else if (existing) {
    await github.rest.issues.update({ owner, repo, issue_number: existing.number, body });
    await github.rest.issues.createComment({
      owner, repo, issue_number: existing.number,
      body: `✅ All certificates are healthy again as of run #${context.runNumber}. Closing.`,
    });
    await github.rest.issues.update({
      owner, repo, issue_number: existing.number, state: 'closed', state_reason: 'completed',
    });
    core.info(`Closed issue #${existing.number}`);
  } else {
    core.info('All certificates healthy and no open issue; nothing to do.');
  }
};
