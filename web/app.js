const tokenFromFragment = new URLSearchParams(location.hash.slice(1)).get('token');
if (tokenFromFragment) {
  sessionStorage.setItem('apg-dashboard-token', tokenFromFragment);
  history.replaceState(null, '', location.pathname);
}
const token = sessionStorage.getItem('apg-dashboard-token');
const queue = document.querySelector('#queue');
const approvalEmpty = document.querySelector('#approval-empty');
const auditList = document.querySelector('#audit-list');
const auditEmpty = document.querySelector('#audit-empty');
const errorBox = document.querySelector('#error');
const pendingCount = document.querySelector('#pending-count');
const callCount = document.querySelector('#call-count');
const integrity = document.querySelector('#integrity');
const connection = document.querySelector('#connection');
const policySource = document.querySelector('#policy-source');
const policyMessage = document.querySelector('#policy-message');
let policyRevision;

async function api(path, options = {}) {
  if (!token) throw new Error('Dashboard token is missing. Reopen the secure URL printed by APG.');
  const response = await fetch(path, {
    ...options,
    headers: { ...(options.headers || {}), Authorization: `Bearer ${token}` },
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || 'Dashboard request failed');
  return payload;
}

function element(name, className, text) {
  const node = document.createElement(name);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderApprovals(requests) {
  queue.replaceChildren();
  pendingCount.textContent = String(requests.length);
  approvalEmpty.hidden = requests.length !== 0;
  for (const request of requests) {
    const card = element('article', 'request-card');
    const top = element('div', 'request-top');
    const title = element('div');
    title.append(element('p', 'server', request.serverId), element('h3', '', request.toolName));
    top.append(title, element('span', `risk risk-${request.risk.band}`, `${request.risk.score} · ${request.risk.band}`));
    const meta = element('div', 'meta');
    meta.append(element('span', '', `Expires ${new Date(request.expiresAt).toLocaleTimeString()}`), element('span', '', request.reasonCodes.join(' · ')));
    const pre = element('pre');
    pre.textContent = JSON.stringify(request.arguments, null, 2);
    const actions = element('div', 'actions');
    const deny = element('button', 'deny', 'Deny');
    const approve = element('button', 'approve', 'Approve once');
    deny.type = approve.type = 'button';
    deny.addEventListener('click', () => decide(request.id, 'deny', deny, approve));
    approve.addEventListener('click', () => decide(request.id, 'approve', deny, approve));
    actions.append(deny, approve);
    card.append(top, meta, pre, actions);
    queue.append(card);
  }
}

function renderAudit(calls, hashChainValid) {
  auditList.replaceChildren();
  callCount.textContent = String(calls.length);
  integrity.textContent = hashChainValid ? 'Verified' : 'Check failed';
  integrity.className = hashChainValid ? 'integrity-ok' : 'integrity-bad';
  auditEmpty.hidden = calls.length !== 0;
  for (const call of calls) {
    const card = element('article', 'audit-card');
    const row = element('div', 'audit-row');
    const title = element('div');
    title.append(element('p', 'server', `${call.serverId} · ${new Date(call.startedAt).toLocaleString()}`), element('h3', '', call.toolName));
    row.append(title, element('span', `decision decision-${call.effectiveDecision}`, call.effectiveDecision));
    const facts = element('div', 'audit-facts');
    facts.append(fact('Status', call.status), fact('Risk', `${call.riskScore} · ${call.riskBand}`), fact('Rule', call.matchedRuleId || 'Default'), fact('Latency', call.latencyMs === undefined ? '—' : `${call.latencyMs} ms`));
    const details = document.createElement('details');
    details.append(element('summary', '', 'View redacted details'));
    const pre = element('pre');
    pre.textContent = JSON.stringify({ arguments: call.arguments, reasons: call.reasonCodes, result: call.resultSummary }, null, 2);
    details.append(pre);
    card.append(row, facts, details);
    auditList.append(card);
  }
}

function fact(label, value) {
  const node = element('div');
  node.append(element('span', '', label), element('strong', '', value));
  return node;
}

async function decide(id, action, ...buttons) {
  buttons.forEach((button) => { button.disabled = true; });
  try {
    await api(`/api/approvals/${id}/${action}`, { method: 'POST' });
    await loadApprovals();
  } catch (error) {
    showError(error.message);
    buttons.forEach((button) => { button.disabled = false; });
  }
}

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
  connection.textContent = 'Attention needed';
}

function showConnected() {
  errorBox.hidden = true;
  connection.textContent = 'Protected';
}

async function loadApprovals() {
  try {
    const payload = await api('/api/approvals');
    renderApprovals(payload.approvals);
    showConnected();
  } catch (error) { showError(error.message); }
}

async function loadAudit() {
  try {
    const payload = await api('/api/audit?limit=50');
    renderAudit(payload.calls, payload.hashChainValid);
    showConnected();
  } catch (error) { showError(error.message); }
}

async function loadPolicy() {
  try {
    const payload = await api('/api/policy');
    policySource.value = payload.source;
    policyRevision = payload.revision;
    policyMessage.textContent = 'Active policy loaded.';
    showConnected();
  } catch (error) { showError(error.message); }
}

async function savePolicy() {
  if (!policyRevision) return showError('Reload the active policy before saving.');
  if (!confirm('Apply this security policy to all new tool calls?')) return;
  const button = document.querySelector('#save-policy');
  button.disabled = true;
  policyMessage.textContent = 'Validating and saving…';
  try {
    const payload = await api('/api/policy', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source: policySource.value, revision: policyRevision }),
    });
    policyRevision = payload.revision;
    policyMessage.textContent = 'Saved. New tool calls now use this policy.';
    showConnected();
  } catch (error) {
    policyMessage.textContent = `Not saved: ${error.message}`;
    showError(error.message);
  } finally { button.disabled = false; }
}

document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    const target = tab.dataset.panel;
    document.querySelectorAll('.tab').forEach((item) => item.classList.toggle('active', item === tab));
    document.querySelectorAll('.panel').forEach((panel) => {
      const active = panel.id === `panel-${target}`;
      panel.classList.toggle('active', active);
      panel.hidden = !active;
    });
    if (target === 'audit') loadAudit();
    if (target === 'policy') loadPolicy();
  });
});

document.querySelector('#refresh-approvals').addEventListener('click', loadApprovals);
document.querySelector('#refresh-audit').addEventListener('click', loadAudit);
document.querySelector('#reload-policy').addEventListener('click', loadPolicy);
document.querySelector('#save-policy').addEventListener('click', savePolicy);
policySource.addEventListener('input', () => { policyMessage.textContent = 'Unsaved changes.'; });
loadApprovals();
loadAudit();
setInterval(loadApprovals, 2_000);
