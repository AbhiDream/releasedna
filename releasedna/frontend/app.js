'use strict';
const el = id => document.getElementById(id);
let currentReport = null;
let selected = null;
let poll = null;
const terminal = state => ['completed', 'failed'].includes(state);
async function api(path, options) {
  const response = await fetch(path, options);
  const body = await response.json();
  if (!response.ok) throw new Error(typeof body.detail === 'string' ? body.detail : `Request failed (${response.status})`);
  return body;
}
function node(tag, content, className) {
  const element = document.createElement(tag);
  if (content !== undefined) element.textContent = String(content);
  if (className) element.className = className;
  return element;
}
function render(report) {
  currentReport = report;
  el('result').hidden = false;
  el('verdict').textContent = `${report.status} · risk score ${report.risk_score ?? 'unavailable'}`;
  el('meaning').textContent = report.status === 'CLEAN' ? report.clean_definition : 'Review the evidence and limitations. The verdict describes release/source differences within the available scope.';
  el('scan-id').textContent = `Scan ${report.scan_id} · ${report.duration_seconds ?? '?'} seconds`;
  el('metrics').replaceChildren();
  for (const [key, label] of Object.entries({artifact_file_count:'Artifact files', source_file_count:'Source files',unique_comparison_paths:'Comparison paths',identical_files:'Identical',added_files:'Added',removed_files:'Removed',changed_files:'Changed'})) {
    const box = node('div', undefined, 'metric');
    box.append(node('strong', report.metrics?.[key] ?? '—'), node('span', label));
    el('metrics').append(box);
  }
  el('integrity').textContent = report.artifact?.verified ? 'Digest matches the official registry metadata.' : 'Artifact integrity was not established.';
  el('digest').textContent = report.artifact?.digest || 'No verified digest';
  el('source').textContent = `Confidence: ${report.source?.confidence || 'unresolved'} · tag: ${report.source?.tag || 'none'}`;
  el('commit').textContent = report.source?.commit || 'No matched commit';
  el('publication').textContent = report.publication?.publication_time || 'Publication time unavailable';
  el('publication-note').textContent = report.publication?.publication_time_limitation || report.publication?.publication_time_source || report.publication?.registry || '';
  el('findings').replaceChildren();
  if (!report.findings?.length) el('findings').append(node('p', 'No suspicious findings reported. Check analysis coverage below.'));
  for (const item of report.findings || []) {
    const card = node('div', undefined, 'finding');
    card.append(node('strong', `${item.rule} · ${item.artifact_path || item.source_path}`), node('p', item.message));
    if (item.evidence?.length) card.append(node('pre', JSON.stringify(item.evidence, null, 2)));
    el('findings').append(card);
  }
  el('files').replaceChildren();
  for (const file of report.files || []) {
    const row = node('tr');
    row.append(node('td', file.path), node('td', file.state), node('td', `${file.classification}${file.omission_kind ? ' / ' + file.omission_kind : ''}`));
    const detail = node('td', file.explanation || (file.state === 'identical' ? 'Bytes and executable permissions match.' : 'See findings.'));
    if (file.diff) { const disclosure = node('details'); disclosure.append(node('summary', 'View diff'), node('pre', file.diff)); detail.append(disclosure); }
    row.append(detail); el('files').append(row);
  }
  el('limitations').replaceChildren(...[...(report.limitations || []), ...(report.source?.reasons || [])].map(text => node('li', text)));
}
async function history() {
  const data = await api('/api/scans');
  el('history').replaceChildren();
  if (!data.items.length) el('history').append(node('p', 'No persisted scans yet.'));
  for (const job of data.items) {
    const row = node('div', undefined, 'history-item');
    const description = node('div', `${job.package.name}@${job.package.version} · ${job.state}`);
    description.append(node('div', `${job.created_at} · ${job.id}`, 'muted'));
    const button = node('button', 'View'); button.type = 'button';
    button.addEventListener('click', () => select(job.id));
    row.append(description, button); el('history').append(row);
  }
}
async function select(id) {
  clearTimeout(poll); selected = id;
  el('error').textContent = '';
  el('result').hidden = true;
  try {
    const job = await api(`/api/scans/${encodeURIComponent(id)}`);
    if (selected !== id) return;
    el('progress').textContent = `${job.state.toUpperCase()} · ${job.package.name}@${job.package.version} · ${id}`;
    if (job.result) render(job.result);
    if (job.error) el('error').textContent = job.error;
    if (!terminal(job.state)) poll = setTimeout(() => select(id), 700);
    else await history();
  } catch (error) { el('error').textContent = `${error.message}. Use Refresh history to reconnect.`; }
}
el('scan-form').addEventListener('submit', async event => {
  event.preventDefault(); el('submit').disabled = true; el('error').textContent = '';
  try {
    const job = await api('/api/scans', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ecosystem:el('ecosystem').value,name:el('name').value.trim(),version:el('version').value.trim()})});
    await history(); await select(job.id);
  } catch (error) { el('error').textContent = error.message; }
  finally { el('submit').disabled = false; }
});
el('refresh').addEventListener('click', () => history().catch(error => { el('error').textContent = error.message; }));
el('download').addEventListener('click', () => {
  if (!currentReport) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(currentReport,null,2)], {type:'application/json'}));
  const link = node('a'); link.href = url; link.download = `releasedna-${currentReport.scan_id}.json`; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
history().catch(error => { el('error').textContent = error.message; });
