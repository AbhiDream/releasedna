'use strict';
const el = id => document.getElementById(id);
let currentReport = null;
let selected = null;
let poll = null;
let workspaceKey = sessionStorage.getItem('releasedna-access-key') || '';
async function authorizedFetch(path, options = {}) {
  const headers = new Headers(options.headers);
  if (workspaceKey) headers.set('Authorization', 'Bearer ' + workspaceKey);
  const response = await fetch(path, {...options, headers});
  if (response.status === 401) el('access-panel').hidden = false;
  return response;
}
const terminal = state => ['completed', 'failed'].includes(state);
async function api(path, options) {
  const response = await authorizedFetch(path, options);
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
  el('anomaly-badge').hidden = !report.findings?.length;
  el('explanation').replaceChildren();
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
    if (file.build_evidence || file.source_map_evidence) {
      const evidence = node('details');
      evidence.append(node('summary', 'Build / source-map evidence'), node('pre', JSON.stringify(file.build_evidence || file.source_map_evidence, null, 2)));
      detail.append(evidence);
    }
    row.append(detail); el('files').append(row);
  }
  el('limitations').replaceChildren(...[...(report.limitations || []), ...(report.source?.reasons || [])].map(text => node('li', text)));
}
async function history() {
  const data = await api('/api/scans');
  el('history-count').textContent = data.total;
  el('history').replaceChildren();
  if (!data.items.length) el('history').append(node('p', 'No persisted scans yet.'));
  for (const job of data.items) {
    const row = node('div', undefined, 'history-item');
    const description = node('div', `${job.package.name}${job.package.version ? '@'+job.package.version : ` · ${job.package.kind==='text'?'text files':'local archives'}`} · ${job.state}`);
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
    el('progress').textContent = `${job.state.toUpperCase()} · ${job.package.name} ${job.package.version || '· local archives'} · ${id}`;
    if (job.result) { render(job.result); filterFiles(); }
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

el('explain').addEventListener('click', async () => {
  if (!currentReport) return;
  const identity = currentReport.scan_id;
  el('explain').disabled = true;
  el('explanation').textContent = 'Requesting explanation of saved findings…';
  try {
    const result = await api(`/api/scans/${encodeURIComponent(identity)}/explanation`, {method:'POST'});
    if (currentReport?.scan_id !== identity) return;
    el('explanation').replaceChildren(node('p', result.notice));
    if (!result.explanations.length) el('explanation').append(node('p', 'No findings to explain. Analysis limitations still apply.'));
    for (const item of result.explanations) el('explanation').append(node('p', `${item.finding_id}: ${item.text}`));
    el('explanation').append(node('small', `Frozen report SHA256: ${result.report_sha256}`));
  } catch (error) { if (currentReport?.scan_id === identity) el('explanation').textContent = error.message; }
  finally { el('explain').disabled = false; }
});

async function monitor() {
  const data = await api('/api/monitor');
  el('watches').replaceChildren(); el('alerts').replaceChildren();
  for (const watch of data.watches) {
    const row = node('div', undefined, 'history-item');
    row.append(node('p', `${watch.ecosystem}:${watch.name} · ${watch.initialized ? 'baseline recorded' : 'waiting for first poll'} · ${watch.last_checked || 'not checked'}${watch.error ? ' · ' + watch.error : ''}`));
    const remove = node('button', 'Stop watching'); remove.type = 'button';
    remove.addEventListener('click', async () => {
      try {
        const response = await authorizedFetch(`/api/monitor/${encodeURIComponent(watch.id)}`, {method:'DELETE'});
        if (!response.ok) throw new Error('Could not stop monitoring');
        await monitor();
      } catch (error) { el('monitor-error').textContent = error.message; }
    });
    row.append(remove); el('watches').append(row);
  }
  if (!data.alerts.length) el('alerts').append(node('p', 'No local release alerts yet.'));
  for (const alert of data.alerts) {
    const row = node('div', undefined, alert.read ? 'history-item' : 'history-item unread');
    row.append(node('p', `${alert.message} · ${alert.created_at}`));
    const view = node('button', 'View scan'); view.type = 'button';
    view.addEventListener('click', async () => {
      try { await api(`/api/alerts/${encodeURIComponent(alert.id)}/read`, {method:'POST'}); await select(alert.scan_id); await monitor(); }
      catch (error) { el('monitor-error').textContent = error.message; }
    });
    row.append(view); el('alerts').append(row);
  }
}
el('watch-form').addEventListener('submit', async event => {
  event.preventDefault(); el('monitor-error').textContent = '';
  try {
    await api('/api/monitor', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ecosystem:el('watch-ecosystem').value,name:el('watch-name').value.trim()})});
    await monitor();
  } catch (error) { el('monitor-error').textContent = error.message; }
});
async function refreshMonitor() {
  try { await monitor(); } catch (error) { el('monitor-error').textContent = error.message; }
  setTimeout(refreshMonitor, 10000);
}
refreshMonitor();

function filterFiles() {
  const query = el('file-search').value.toLowerCase();
  const filter = el('file-filter').value;
  let visible = 0;
  [...el('files').children].forEach((row,index) => {
    const file = currentReport.files[index];
    row.hidden = !file.path.toLowerCase().includes(query) || (filter !== 'all' && file.state !== filter && file.classification !== filter);
    if (!row.hidden) visible++;
  });
  el('file-count').textContent = `${visible} of ${currentReport?.files?.length || 0} paths`;
}
el('file-search').addEventListener('input', () => { if(currentReport) filterFiles(); });
el('file-filter').addEventListener('change', () => { if(currentReport) filterFiles(); });
function inputTab(selectedSide) {
  for(const side of ['registry','local','text']) {
    const active = side === selectedSide;
    el(side+'-input').hidden = !active;
    el(side+'-tab').setAttribute('aria-selected',String(active));
    el(side+'-tab').tabIndex = active ? 0 : -1;
  }
}
for(const [index,side] of ['registry','local','text'].entries()) {
  el(side+'-tab').addEventListener('click',()=>inputTab(side));
  el(side+'-tab').addEventListener('keydown',event=>{
    if (['ArrowLeft','ArrowRight'].includes(event.key)) {
      event.preventDefault();
      const next=['registry','local','text'][(index+(event.key==='ArrowRight'?1:2))%3];
      inputTab(next);el(next+'-tab').focus();
    }
  });
}
el('baseline').addEventListener('click',()=>{el('ecosystem').value='npm';el('name').value='is-number';el('version').value='7.0.0';el('scan-form').requestSubmit();});
async function uploads() {
  const data=await api('/api/uploads');
  el('uploads').replaceChildren();
  if(!data.items.length) el('uploads').append(node('p','No stored uploads.'));
  for(const item of data.items) {
    const row=node('div',undefined,'history-item');
    row.append(node('span',`${item.label} · ${(item.bytes/1024).toFixed(1)} KiB`));
    const button=node('button','Remove');button.type='button';
    button.addEventListener('click',async()=>{
      try { const res=await authorizedFetch('/api/uploads/'+encodeURIComponent(item.id),{method:'DELETE'});if(!res.ok)throw new Error((await res.json()).detail);await uploads(); }
      catch(error){el('local-error').textContent=error.message;}
    });
    row.append(button);el('uploads').append(row);
  }
}
el('local-form').addEventListener('submit',async event=>{
  event.preventDefault();el('local-submit').disabled=true;el('local-error').textContent='';
  const created=[];let submitted=false;
  try {
    const request={name:el('artifact-file').files[0].name};
    for(const side of ['artifact','source']) {
      const file=el(side+'-file').files[0];
      if(!file || file.size>24*1024*1024 || !file.size)throw new Error('Each archive must contain 1 byte to 24 MiB.');
      const saved=await api('/api/uploads?label='+encodeURIComponent(file.name.slice(0,160)),{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:file});
      created.push(saved.id);request[side+'_id']=saved.id;
      request[side+'_layout']=el(side+'-layout').value;request[side+'_prefix']=el(side+'-prefix').value.trim();
    }
    const job=await api('/api/comparisons',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(request)});
    submitted=true;await history();await select(job.id);
  } catch(error){el('local-error').textContent=error.message;}
  finally {
    if(!submitted) for(const id of created) await authorizedFetch('/api/uploads/'+encodeURIComponent(id),{method:'DELETE'}).catch(()=>{});
    el('local-submit').disabled=false;await uploads().catch(()=>{});
  }
});
async function health() {
  try {const status=await api('/health');el('health-label').textContent=status.worker_alive?'Inspection engine online':'Worker unavailable';el('deployment-label').textContent=status.deployment;el('storage-warning').hidden=status.storage!=='ephemeral';el('access-panel').hidden=!status.auth_required || Boolean(workspaceKey);}
  catch {el('health-label').textContent='Backend disconnected';}
}
health();uploads().catch(error=>{el('local-error').textContent=error.message;});

async function explanationConfig() {
  try {
    const config = await api('/api/explanation/config');
    el('explain').disabled = !config.configured;
    el('explain').textContent = config.configured ? 'Explain findings' : 'Groq explanation · key not configured';
  } catch { el('explain').disabled = true; }
}
explanationConfig();

el('access-form').addEventListener('submit', async event => {
  event.preventDefault(); workspaceKey=el('access-key').value.trim();
  try {
    await api('/api/queue'); sessionStorage.setItem('releasedna-access-key',workspaceKey);
    el('access-key').value='';el('access-panel').hidden=true;el('access-error').textContent='';
    await Promise.all([history(),uploads(),monitor(),explanationConfig()]);el('error').textContent='';el('local-error').textContent='';el('monitor-error').textContent='';
  } catch(error) {workspaceKey='';sessionStorage.removeItem('releasedna-access-key');el('access-error').textContent=error.message;}
});
el('batch-form').addEventListener('submit',async event=>{
  event.preventDefault();el('batch-submit').disabled=true;el('batch-error').textContent='';
  try {
    const lines=el('batch-packages').value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
    if(!lines.length || lines.length>20)throw new Error('Enter 1 to 20 package lines.');
    const packages=lines.map((line,index)=>{
      const parts=line.split(',').map(x=>x.trim());
      if(parts.length!==3 || !['npm','pypi'].includes(parts[0]) || !parts[1] || !parts[2])throw new Error(`Line ${index+1}: use ecosystem,package,version.`);
      return {ecosystem:parts[0],name:parts[1],version:parts[2]};
    });
    const result=await api('/api/scans/batch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({packages})});
    await history();await select(result.items[0].id);
  } catch(error){el('batch-error').textContent=error.message;}
  finally{el('batch-submit').disabled=false;}
});
el('text-form').addEventListener('submit',async event=>{
  event.preventDefault();el('text-submit').disabled=true;el('text-error').textContent='';
  const created=[];let submitted=false;
  try {
    const request={name:el('text-name').value.trim()};
    for(const side of ['artifact','source']) {
      const file=el('text-'+side).files[0];
      if(!file || !file.size || file.size>120000)throw new Error('Each text file must contain 1 to 120,000 bytes.');
      const saved=await api('/api/uploads?label='+encodeURIComponent(file.name.slice(0,160)),{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:file});
      created.push(saved.id);request[side+'_id']=saved.id;
    }
    const job=await api('/api/text-comparisons',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(request)});
    submitted=true;await history();await select(job.id);
  } catch(error){el('text-error').textContent=error.message;}
  finally {
    if(!submitted)for(const id of created)await authorizedFetch('/api/uploads/'+encodeURIComponent(id),{method:'DELETE'}).catch(()=>{});
    el('text-submit').disabled=false;await uploads().catch(()=>{});
  }
});
async function refreshQueue() {
  try {
    const state=await api('/api/queue');
    const running=state.items.filter(x=>x.state==='running').length;
    el('queue-status').textContent=`One scan at a time · ${running} running · ${state.items.length-running} queued · capacity ${state.capacity}`;
    el('queue-items').replaceChildren(...state.items.map((job,index)=>{
      const row=node('div',undefined,'history-item');
      row.append(node('span',`${index+1}. ${job.package.name} ${job.package.version||''} · ${job.state}`));
      const view=node('button','View');view.type='button';view.addEventListener('click',()=>select(job.id));row.append(view);return row;
    }));
  }catch(error){el('queue-status').textContent=error.message;}
  setTimeout(refreshQueue,2000);
}
refreshQueue();
// Protected generated reports are downloaded with the workspace key; it never enters a URL.
for(const link of document.querySelectorAll('a[href="/corpus"],a[href="/evaluation"],a[href="/fresh-evaluation"],a[href="/docs"]')) {
  link.addEventListener('click',async event=>{
    if(!workspaceKey)return;
    event.preventDefault();
    try {
      const path=link.getAttribute('href')==='/docs'?'/openapi.json':link.getAttribute('href');
      const response=await authorizedFetch(path);
      if(!response.ok)throw new Error((await response.json()).detail || 'Report unavailable');
      const url=URL.createObjectURL(await response.blob());const save=node('a');save.href=url;
      save.download=path==='/openapi.json'?'releasedna-openapi.json':`releasedna-${path.slice(1)}.html`;
      save.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
    }catch(error){el('error').textContent=error.message;}
  });
}
