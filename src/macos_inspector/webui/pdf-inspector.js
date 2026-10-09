const pdfState = {busy: false, historyLoaded: false, loadingHistory: false};
const MAX_PDF_BYTES = 25 * 1024 * 1024;

function confirmPdfNavigation(event) {
  if (!pdfState.busy) return;
  event.preventDefault();
  event.returnValue = '';
}

async function checkPdfHealth() {
  const wasOffline = !state.online;
  try {
    const health = await api('/api/health');
    $('#session-help').classList.toggle('hidden', !health.session_required);
    if (health.session_required) {
      setConnection('offline');
      setInline('#pdf-message', 'Browser session not authorized. Reopen macOS Inspector.command.', true);
      return;
    }
    setConnection('online', health);
    if (!pdfState.historyLoaded || wasOffline) await loadPdfHistory();
  } catch (error) { setConnection('offline'); }
}

function updatePdfAvailability() {
  const file = $('#pdf-file')?.files[0];
  if ($('#inspect-pdf')) $('#inspect-pdf').disabled = !state.online || pdfState.busy || !file || file.size === 0 || file.size > MAX_PDF_BYTES;
  if ($('#pdf-file')) $('#pdf-file').disabled = pdfState.busy;
  if ($('#clear-pdf')) $('#clear-pdf').disabled = pdfState.busy || !file;
  $('#pdf-inspector')?.classList.toggle('pdf-busy', pdfState.busy);
  $('#pdf-result')?.setAttribute('aria-busy', String(pdfState.busy));
  if ($('#pdf-button-label')) $('#pdf-button-label').textContent = pdfState.busy ? 'Inspecting PDF...' : 'Inspect PDF';
  const step = pdfState.busy ? 'inspect' : !$('#pdf-result')?.classList.contains('hidden') ? 'review' : 'select';
  ['select', 'inspect', 'review'].forEach(name => {
    const element = $(`#pdf-step-${name}`);
    if (name === step) element?.setAttribute('aria-current', 'step');
    else element?.removeAttribute('aria-current');
  });
}

function pdfReportLinks(reports) {
  return ['html', 'json'].filter(format => /^\/(?:reports\/|private-reports\/[0-9a-f]{48}\/)macos-inspector-pdf-[0-9a-f-]{36}\.(html|json)$/.test(reports?.[format] || '')).map(format => `<a class="secondary-button" href="${escapeHtml(reports[format])}" target="_blank" rel="noopener">${format === 'html' ? 'Open HTML report' : 'Open JSON report'}</a>`).join('');
}

function pdfTable(rows, fields) {
  if (!rows?.length) return '<p class="muted">No records in the inspected scope. Check the analysis limitations.</p>';
  return `<div class="pdf-table-wrap"><table role="table"><thead role="rowgroup"><tr role="row">${fields.map(([,label]) => `<th role="columnheader" scope="col">${escapeHtml(label)}</th>`).join('')}</tr></thead><tbody role="rowgroup">${rows.map(row => `<tr role="row">${fields.map(([key,label]) => `<td role="cell" data-label="${escapeHtml(label)}">${escapeHtml(row[key] ?? '')}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
}

function renderPdfInspection(payload) {
  const report = payload.report;
  const panel = $('#pdf-result');
  const file = report.file;
  const structure = report.structure;
  const assessment = report.assessment;
  const limits = report.limitations || [];
  const answers = (report.answers || []).map(row => `<article><h4>${escapeHtml(row.question)}</h4><strong>${escapeHtml(row.answer)}</strong><p>${escapeHtml(row.note)}</p></article>`).join('');
  const scripts = (report.javascript || []).map(item => `<details class="pdf-evidence"><summary>JavaScript | ${escapeHtml(item.context)} | ${escapeHtml(item.bytes)} bytes</summary><p>${escapeHtml((item.indicators || []).join('; ') || 'No supported heuristic indicators found. This is not proof of harmless code.')}</p><p>SHA-256: <code>${escapeHtml(item.sha256)}</code></p><pre>${escapeHtml(item.preview)}</pre><small>${item.preview_truncated ? 'Excerpt truncated. ' : ''}Code was not executed.</small></details>`).join('') || '<p class="muted">No readable JavaScript recorded. Check structural names and limitations.</p>';
  panel.innerHTML = `<div class="pdf-results-heading"><div><p class="eyebrow">DOCUMENT EVIDENCE</p><h3>Inspection results</h3></div><div class="pdf-report-links">${pdfReportLinks(payload.reports)}</div></div><div class="pdf-assessment"><p class="eyebrow">${escapeHtml(assessment.label)}</p><h3>${escapeHtml(file.name)}</h3><p>${escapeHtml(assessment.explanation)}</p><p class="pdf-next-step"><strong>Next step</strong> ${escapeHtml(assessment.next_step)}</p><p>${escapeHtml(report.boundary)}</p><small>Malware verdict: Not determined | Analyzed ${escapeHtml(report.analyzed_at)}</small></div>
    <div class="pdf-answers">${answers}</div>
    <details class="pdf-evidence" open><summary>Identity and structure</summary><p>${escapeHtml(file.bytes)} bytes | ${escapeHtml(structure.header)} at byte ${escapeHtml(structure.header_offset)} | ${escapeHtml(structure.object_count)} observed objects (${escapeHtml(structure.compressed_object_count)} compressed)</p><p>SHA-256: <code>${escapeHtml(file.sha256)}</code></p><p>Final EOF marker: ${escapeHtml(structure.final_eof_marker)} | Encryption indicated: ${escapeHtml(structure.encrypted_or_indicated)}</p><small>${escapeHtml(structure.xref_validation)}</small></details>
    <details class="pdf-evidence" open><summary>Actions and declared triggers</summary><p>Document open is different from a link click or another event. A declared action is not proof that a reader executes it.</p>${pdfTable(report.actions, [['type','Action'],['trigger','Declared trigger'],['target','Declared target'],['context','Object context']])}</details>
    <details class="pdf-evidence" open><summary>JavaScript evidence</summary>${scripts}</details>
    <details class="pdf-evidence"><summary>Destinations, not observed requests</summary><p>Plain text only. No destination was contacted.</p>${pdfTable(report.destinations, [['value','Destination'],['kind','Recorded as'],['context','Object context']])}</details>
    <details class="pdf-evidence"><summary>Attachments</summary>${pdfTable(report.attachments, [['filename','Filename'],['context','Object context'],['note','Limit']])}</details>
    <details class="pdf-evidence"><summary>Parsed structural names and declared metadata</summary><p>Counts are observations, not proof that an action runs.</p>${pdfTable(Object.entries(report.name_counts || {}).map(([name,count]) => ({name: '/' + name,count})), [['name','Name'],['count','Occurrences']])}${pdfTable(Object.entries(report.metadata || {}).map(([name,value]) => ({name,value})), [['name','Field'],['value','Declared value (unverified)']])}</details>
    <details class="pdf-evidence" ${limits.length ? 'open' : ''}><summary>Analysis limitations (${limits.length})</summary><ul>${limits.map(item => `<li>${escapeHtml(item)}</li>`).join('') || '<li>No additional collection limits recorded within the supported static scope.</li>'}</ul><p>${escapeHtml(report.privacy)}</p></details>`;
  panel.classList.remove('hidden');
  $('#pdf-empty').classList.add('hidden');
  updatePdfAvailability();
}

async function inspectSelectedPdf() {
  const file = $('#pdf-file').files[0];
  if (pdfState.busy || !state.online || !file) return;
  if (!file.size || file.size > MAX_PDF_BYTES) return setInline('#pdf-message', 'Select a nonempty PDF no larger than 25 MiB.', true);
  pdfState.busy = true;
  window.addEventListener('beforeunload', confirmPdfNavigation);
  updatePdfAvailability();
  $('#pdf-result').classList.add('hidden');
  $('#pdf-empty').classList.add('hidden');
  setInline('#pdf-message', 'Inspecting locally. No PDF content is being executed or sent to external services.');
  try {
    const payload = await api('/api/pdf-inspector', {method: 'POST', headers: {'Content-Type': 'application/pdf', 'X-MacOS-Inspector': '1', 'X-PDF-Filename': encodeURIComponent(file.name)}, body: file});
    renderPdfInspection(payload);
    setInline('#pdf-message', 'Inspection finished. The original was not retained. Review limitations before interpreting missing indicators.');
    await loadPdfHistory();
  } catch (error) {
    setInline('#pdf-message', error.message, true);
  } finally {
    pdfState.busy = false;
    window.removeEventListener('beforeunload', confirmPdfNavigation);
    updatePdfAvailability();
  }
}

async function loadPdfHistory() {
  if (!state.online || pdfState.loadingHistory) return;
  pdfState.loadingHistory = true;
  $('#refresh-pdf-history').disabled = true;
  try {
    const payload = await api('/api/pdf-inspections');
    $('#pdf-history-list').innerHTML = (payload.inspections || []).map(row => `<article class="pdf-history-row"><strong>${escapeHtml(row.file.name)}</strong><small>${escapeHtml(row.analyzed_at)} | ${escapeHtml(row.label)}</small><code>${escapeHtml(row.file.sha256)}</code><div class="pdf-report-links">${pdfReportLinks(row.reports)}</div></article>`).join('') || '<p class="muted">No PDF inspections saved in this output directory.</p>';
    pdfState.historyLoaded = true;
  } catch (error) { $('#pdf-history-list').textContent = error.message; }
  finally { pdfState.loadingHistory = false; $('#refresh-pdf-history').disabled = false; }
}

function resetPdfResult() {
  $('#pdf-result').classList.add('hidden');
  $('#pdf-result').innerHTML = '';
  $('#pdf-empty').classList.remove('hidden');
  const file = $('#pdf-file').files[0];
  const size = file && file.size < 1024 * 1024 ? `${file.size.toLocaleString('en-US')} bytes` : file ? `${(file.size / 1024 / 1024).toFixed(2)} MiB` : '';
  $('#pdf-selected-file').textContent = file ? `${file.name} | ${size}` : 'No document selected.';
  const invalid = Boolean(file && (!file.size || file.size > MAX_PDF_BYTES));
  setInline('#pdf-message', invalid ? 'Select a nonempty PDF no larger than 25 MiB.' : file ? 'Ready for local inspection. The original PDF will not be retained.' : 'The original is not retained. Reports can contain sensitive document data.', invalid);
  updatePdfAvailability();
}

document.addEventListener('DOMContentLoaded', async () => {
  if (window.location.protocol === 'file:' || new URLSearchParams(window.location.search).has('source-preview')) {
    document.body.classList.add('file-mode');
    $('#local-launcher-help').classList.remove('hidden');
    return;
  }
  $('#pdf-file').addEventListener('change', resetPdfResult);
  $('#clear-pdf').addEventListener('click', () => { if (!pdfState.busy) { $('#pdf-file').value = ''; resetPdfResult(); $('#pdf-file').focus(); } });
  $('#inspect-pdf').addEventListener('click', inspectSelectedPdf);
  $('#refresh-pdf-history').addEventListener('click', loadPdfHistory);
  window.addEventListener('hashchange', async () => {
    if (new URLSearchParams(window.location.hash.slice(1)).has('launch')) {
      await authorizeLaunchFragment();
      await checkPdfHealth();
    }
  });
  window.addEventListener('pagehide', () => clearInterval(state.healthPoll));
  window.addEventListener('pageshow', event => {
    if (event.persisted) {
      checkPdfHealth();
      state.healthPoll = setInterval(checkPdfHealth, 4000);
    }
  });
  setConnection('checking');
  await authorizeLaunchFragment();
  await checkPdfHealth();
  state.healthPoll = setInterval(checkPdfHealth, 4000);
});
