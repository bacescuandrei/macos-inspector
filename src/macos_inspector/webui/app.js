const state = { config: null, activeJob: null, baselineJob: null, poll: null, healthPoll: null, online: false, starting: false, loadingConfig: false, findings: [], filteredFindings: [], findingPage: 1, findingPageSize: 50, historyScans: [] };

const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
const api = async (url, options = {}) => {
  let response;
  try {
    response = await fetch(url, options);
  } catch (error) {
    setConnection('offline');
    throw new Error('Dashboard server unavailable. Start it with: python3 -m macos_inspector --web');
  }
  let payload;
  try {
    payload = await response.json();
  } catch (error) {
    throw new Error('Dashboard returned an invalid response. Open this page through http://127.0.0.1:8765, not as a file.');
  }
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
};

function setMessage(message, error = false) {
  const element = $('#action-message');
  element.textContent = message || '';
  element.classList.toggle('error', error);
}

function updateRunAvailability() {
  const disabled = !state.online || state.starting || Boolean(state.activeJob);
  const runButton = $('#run-selected');
  if (runButton) runButton.disabled = disabled;
  document.querySelectorAll('[data-run-one]').forEach((button) => { button.disabled = disabled; });
  const cancelButton = $('#cancel-scan');
  if (cancelButton && !cancelButton.classList.contains('hidden')) cancelButton.disabled = !state.online;
}

function setConnection(status, health = null) {
  const element = $('#connection');
  state.online = status === 'online';
  if (element) {
    element.className = `connection ${status}`;
    element.textContent = status === 'online' ? `Connected · v${health?.version || '?'}` : status === 'checking' ? 'Connecting…' : 'Offline · retrying';
    element.title = status === 'online' && health?.started_at ? `Server started ${health.started_at}` : 'The dashboard will reconnect automatically.';
  }
  updateRunAvailability();
}

function finishActiveJob(jobId) {
  if (state.activeJob === jobId) state.activeJob = null;
  state.starting = false;
  $('#cancel-scan').classList.add('hidden');
  updateRunAvailability();
}

function renderCollectors() {
  $('#collectors').innerHTML = state.config.collectors.map((collector) => `
    <div class="collector-card${collector.external_network ? ' external' : ''}">
      <input type="checkbox" id="collector-${escapeHtml(collector.id)}" data-collector="${escapeHtml(collector.id)}">
      <label for="collector-${escapeHtml(collector.id)}"><span class="collector-title">${escapeHtml(collector.title)}${collector.external_network ? '<em class="online-badge">Online opt-in</em>' : ''}</span><span class="collector-id">${escapeHtml(collector.id)}</span>${collector.privacy_note ? `<small class="collector-note">${escapeHtml(collector.privacy_note)}</small>` : ''}</label>
      <button type="button" class="mini-button" data-run-one="${escapeHtml(collector.id)}">Run</button>
    </div>`).join('');
  document.querySelectorAll('[data-run-one]').forEach((button) => button.addEventListener('click', () => startScan([button.dataset.runOne])));
  document.querySelectorAll('[data-collector]').forEach((input) => input.addEventListener('change', syncActiveProfile));
  renderProfiles();
  updateRunAvailability();
}

function renderProfiles() {
  const profiles = state.config.profiles || [];
  $('#scan-profiles').innerHTML = profiles.map((profile) => `<button type="button" class="profile-card" data-profile="${escapeHtml(profile.id)}" title="${escapeHtml(profile.description)}"><strong>${escapeHtml(profile.title)}</strong><small>${escapeHtml(profile.description)}</small><span>${escapeHtml(profile.collectors.length)} section${profile.collectors.length === 1 ? '' : 's'}</span></button>`).join('');
  document.querySelectorAll('[data-profile]').forEach((button) => button.addEventListener('click', () => selectProfile(button.dataset.profile, true)));
  const defaultProfile = profiles.find((profile) => profile.default) || profiles[0];
  if (defaultProfile) selectProfile(defaultProfile.id, false);
}

function selectedCollectors() {
  return selectedValues('collector');
}

function syncActiveProfile() {
  const selected = new Set(selectedCollectors());
  document.querySelectorAll('[data-profile]').forEach((button) => {
    const profile = (state.config.profiles || []).find((item) => item.id === button.dataset.profile);
    const matches = profile && profile.collectors.length === selected.size && profile.collectors.every((collector) => selected.has(collector));
    button.classList.toggle('active', Boolean(matches));
    button.setAttribute('aria-pressed', matches ? 'true' : 'false');
  });
}

function selectProfile(profileId, announce = true) {
  const profile = (state.config.profiles || []).find((item) => item.id === profileId);
  if (!profile) return;
  const selected = new Set(profile.collectors);
  document.querySelectorAll('[data-collector]').forEach((input) => { input.checked = selected.has(input.dataset.collector); });
  syncActiveProfile();
  if (announce) setMessage(`${profile.title} selected · ${profile.collectors.length} audit section${profile.collectors.length === 1 ? '' : 's'}. Review the scope, then run the audit.`);
}

function renderFormats() {
  const labels = { html: 'Interactive HTML', json: 'JSON', markdown: 'Markdown', csv: 'CSV', sarif: 'SARIF', manifest: 'Evidence manifest', pdf: 'PDF', bundle: 'Case bundle ZIP' };
  const capabilities = state.config.format_capabilities || {};
  $('#formats').innerHTML = state.config.formats.map((format) => {
    const capability = capabilities[format] || {available: true, reason: ''};
    const available = capability.available !== false;
    const checked = available ? 'checked' : '';
    const unavailable = available ? '' : '<span class="format-unavailable">Unavailable</span>';
    return `<label class="format-option${available ? '' : ' unavailable'}" title="${escapeHtml(capability.reason || '')}" aria-disabled="${available ? 'false' : 'true'}"><input type="checkbox" data-format="${escapeHtml(format)}" ${checked} ${available ? '' : 'disabled'}> ${escapeHtml(labels[format] || format.toUpperCase())}${unavailable}</label>`;
  }).join('');
}

async function loadReadiness() {
  const button = $('#refresh-readiness');
  button.disabled = true;
  $('#readiness-summary').textContent = 'Checking local access…';
  try {
    const readiness = await api('/api/readiness');
    const summary = readiness.summary || {};
    $('#readiness-summary').innerHTML = `<strong class="readiness-overall readiness-${escapeHtml(readiness.overall)}">${escapeHtml(readiness.overall)}</strong><span>${escapeHtml(summary.ready || 0)} ready · ${escapeHtml(summary.limited || 0)} limited · ${escapeHtml(summary.unavailable || 0)} unavailable · ${escapeHtml(summary.optional || 0)} optional</span>`;
    $('#readiness-checks').innerHTML = (readiness.checks || []).map((check) => `<article class="readiness-card"><div><strong>${escapeHtml(check.title)}</strong><span class="readiness-status readiness-${escapeHtml(check.status)}">${escapeHtml(check.status)}</span></div><p>${escapeHtml(check.detail)}</p><small>${escapeHtml(check.impact)}</small>${check.action && check.action !== 'No action required.' ? `<details><summary>Recommended action</summary><p>${escapeHtml(check.action)}</p></details>` : ''}</article>`).join('');
  } catch (error) {
    $('#readiness-summary').textContent = 'Readiness check unavailable.';
    $('#readiness-checks').innerHTML = `<p class="muted">${escapeHtml(error.message)}</p>`;
  } finally {
    button.disabled = false;
  }
}

function selectedValues(attribute) {
  return [...document.querySelectorAll(`[data-${attribute}]:checked`)].map((element) => element.dataset[attribute]);
}

async function startScan(collectorOverride = null) {
  const collectors = collectorOverride || selectedCollectors();
  const formats = selectedValues('format');
  if (!collectors.length) return setMessage('Select at least one audit section.', true);
  if (!formats.length) return setMessage('Select at least one report format.', true);
  const onlineCollectors = (state.config.collectors || []).filter((collector) => collectors.includes(collector.id) && collector.external_network);
  if (onlineCollectors.length && !window.confirm(`This scan will access the internet for: ${onlineCollectors.map((collector) => collector.title).join(', ')}. No host, case, hash, or file data is sent. Continue?`)) return;
  state.starting = true;
  updateRunAvailability();
  $('#cancel-scan').classList.remove('hidden');
  $('#cancel-scan').disabled = false;
  setMessage('Starting read-only collection…');
  try {
    const job = await api('/api/scans', { method: 'POST', headers: {'Content-Type': 'application/json', 'X-MacOS-Inspector': '1'}, body: JSON.stringify({ collectors, formats, minimum: $('#minimum').value, case_reference: $('#case-reference').value, analyst: $('#analyst').value }) });
    state.activeJob = job.job_id;
    state.starting = false;
    updateRunAvailability();
    pollJob(job.job_id);
  } catch (error) {
    state.starting = false;
    state.activeJob = null;
    $('#cancel-scan').classList.add('hidden');
    updateRunAvailability();
    setMessage(error.message, true);
  }
}

async function pollJob(jobId) {
  if (state.poll) clearTimeout(state.poll);
  try {
    const job = await api(`/api/scans/${encodeURIComponent(jobId)}`);
    renderProgress(job);
    if (job.state === 'completed') {
      finishActiveJob(jobId);
      setMessage('Scan complete. Findings and reports are ready.');
      renderReports(job);
      await loadReport(job);
      loadHistory();
      return;
    }
    if (job.state === 'failed') {
      finishActiveJob(jobId);
      setMessage(job.error || 'The scan failed.', true);
      return;
    }
    if (job.state === 'cancelled') {
      finishActiveJob(jobId);
      setMessage('Scan cancelled. No partial reports were generated.');
      return;
    }
    if (job.state === 'interrupted') {
      finishActiveJob(jobId);
      setMessage(job.error || 'The scan was interrupted by a dashboard restart. No partial reports were generated.', true);
      return;
    }
    state.poll = setTimeout(() => pollJob(jobId), 700);
  } catch (error) {
    setMessage(error.message, true);
  }
}

function renderProgress(job) {
  const pill = $('#scan-state');
  pill.textContent = job.state === 'completed' ? 'Complete' : job.state === 'failed' ? 'Failed' : job.state === 'cancelled' ? 'Cancelled' : job.state === 'interrupted' ? 'Interrupted' : job.state === 'running' ? 'Running' : 'Queued';
  pill.className = `state-pill ${job.state === 'completed' ? 'complete' : job.state === 'failed' ? 'failed' : job.state === 'cancelled' ? 'cancelled' : job.state === 'interrupted' ? 'interrupted' : job.state === 'running' ? 'running' : ''}`;
  const completed = job.state === 'completed' ? (job.total_collectors || job.collectors?.length || 0) : (job.completed_collectors || 0);
  const total = job.total_collectors || job.collectors?.length || 0;
  $('#progress').className = 'progress-box';
  const headline = job.state === 'completed' ? 'Scan completed' : job.state === 'failed' ? 'Scan failed' : job.state === 'cancelled' ? 'Scan cancelled' : job.state === 'interrupted' ? 'Scan interrupted by dashboard restart' : job.cancel_requested ? 'Stopping safely…' : job.current_collector ? `Collecting ${job.current_collector}` : 'Preparing collection…';
  const itemTotal = Number(job.total_items || 0);
  const itemCompleted = Math.min(Number(job.completed_items || 0), itemTotal);
  const percent = itemTotal ? Math.round(itemCompleted / itemTotal * 100) : 0;
  let itemProgress = '';
  if (job.state === 'running' && itemTotal) {
    const ordinal = Math.min(itemCompleted + (job.current_item ? 1 : 0), itemTotal);
    const remaining = Math.max(0, Number(job.estimated_seconds_remaining || 0));
    const estimate = remaining ? ` · about ${formatDuration(remaining)} remaining` : '';
    const itemLabel = job.current_item ? ` · ${escapeHtml(job.current_item)}` : '';
    itemProgress = `<div class="item-progress"><div class="progress-meter" role="progressbar" aria-label="Collector item progress" aria-valuemin="0" aria-valuemax="${itemTotal}" aria-valuenow="${itemCompleted}"><span style="width:${percent}%"></span></div><small>Application ${ordinal} of ${itemTotal}${itemLabel}${estimate}</small></div>`;
  }
  $('#progress').innerHTML = `<strong>${escapeHtml(headline)}</strong><span>${completed} of ${total} audit sections complete</span>${itemProgress}`;
}

function formatDuration(seconds) {
  if (seconds < 60) return `${Math.max(1, seconds)}s`;
  const minutes = Math.ceil(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

async function cancelScan() {
  if (!state.activeJob) return;
  const button = $('#cancel-scan');
  button.disabled = true;
  setMessage('Cancellation requested. Stopping the active read-only command…');
  try {
    await api(`/api/scans/${encodeURIComponent(state.activeJob)}/cancel`, {method: 'POST', headers: {'X-MacOS-Inspector': '1'}});
  } catch (error) {
    button.disabled = false;
    setMessage(error.message, true);
  }
}

function renderReports(job) {
  const labels = { html: 'Open HTML report', json: 'Open JSON', markdown: 'Open Markdown', csv: 'Open CSV', sarif: 'Open SARIF', manifest: 'Open manifest', pdf: 'Open PDF', bundle: 'Download case bundle' };
  const links = Object.entries(job.reports || {}).map(([format, url]) => `<a href="${escapeHtml(url)}" target="_blank" rel="noreferrer">${escapeHtml(labels[format] || format.toUpperCase())}</a>`).join('');
  const verify = job.reports?.manifest && job.scan_id ? `<button type="button" class="verify-button" data-verify-scan="${escapeHtml(job.scan_id)}">Verify evidence</button>` : '';
  $('#report-links').innerHTML = `<strong>Exports</strong>${links}${verify}`;
  $('#report-links').classList.remove('hidden');
  const verifyButton = document.querySelector('[data-verify-scan]');
  if (verifyButton) verifyButton.addEventListener('click', () => verifyEvidence(verifyButton));
}

async function verifyEvidence(button) {
  button.disabled = true;
  setMessage('Verifying manifest, signatures and report digests…');
  try {
    const result = await api(`/api/manifests/${encodeURIComponent(button.dataset.verifyScan)}/verify`);
    const identity = result.algorithm ? ` Signature: ${result.algorithm}${result.public_key_sha256 ? ` · key ${result.public_key_sha256.slice(0, 16)}…` : ''}.` : ' Manifest is unsigned.';
    setMessage(result.valid ? `Evidence verified: ${result.artifact_count} report(s) match.${identity}` : `Verification failed: ${result.errors.join(' ')}`, !result.valid);
  } catch (error) {
    setMessage(error.message, true);
  } finally {
    button.disabled = false;
  }
}

async function loadReport(job) {
  if (!job.reports || !job.reports.json) return;
  try {
    const payload = await api(job.reports.json);
    renderCaseMetadata(payload.metadata || {});
    renderSummary(payload.summary);
    renderTimeline(payload.timeline || []);
    renderFindings(payload.findings || []);
  } catch (error) { setMessage(`Could not load report data: ${error.message}`, true); }
}

function renderCaseMetadata(metadata) {
  const banner = $('#case-banner');
  const values = [
    metadata.case_reference ? ['Case', metadata.case_reference] : null,
    metadata.analyst ? ['Analyst', metadata.analyst] : null,
    metadata.hostname ? ['Host', metadata.hostname] : null,
    metadata.scan_id ? ['Scan', metadata.scan_id] : null,
  ].filter(Boolean);
  banner.innerHTML = values.map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join('');
  banner.classList.toggle('hidden', !values.length);
}

function renderSummary(summary) {
  const cards = [
    ['Score', `${summary.overall_score}/100`],
    ['Findings shown', summary.finding_count],
    ['Total findings', summary.total_finding_count ?? summary.finding_count],
    ['Coverage', `${Math.round(Object.values(summary.category_coverage || {}).reduce((a, b) => a + b, 0) / Math.max(1, Object.keys(summary.category_coverage || {}).length))}%`],
  ];
  $('#summary').innerHTML = cards.map(([label, value]) => `<div class="summary-item"><span class="summary-label">${escapeHtml(label)}</span><span class="summary-value">${escapeHtml(value)}</span></div>`).join('');
  $('#summary').classList.remove('hidden');
}

function renderTimeline(events) {
  const panel = $('#timeline-panel');
  if (!events.length) { panel.classList.add('hidden'); return; }
  $('#timeline-count').textContent = events.length;
  $('#timeline').innerHTML = events.slice(-250).reverse().map((event) => `<div class="timeline-row"><time>${escapeHtml(event.timestamp)}</time><span>${escapeHtml(event.category)}</span><strong>${escapeHtml(event.summary)}</strong><code>${escapeHtml(event.finding_id)}</code></div>`).join('');
  panel.classList.remove('hidden');
}

function renderFindings(findings) {
  state.findings = findings;
  state.findingPage = 1;
  const statuses = [...new Set(findings.map((finding) => finding.status).filter(Boolean))].sort();
  const categories = [...new Set(findings.map((finding) => finding.category).filter(Boolean))].sort();
  $('#finding-status-filter').innerHTML = '<option value="">All statuses</option>' + statuses.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join('');
  $('#finding-category-filter').innerHTML = '<option value="">All categories</option>' + categories.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join('');
  $('#finding-search').value = '';
  $('#findings-toolbar').classList.toggle('hidden', !findings.length);
  applyFindingFilters();
}

function applyFindingFilters(resetPage = false) {
  if (resetPage) state.findingPage = 1;
  const query = $('#finding-search').value.trim().toLowerCase();
  const status = $('#finding-status-filter').value;
  const category = $('#finding-category-filter').value;
  state.filteredFindings = state.findings.filter((finding) => {
    if (status && finding.status !== status) return false;
    if (category && finding.category !== category) return false;
    if (!query) return true;
    return [finding.finding_id, finding.title, finding.observed_result, finding.category, finding.status, JSON.stringify(finding.evidence || [])].join(' ').toLowerCase().includes(query);
  });
  const pages = Math.max(1, Math.ceil(state.filteredFindings.length / state.findingPageSize));
  state.findingPage = Math.min(state.findingPage, pages);
  renderFindingPage();
}

function renderFindingPage() {
  const total = state.filteredFindings.length;
  const start = (state.findingPage - 1) * state.findingPageSize;
  const visible = state.filteredFindings.slice(start, start + state.findingPageSize);
  if (!state.findings.length) {
    $('#findings').innerHTML = '<div class="empty-state"><h3>No findings match this severity filter</h3><p>The scan completed successfully, but no findings are visible at the selected threshold.</p></div>';
  } else if (!visible.length) {
    $('#findings').innerHTML = '<div class="empty-state"><h3>No matching findings</h3><p>Adjust the search, status, or category filters.</p></div>';
  } else $('#findings').innerHTML = visible.map((finding, index) => {
    const severity = finding.severity.toLowerCase().replaceAll(' ', '-');
    const evidence = escapeHtml(JSON.stringify(finding.evidence || [], null, 2));
    const commands = (finding.commands_used || []).map((command) => `<li><code>${escapeHtml(command)}</code></li>`).join('') || '<li>None</li>';
    const references = (finding.references || []).map((reference) => `<li><a href="${escapeHtml(reference)}" target="_blank" rel="noreferrer">${escapeHtml(reference)}</a></li>`).join('') || '<li>None</li>';
    return `<article class="finding" data-finding-index="${start + index}"><div class="finding-head"><span class="severity severity-${severity}">${escapeHtml(finding.severity)}</span><span class="finding-status">${escapeHtml(finding.status)}</span><span class="finding-title">${escapeHtml(finding.title)}</span><span class="finding-id">${escapeHtml(finding.finding_id)}</span><button type="button" class="finding-toggle">Details</button></div><p class="finding-observed">${escapeHtml(finding.observed_result)}</p><div class="finding-details"><p><strong>Why it matters</strong><br>${escapeHtml(finding.why_it_matters)}</p><p><strong>Recommendation</strong><br>${escapeHtml(finding.recommendation)}</p><p><strong>Commands used</strong></p><ul>${commands}</ul><p><strong>References</strong></p><ul>${references}</ul><p><strong>Evidence</strong></p><pre>${evidence}</pre></div></article>`;
  }).join('');
  document.querySelectorAll('.finding-toggle').forEach((button) => button.addEventListener('click', () => button.closest('.finding').classList.toggle('open')));
  $('#finding-range').textContent = total ? `${start + 1}–${Math.min(start + state.findingPageSize, total)} of ${total}` : '0 findings';
  $('#findings-prev').disabled = state.findingPage <= 1;
  $('#findings-next').disabled = start + state.findingPageSize >= total;
}

async function loadHistory() {
  try {
    const payload = await api('/api/scans');
    state.historyScans = payload.scans;
    renderHistory();
  } catch (error) { $('#history').innerHTML = `<p class="muted">${escapeHtml(error.message)}</p>`; }
}

async function loadDashboardData() {
  if (state.loadingConfig) return;
  state.loadingConfig = true;
  try {
    state.config = await api('/api/config');
    renderCollectors();
    renderFormats();
    await loadReadiness();
    await loadHistory();
  } catch (error) {
    setMessage(error.message, true);
  } finally {
    state.loadingConfig = false;
  }
}

async function checkHealth() {
  const wasOffline = !state.online;
  try {
    const health = await api('/api/health');
    setConnection('online', health);
    if (!state.config) await loadDashboardData();
    if (health.active_job && !state.activeJob) {
      state.activeJob = health.active_job.job_id;
      $('#cancel-scan').classList.remove('hidden');
      updateRunAvailability();
      pollJob(state.activeJob);
    } else if (wasOffline && state.activeJob) {
      pollJob(state.activeJob);
    }
    return health;
  } catch (error) {
    setConnection('offline');
    return null;
  }
}

function renderHistory() {
  const query = $('#history-search').value.trim().toLowerCase();
  const matching = state.historyScans.filter((job) => !query || [job.scan_id, job.case_reference, job.analyst, job.state, ...(job.collectors || [])].join(' ').toLowerCase().includes(query));
  const visible = matching.slice(0, 50);
  $('#history-count').textContent = matching.length === state.historyScans.length ? `${matching.length} scan${matching.length === 1 ? '' : 's'}` : `${matching.length} of ${state.historyScans.length}`;
  if (!state.historyScans.length) { $('#history').innerHTML = '<p class="muted">No previous scans in this output directory.</p>'; return; }
  if (!visible.length) { $('#history').innerHTML = '<p class="muted">No scans match this search.</p>'; return; }
  $('#history').innerHTML = visible.map((job) => {
    const actions = job.reports?.json ? `<button type="button" class="history-baseline${state.baselineJob?.job_id === job.job_id ? ' selected' : ''}" data-baseline-id="${escapeHtml(job.job_id)}">Baseline</button><button type="button" class="history-compare" data-compare-id="${escapeHtml(job.job_id)}">Compare</button><button type="button" class="history-open" data-history-id="${escapeHtml(job.job_id)}">View</button>` : '';
    return `<div class="history-row"><div class="history-main"><strong>${job.case_reference ? `<span class="case-tag">${escapeHtml(job.case_reference)}</span> ` : ''}${escapeHtml((job.collectors || []).join(' · '))}</strong><small>${escapeHtml(job.completed_at || job.created_at || '')} · score ${escapeHtml(job.summary?.overall_score ?? '—')}${job.analyst ? ` · ${escapeHtml(job.analyst)}` : ''}${job.error ? ` · ${escapeHtml(job.error)}` : ''}<code>${escapeHtml(job.scan_id || '')}</code></small></div><span class="status-pill status-${escapeHtml(job.state)}">${escapeHtml(job.state)}</span>${actions}</div>`;
  }).join('') + (matching.length > 50 ? `<p class="muted">Showing the 50 most recent matches.</p>` : '');
  document.querySelectorAll('[data-history-id]').forEach((button) => button.addEventListener('click', () => loadHistoryJob(state.historyScans.find((item) => item.job_id === button.dataset.historyId))));
  document.querySelectorAll('[data-baseline-id]').forEach((button) => button.addEventListener('click', () => setBaseline(state.historyScans.find((item) => item.job_id === button.dataset.baselineId))));
  document.querySelectorAll('[data-compare-id]').forEach((button) => button.addEventListener('click', () => compareWithBaseline(state.historyScans.find((item) => item.job_id === button.dataset.compareId))));
}

function setBaseline(job) {
  if (!job?.scan_id || !job.reports?.json) return setMessage('This scan has no JSON report and cannot be used as a baseline.', true);
  state.baselineJob = job;
  setMessage(`Baseline selected: ${job.scan_id.slice(0, 8)} · score ${job.summary?.overall_score ?? '—'}. Choose Compare on another scan.`);
  document.querySelectorAll('[data-baseline-id]').forEach((button) => button.classList.toggle('selected', button.dataset.baselineId === job.job_id));
}

async function compareWithBaseline(job) {
  if (!state.baselineJob) return setMessage('Select a baseline scan first.', true);
  if (!job?.scan_id || !job.reports?.json) return setMessage('This scan has no JSON report and cannot be compared.', true);
  if (job.scan_id === state.baselineJob.scan_id) return setMessage('Choose a different scan to compare with the baseline.', true);
  setMessage('Comparing normalized findings…');
  try {
    const comparison = await api(`/api/compare?baseline=${encodeURIComponent(state.baselineJob.scan_id)}&current=${encodeURIComponent(job.scan_id)}`);
    renderComparison(comparison);
    setMessage('Comparison complete.');
    document.querySelector('.results-panel').scrollIntoView({behavior: 'smooth', block: 'start'});
  } catch (error) { setMessage(error.message, true); }
}

function renderComparison(comparison) {
  const delta = comparison.score_delta > 0 ? `+${comparison.score_delta}` : String(comparison.score_delta);
  $('#comparison-summary').innerHTML = [['Score change', delta], ['New', comparison.counts.new], ['Resolved', comparison.counts.resolved], ['Changed', comparison.counts.changed]].map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join('');
  const rows = [
    ...comparison.new.map((finding) => ({kind: 'New', id: finding.finding_id, title: finding.title, detail: `${finding.severity} · ${finding.status}`})),
    ...comparison.resolved.map((finding) => ({kind: 'Resolved', id: finding.finding_id, title: finding.title, detail: `${finding.severity} · ${finding.status}`})),
    ...comparison.changed.map((finding) => ({kind: 'Changed', id: finding.finding_id, title: finding.title, detail: Object.entries(finding.changes).map(([field, values]) => `${field}: ${values.before} → ${values.after}`).join(' · ')})),
  ];
  const scopeWarning = comparison.scope?.changed ? `<div class="comparison-warning"><strong>Collection scope changed.</strong> Added: ${escapeHtml(comparison.scope.added_collectors.join(', ') || 'none')}. Removed: ${escapeHtml(comparison.scope.removed_collectors.join(', ') || 'none')}. New and resolved counts may reflect collector coverage rather than a host-state change.</div>` : '';
  const exports = comparison.reports ? `<div class="comparison-exports"><strong>Comparison reports</strong><a href="${escapeHtml(comparison.reports.comparison_html)}" target="_blank" rel="noreferrer">Open HTML</a><a href="${escapeHtml(comparison.reports.comparison_json)}" target="_blank" rel="noreferrer">Open JSON</a></div>` : '';
  $('#comparison-results').innerHTML = exports + scopeWarning + (rows.length ? rows.slice(0, 200).map((row) => `<div class="comparison-row"><span class="comparison-kind comparison-${row.kind.toLowerCase()}">${escapeHtml(row.kind)}</span><div><strong>${escapeHtml(row.title)}</strong><code>${escapeHtml(row.id)}</code><small>${escapeHtml(row.detail)}</small></div></div>`).join('') + (rows.length > 200 ? `<p class="muted">Showing 200 of ${rows.length} changes.</p>` : '') : '<p class="muted">No finding-level changes were detected.</p>');
  $('#comparison-panel').classList.remove('hidden');
}

async function loadHistoryJob(job) {
  if (!job) return;
  renderProgress(job); renderReports(job); await loadReport(job);
  document.querySelector('.results-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

document.addEventListener('DOMContentLoaded', async () => {
  if (window.location.protocol === 'file:') {
    setMessage('Open the dashboard through the local server: python3 -m macos_inspector --web', true);
  }
  $('#select-all').addEventListener('click', () => {
    document.querySelectorAll('[data-collector]').forEach((input) => { input.checked = true; });
    syncActiveProfile();
    setMessage('All audit sections selected.');
  });
  $('#clear-selection').addEventListener('click', () => {
    document.querySelectorAll('[data-collector]').forEach((input) => { input.checked = false; });
    syncActiveProfile();
    setMessage('Audit scope cleared. Select a profile or individual sections.');
  });
  $('#run-selected').addEventListener('click', () => startScan());
  $('#cancel-scan').addEventListener('click', cancelScan);
  $('#refresh-history').addEventListener('click', loadHistory);
  $('#refresh-readiness').addEventListener('click', loadReadiness);
  $('#history-search').addEventListener('input', renderHistory);
  $('#clear-history-search').addEventListener('click', () => { $('#history-search').value = ''; renderHistory(); });
  $('#close-comparison').addEventListener('click', () => $('#comparison-panel').classList.add('hidden'));
  $('#finding-search').addEventListener('input', () => applyFindingFilters(true));
  $('#finding-status-filter').addEventListener('change', () => applyFindingFilters(true));
  $('#finding-category-filter').addEventListener('change', () => applyFindingFilters(true));
  $('#findings-prev').addEventListener('click', () => { if (state.findingPage > 1) { state.findingPage -= 1; renderFindingPage(); document.querySelector('.results-panel').scrollIntoView({behavior: 'smooth'}); } });
  $('#findings-next').addEventListener('click', () => { if (state.findingPage * state.findingPageSize < state.filteredFindings.length) { state.findingPage += 1; renderFindingPage(); document.querySelector('.results-panel').scrollIntoView({behavior: 'smooth'}); } });
  setConnection('checking');
  const health = await checkHealth();
  if (!health) setMessage('Dashboard server unavailable. Retrying automatically…', true);
  state.healthPoll = setInterval(checkHealth, 4000);
});
