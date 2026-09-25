const state = { config: null, settings: null, cases: [], applications: [], activeCaseId: '', activeJob: null, baselineJob: null, poll: null, healthPoll: null, online: false, starting: false, loadingConfig: false, findings: [], filteredFindings: [], findingPage: 1, findingPageSize: 50, historyScans: [], currentScanId: '', guidance: null, decisionSupport: null, applicationReviewFilter: 'attention', processCandidates: new Map(), viewMode: 'simple' };

const COPY = {
    manage:'Manage', introTitle:'Collect evidence without terminal commands', introText:'Choose audit sections, run a read-only scan, inspect findings, and explicitly contain a reported process when necessary.', safety:'Local-first | online OSINT is opt-in | containment requires confirmation', operationsTitle:'Cases, sources and rules', localSettings:'Local settings | private permissions', casesTitle:'Case management', casesHelp:'Organize scans, analyst identity and investigation notes.', activeCase:'Active case', caseReference:'Reference', caseTitle:'Case title', analyst:'Analyst', archived:'Archived', caseNotes:'Local notes', saveCase:'Save case', osintHelp:'Enable providers and inspect local-cache provenance.', cacheHours:'Cache (hours)', saveSettings:'Save settings', clearCache:'Clear cache', rulesHelp:'Import versioned packs and scan explicit targets only.', chooseFile:'Choose file', enableYara:'Enable YARA scanning', yaraOptional:'Requires the yara executable in a trusted path.', yaraTargets:'Explicit YARA targets | one path per line', saveYara:'Save YARA targets', evidenceProtection:'Evidence protection', evidenceHelp:'Built-in HMAC, with Ed25519 and AES-256-GCM when cryptographic support is available.', generateKey:'Generate signing identity', signManifests:'Sign manifests automatically', keyPrivacy:'The secret or private key remains local with 0600 permissions and is never included in reports or bundles.', attachCase:'Attach a saved case', bundlePassword:'Encrypted bundle password | minimum 12 characters', noSavedCase:'No saved case', configured:'configured', notConfigured:'not configured',
    publicNoKey:'Public source | no key', optionalKey:'Public API | optional key', optionalFreeKey:'Optional | free Auth-Key', optional:'optional', explicitLookup:'Explicit ThreatFox IOC lookup', lookup:'Lookup', threatfoxPrivacy:'Only the indicator entered above is sent to ThreatFox after you press Lookup. Nothing is submitted automatically.', iocPacks:'IOC packs', yaraRules:'YARA rules', readinessTitle:'Collection readiness', recheck:'Recheck', checkingAccess:'Checking local access...', runningDiagnostics:'Running read-only diagnostics...', auditSections:'Audit sections', all:'All', clear:'Clear', scanProfiles:'What do you want to investigate?', individualSections:'Individual sections', reportFormats:'Report formats', caseReferenceOptional:'Case reference', analystOptional:'Analyst', optionalLabel:'optional', casePlaceholder:'Incident or case ID', analystPlaceholder:'Name or team', minimumSeverity:'Minimum severity shown', severityAll:'All findings', severityLow:'Low and above', severityMedium:'Medium and above', severityHigh:'High and above', severityCritical:'Critical only', runSelected:'Run selected audit', cancelScan:'Cancel running scan', scanResults:'Scan results', ready:'Ready', readyTitle:'Ready when you are.', readyHelp:'Select a section and start an audit.', scanComparison:'Scan comparison', close:'Close', searchFindings:'Search findings', searchFindingsPlaceholder:'Title, ID, evidence...', status:'Status', allStatuses:'All statuses', category:'Category', allCategories:'All categories', previous:'Previous', next:'Next', noScan:'No scan selected', noScanHelp:'Your findings will appear here with evidence, commands and recommendations.', previousScans:'Previous scans', refresh:'Refresh', findScan:'Find a scan', findScanPlaceholder:'Case, analyst, collector or scan ID', interfaceLanguage:'Interface language', onlineOptIn:'Online opt-in', run:'Run', sections:'sections', unavailable:'Unavailable'
};

const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
const t = (key) => COPY[key] || key;
const writeOptions = (method, body) => ({method, headers:{'Content-Type':'application/json', 'X-MacOS-Inspector':'1'}, body:JSON.stringify(body)});

function applyEnglishCopy() {
  document.documentElement.lang = 'en';
  document.querySelectorAll('[data-i18n]').forEach((element) => { const value = t(element.dataset.i18n); if (value) element.textContent = value; });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((element) => { element.placeholder = t(element.dataset.i18nPlaceholder); });
  document.querySelectorAll('[data-i18n-aria]').forEach((element) => { element.setAttribute('aria-label', t(element.dataset.i18nAria)); });
  const emptyOptions = [$('#case-select option[value=""]'), $('#scan-case-select option[value=""]')];
  emptyOptions.forEach((option) => { if (option) option.textContent = t('noSavedCase'); });
  if (state.config) {
    renderCollectors(true);
    renderFormats(true);
  }
}

function setViewMode(mode, persist = true) {
  state.viewMode = mode === 'analyst' ? 'analyst' : 'simple';
  document.body.classList.toggle('mode-simple', state.viewMode === 'simple');
  document.body.classList.toggle('mode-analyst', state.viewMode === 'analyst');
  const simple = $('#view-simple');
  const analyst = $('#view-analyst');
  if (simple) simple.setAttribute('aria-pressed', String(state.viewMode === 'simple'));
  if (analyst) analyst.setAttribute('aria-pressed', String(state.viewMode === 'analyst'));
  if (persist) {
    try { window.localStorage.setItem('macos-inspector-view-mode', state.viewMode); } catch (error) { /* Local preferences are optional. */ }
  }
}
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
  const guidedButton = $('#check-this-mac');
  if (guidedButton) guidedButton.disabled = disabled;
  document.querySelectorAll('[data-run-one]').forEach((button) => { button.disabled = disabled; });
  const inspectButton = $('#inspect-application');
  if (inspectButton) inspectButton.disabled = disabled || !$('#target-application')?.value;
  const activityButton = $('#inspect-application-activity');
  if (activityButton) activityButton.disabled = disabled || !$('#target-application')?.value;
  document.querySelectorAll('[data-recheck-app]').forEach((button) => { button.disabled = disabled; });
  const cancelButton = $('#cancel-scan');
  if (cancelButton && !cancelButton.classList.contains('hidden')) cancelButton.disabled = !state.online;
}

function setGuideVisible(visible) {
  const guide = $('#welcome-guide');
  if (!guide) return;
  guide.classList.toggle('hidden', !visible);
  if (visible) guide.scrollIntoView({behavior: 'smooth', block: 'start'});
}

function dismissGuide() {
  try { window.localStorage.setItem('macos-inspector-guide-1.3.0', 'dismissed'); } catch (error) { /* Local preferences are optional. */ }
  setGuideVisible(false);
}

async function startGuidedCheck() {
  if (!state.config) return setMessage('The dashboard is still loading. Try again in a moment.', true);
  selectProfile('quick', false);
  dismissGuide();
  document.querySelector('.workspace-grid').scrollIntoView({behavior: 'smooth', block: 'start'});
  await startScan();
}

function setConnection(status, health = null) {
  const element = $('#connection');
  state.online = status === 'online';
  if (element) {
    element.className = `connection ${status}`;
    element.textContent = status === 'online' ? `Connected | v${health?.version || '?'}` : status === 'checking' ? 'Connecting...' : 'Offline | retrying';
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

function renderCollectors(preserve = false) {
  const previouslySelected = preserve ? new Set(selectedCollectors()) : new Set();
  $('#collectors').innerHTML = state.config.collectors.map((collector) => `
    <div class="collector-card${collector.external_network ? ' external' : ''}">
      <input type="checkbox" id="collector-${escapeHtml(collector.id)}" data-collector="${escapeHtml(collector.id)}">
      <label for="collector-${escapeHtml(collector.id)}"><span class="collector-title">${escapeHtml(collector.title)}${collector.external_network ? `<em class="online-badge">${escapeHtml(t('onlineOptIn'))}</em>` : ''}</span><span class="collector-id">${escapeHtml(collector.id)}</span>${collector.privacy_note ? `<small class="collector-note">${escapeHtml(collector.privacy_note)}</small>` : ''}</label>
      <button type="button" class="mini-button" data-run-one="${escapeHtml(collector.id)}">${escapeHtml(t('run'))}</button>
    </div>`).join('');
  document.querySelectorAll('[data-run-one]').forEach((button) => button.addEventListener('click', () => startScan([button.dataset.runOne])));
  document.querySelectorAll('[data-collector]').forEach((input) => input.addEventListener('change', syncActiveProfile));
  if (preserve) document.querySelectorAll('[data-collector]').forEach((input) => { input.checked = previouslySelected.has(input.dataset.collector); });
  renderProfiles(preserve);
  updateRunAvailability();
}

function renderProfiles(preserve = false) {
  const profiles = state.config.profiles || [];
  const cards = (items) => items.map((profile) => `<button type="button" class="profile-card${profile.goal ? ' goal-card' : ''}" data-profile="${escapeHtml(profile.id)}" title="${escapeHtml(profile.description)}"><strong>${escapeHtml(profile.title)}</strong><small>${escapeHtml(profile.description)}</small><span>${escapeHtml(profile.collectors.length)} ${escapeHtml(t('sections'))}</span></button>`).join('');
  const goals = profiles.filter((profile) => profile.goal);
  const presets = profiles.filter((profile) => !profile.goal);
  $('#scan-profiles').innerHTML = `<section><span class="profile-group-label">START WITH WHAT YOU NOTICED</span><div class="profile-grid">${cards(goals)}</div></section><section><span class="profile-group-label">SCAN PRESETS</span><div class="profile-grid">${cards(presets)}</div></section>`;
  document.querySelectorAll('[data-profile]').forEach((button) => button.addEventListener('click', () => selectProfile(button.dataset.profile, true)));
  if (preserve) syncActiveProfile();
  else {
    const defaultProfile = profiles.find((profile) => profile.default) || profiles[0];
    if (defaultProfile) selectProfile(defaultProfile.id, false);
  }
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
  if (announce) setMessage(`${profile.title} selected | ${profile.collectors.length} audit section${profile.collectors.length === 1 ? '' : 's'}. Review the scope, then run the audit.`);
}

function renderFormats(preserve = false) {
  const selectedBefore = preserve ? new Set(selectedValues('format')) : new Set();
  const labels = { html: 'Interactive HTML', json: 'JSON', markdown: 'Markdown', csv: 'CSV', sarif: 'SARIF', manifest: 'Evidence manifest', pdf: 'PDF', bundle: 'Case bundle ZIP', 'encrypted-bundle': 'Encrypted case bundle' };
  const capabilities = state.config.format_capabilities || {};
  $('#formats').innerHTML = state.config.formats.map((format) => {
    const capability = capabilities[format] || {available: true, reason: ''};
    const available = capability.available !== false;
    // Encryption is deliberately opt-in because selecting it requires a password.
    const checked = available && (preserve ? selectedBefore.has(format) : format !== 'encrypted-bundle') ? 'checked' : '';
    const unavailable = available ? '' : `<span class="format-unavailable">${escapeHtml(t('unavailable'))}</span>`;
    return `<label class="format-option${available ? '' : ' unavailable'}" title="${escapeHtml(capability.reason || '')}" aria-disabled="${available ? 'false' : 'true'}"><input type="checkbox" data-format="${escapeHtml(format)}" ${checked} ${available ? '' : 'disabled'}> ${escapeHtml(labels[format] || format.toUpperCase())}${unavailable}</label>`;
  }).join('');
  document.querySelectorAll('[data-format]').forEach((input) => input.addEventListener('change', updateBundlePasswordVisibility));
  updateBundlePasswordVisibility();
}

function updateBundlePasswordVisibility() {
  const selected = document.querySelector('[data-format="encrypted-bundle"]:checked');
  $('#bundle-password-wrap').classList.toggle('hidden', !selected);
  if (!selected) $('#bundle-password').value = '';
}

async function loadReadiness() {
  const button = $('#refresh-readiness');
  button.disabled = true;
  $('#readiness-summary').textContent = 'Checking local access...';
  try {
    const readiness = await api('/api/readiness');
    const summary = readiness.summary || {};
    $('#readiness-summary').innerHTML = `<strong class="readiness-overall readiness-${escapeHtml(readiness.overall)}">${escapeHtml(readiness.overall)}</strong><span>${escapeHtml(summary.ready || 0)} ready | ${escapeHtml(summary.limited || 0)} limited | ${escapeHtml(summary.unavailable || 0)} unavailable | ${escapeHtml(summary.optional || 0)} optional</span>`;
    $('#readiness-checks').innerHTML = (readiness.checks || []).map((check) => `<article class="readiness-card"><div><strong>${escapeHtml(check.title)}</strong><span class="readiness-status readiness-${escapeHtml(check.status)}">${escapeHtml(check.status)}</span></div><p>${escapeHtml(check.detail)}</p><small>${escapeHtml(check.impact)}</small>${check.action && check.action !== 'No action required.' ? `<details><summary>Recommended action</summary><p>${escapeHtml(check.action)}</p></details>` : ''}</article>`).join('');
  } catch (error) {
    $('#readiness-summary').textContent = 'Readiness check unavailable.';
    $('#readiness-checks').innerHTML = `<p class="muted">${escapeHtml(error.message)}</p>`;
  } finally {
    button.disabled = false;
  }
}

function renderApplications() {
  const query = $('#application-search').value.trim().toLowerCase();
  const selected = $('#target-application').value;
  const matches = state.applications.filter((application) => !query || `${application.name} ${application.path}`.toLowerCase().includes(query));
  $('#target-application').innerHTML = `<option value="">${matches.length ? 'Choose an application' : 'No matching applications'}</option>` + matches.map((application) => `<option value="${escapeHtml(application.path)}">${escapeHtml(application.name)} | ${escapeHtml(application.path)}</option>`).join('');
  if (matches.some((application) => application.path === selected)) $('#target-application').value = selected;
  $('#target-app-count').textContent = query ? `${matches.length} of ${state.applications.length} applications match. Clear the search to restore the full list.` : `${state.applications.length} applications found in standard macOS application folders.`;
  updateRunAvailability();
}

async function loadApplications() {
  try {
    const payload = await api('/api/applications');
    state.applications = payload.applications || [];
    renderApplications();
  } catch (error) {
    state.applications = [];
    $('#target-application').innerHTML = '<option value="">Application list unavailable</option>';
    $('#target-app-count').textContent = error.message;
    updateRunAvailability();
  }
}

async function inspectSelectedApplication() {
  const target = $('#target-application').value;
  if (!target) return setMessage('Choose an application to inspect.', true);
  setMessage(`Preparing a focused trust check for ${target.split('/').pop()}...`);
  await startScan(['application-trust'], target);
}

async function inspectSelectedApplicationActivity() {
  const target = $('#target-application').value;
  if (!target) return setMessage('Choose an application to inspect.', true);
  setMessage(`Preparing a trust and activity check for ${target.split('/').pop()}...`);
  await startScan(['application-trust', 'live-triage', 'persistence'], target);
}

function selectedValues(attribute) {
  return [...document.querySelectorAll(`[data-${attribute}]:checked`)].map((element) => element.dataset[attribute]);
}

async function startScan(collectorOverride = null, targetApplication = '') {
  const collectors = collectorOverride || selectedCollectors();
  const formats = selectedValues('format');
  if (!collectors.length) return setMessage('Select at least one audit section.', true);
  if (!formats.length) return setMessage('Select at least one report format.', true);
  if (formats.includes('encrypted-bundle') && $('#bundle-password').value.length < 12) return setMessage('Encrypted bundle password must contain at least 12 characters.', true);
  const onlineCollectors = (state.config.collectors || []).filter((collector) => collectors.includes(collector.id) && collector.external_network);
  if (onlineCollectors.length && !window.confirm(`This scan will access the internet for: ${onlineCollectors.map((collector) => collector.title).join(', ')}. No host, case, hash, or file data is sent. Continue?`)) return;
  state.starting = true;
  updateRunAvailability();
  $('#cancel-scan').classList.remove('hidden');
  $('#cancel-scan').disabled = false;
  setMessage('Starting read-only collection...');
  try {
    const job = await api('/api/scans', writeOptions('POST', { collectors, formats, minimum: $('#minimum').value, case_reference: $('#case-reference').value, analyst: $('#analyst').value, bundle_password: $('#bundle-password').value, target_application: targetApplication }));
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
  const headline = job.state === 'completed' ? 'Scan completed' : job.state === 'failed' ? 'Scan failed' : job.state === 'cancelled' ? 'Scan cancelled' : job.state === 'interrupted' ? 'Scan interrupted by dashboard restart' : job.cancel_requested ? 'Stopping safely...' : job.current_collector ? `Collecting ${job.current_collector}` : 'Preparing collection...';
  const itemTotal = Number(job.total_items || 0);
  const itemCompleted = Math.min(Number(job.completed_items || 0), itemTotal);
  const percent = itemTotal ? Math.round(itemCompleted / itemTotal * 100) : 0;
  let itemProgress = '';
  if (job.state === 'running' && itemTotal) {
    const ordinal = Math.min(itemCompleted + (job.current_item ? 1 : 0), itemTotal);
    const remaining = Math.max(0, Number(job.estimated_seconds_remaining || 0));
    const estimate = remaining ? ` | about ${formatDuration(remaining)} remaining` : '';
    const itemLabel = job.current_item ? ` | ${escapeHtml(job.current_item)}` : '';
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
  setMessage('Cancellation requested. Stopping the active read-only command...');
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
  setMessage('Verifying manifest, signatures and report digests...');
  try {
    const result = await api(`/api/manifests/${encodeURIComponent(button.dataset.verifyScan)}/verify`);
    const identity = result.algorithm ? ` Signature: ${result.algorithm}${result.public_key_sha256 ? ` | key ${result.public_key_sha256.slice(0, 16)}...` : ''}.` : ' Manifest is unsigned.';
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
    state.currentScanId = payload.metadata?.scan_id || '';
    try {
      state.decisionSupport = state.currentScanId ? await api(`/api/decision-support/${encodeURIComponent(state.currentScanId)}`) : null;
      state.guidance = state.decisionSupport?.guidance || null;
    } catch (error) {
      state.decisionSupport = null;
      state.guidance = null;
      setMessage(`The report loaded, but decision support is unavailable: ${error.message}`, true);
    }
    renderCaseMetadata(payload.metadata || {});
    renderExperience(state.decisionSupport?.experience);
    renderSummary(payload.summary, state.decisionSupport?.experience);
    renderGuidance(state.guidance);
    renderApplicationReview(state.decisionSupport?.application_review);
    renderDecisionSupport(state.decisionSupport);
    renderTimeline(payload.timeline || []);
    renderFindings(payload.findings || []);
  } catch (error) { setMessage(`Could not load report data: ${error.message}`, true); }
}

function renderApplicationReview(review) {
  const panel = $('#application-review');
  if (!review?.available) { panel.classList.add('hidden'); panel.innerHTML = ''; return; }
  const counts = review.counts || {};
  const groups = review.groups || {};
  const filter = state.applicationReviewFilter;
  const rows = (review.applications || []).filter((item) => {
    if (filter === 'all') return true;
    if (filter === 'attention') return ['review_first', 'needs_context', 'unable_to_verify'].includes(item.group);
    if (filter === 'active') return Boolean(item.activity?.has_activity);
    if (filter === 'changed') return Boolean(item.change) && item.change.kind !== 'application-coverage-change';
    if (filter === 'coverage') return item.change?.kind === 'application-coverage-change';
    return item.group === filter;
  });
  if (filter === 'changed') {
    const changeRank = { high: 0, review: 1, context: 2 };
    rows.sort((left, right) => (changeRank[left.change?.priority] ?? 1) - (changeRank[right.change?.priority] ?? 1));
  }
  const activeCount = (review.applications || []).filter((item) => item.activity?.has_activity).length;
  const changedCount = (review.applications || []).filter((item) => item.change && item.change.kind !== 'application-coverage-change').length;
  const coverageCount = (review.applications || []).filter((item) => item.change?.kind === 'application-coverage-change').length;
  const filters = [
    ['attention', 'Needs attention', (counts.review_first || 0) + (counts.needs_context || 0) + (counts.unable_to_verify || 0)],
    ['all', 'All applications', review.total || 0],
    ['active', 'Active in this scan', activeCount],
    ['changed', 'Changed since last scan', changedCount],
    ...(coverageCount ? [['coverage', 'New evidence coverage', coverageCount]] : []),
    ['checks_passed', 'Checks passed', counts.checks_passed || 0],
    ['reviewed', 'Reviewed locally', counts.reviewed || 0],
  ];
  const cards = rows.slice(0, 150).map((item) => {
    const provenance = item.provenance || {};
    const change = item.change || null;
    const facts = [
      item.publisher_team_id ? `Team ID ${item.publisher_team_id}` : 'Team ID unavailable',
      item.signature_valid === true ? 'Signature valid' : item.signature_valid === false ? 'Signature invalid' : item.legacy_verification ? 'Signature completion not recorded' : 'Signature check not completed',
      item.gatekeeper_accepted === true ? 'Gatekeeper accepted' : item.gatekeeper_accepted === false ? 'Gatekeeper rejected' : 'Gatekeeper unknown',
      item.notarized === true ? 'Notarized' : item.notarized === false ? 'Notarization not confirmed' : 'Notarization not separately reported',
    ];
    if (item.legacy_verification) facts.unshift('Historical check: recheck required');
    const sourceHosts = Array.isArray(provenance.source_hosts) ? provenance.source_hosts : [];
    const provenanceRows = [
      ['Signing identity', provenance.publisher || 'Not available'],
      ['Signature type', provenance.signature_type || 'Not available'],
      ['Gatekeeper source', provenance.gatekeeper_source || 'Not available'],
      ['Installation scope', provenance.install_scope || 'Not available'],
      ['Download source', sourceHosts.length ? sourceHosts.join(', ') : 'Not recorded'],
      ['Downloaded by', provenance.download_agent || 'Not recorded'],
      ['Download time', provenance.downloaded_at || 'Not recorded'],
    ];
    const provenanceBlock = `<details class="application-provenance"><summary>Who signed this app and where did it come from?</summary><p>${escapeHtml(provenance.summary || 'Publisher and acquisition metadata were not available.')}</p><dl>${provenanceRows.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`).join('')}</dl><small>${escapeHtml(provenance.privacy_note || 'Publisher and source observations do not establish that an application is safe.')}</small></details>`;
    const changedFields = (change?.changed_fields || []).map((field) => `<li><span>${escapeHtml(field.label)}</span><code>${escapeHtml(field.before)} to ${escapeHtml(field.after)}</code></li>`).join('');
    const changeBlock = change ? `<details class="application-change application-change-${escapeHtml(change.priority || 'review')}"><summary>${escapeHtml(change.label || 'Application changed')}</summary><p>${escapeHtml(change.detail || 'Application evidence changed since the previous comparable scan.')}</p>${changedFields ? `<ul>${changedFields}</ul>` : ''}<small>${escapeHtml(change.next_action || 'Validate the change before closing the review.')}</small></details>` : '';
    const signals = (item.signals || []).map((signal) => `<li>${escapeHtml(signal)}</li>`).join('');
    const activity = item.activity || {};
    const activityCounts = activity.counts || {};
    const activityBadges = [
      activityCounts.running ? `${activityCounts.running} running` : '',
      activityCounts.network ? `${activityCounts.network} network endpoint${activityCounts.network === 1 ? '' : 's'}` : '',
      activityCounts.startup ? `${activityCounts.startup} startup item${activityCounts.startup === 1 ? '' : 's'}` : '',
    ].filter(Boolean);
    const activityRows = [
      ...(activity.running_processes || []).map((row) => `<li><strong>Running process${row.pid ? ` ${escapeHtml(row.pid)}` : ''}</strong><code>${escapeHtml(row.executable || 'Executable unavailable')}</code>${row.elapsed ? `<small>Running for ${escapeHtml(row.elapsed)}</small>` : ''}</li>`),
      ...(activity.network_connections || []).map((row) => `<li><strong>${escapeHtml(row.state || 'Network activity')}</strong><code>${escapeHtml(row.endpoint || 'Endpoint unavailable')}</code></li>`),
      ...(activity.startup_items || []).map((row) => `<li><strong>Starts automatically</strong><span>${escapeHtml(row.title || 'Startup item')}</span><code>${escapeHtml(row.executable || 'Executable unavailable')}</code></li>`),
    ].join('');
    const truncated = activity.details_truncated ? '<small>Showing the first 20 matching entries in each activity type. Open the complete Live Triage evidence for the full snapshot.</small>' : '';
    const noActivity = activity.coverage?.available
      ? 'No matching activity was observed in the live or startup evidence collected by this scan.'
      : 'Activity context was not collected. Include Live Triage or Persistence to correlate behavior.';
    const activityBlock = activityBadges.length ? `<div class="application-activity-badges">${activityBadges.map((label) => `<span>${escapeHtml(label)}</span>`).join('')}</div><details class="application-activity"><summary>Why this app appears active</summary><p>${escapeHtml(activity.conclusion || 'Observed activity is context, not a security verdict.')}</p>${truncated}<ul>${activityRows}</ul></details>` : `<p class="application-no-activity">${escapeHtml(noActivity)}</p>`;
    return `<article class="application-review-row application-group-${escapeHtml(item.group)}"><div class="application-review-main"><span class="application-group">${escapeHtml(item.group_label || groups[item.group] || 'Recorded')}</span><h4>${escapeHtml(item.name)}</h4><p>${escapeHtml(item.explanation)}</p><div class="application-facts">${facts.map((fact) => `<span>${escapeHtml(fact)}</span>`).join('')}</div>${changeBlock}${provenanceBlock}${activityBlock}${signals ? `<ul class="application-signals">${signals}</ul>` : ''}<code>${escapeHtml(item.path || 'Location unavailable')}</code></div><div class="application-review-actions"><button type="button" class="text-button" data-review-finding="${escapeHtml(item.finding_id)}">Open result</button><button type="button" class="secondary-button" data-recheck-app="${escapeHtml(item.path || '')}">Recheck this app</button></div></article>`;
  }).join('');
  const empty = filter === 'attention'
    ? '<p class="application-review-clear">No application currently needs attention based on the checks in this scan.</p>'
    : '<p class="muted">No application is in this group.</p>';
  panel.innerHTML = `<div class="application-review-heading"><div><p class="eyebrow">APPLICATION REVIEW</p><h3 id="application-review-title">Which applications should I look at first?</h3><p>${escapeHtml(review.conclusion)}</p></div><div class="application-review-counts"><span><strong>${escapeHtml(counts.review_first || 0)}</strong>review first</span><span><strong>${escapeHtml(counts.needs_context || 0)}</strong>need context</span><span><strong>${escapeHtml(counts.unable_to_verify || 0)}</strong>not verified</span></div></div><div class="application-review-filters">${filters.map(([value, label, count]) => `<button type="button" data-app-review-filter="${value}" class="${filter === value ? 'active' : ''}">${escapeHtml(label)} <strong>${escapeHtml(count)}</strong></button>`).join('')}</div><div class="application-review-list">${cards || empty}${rows.length > 150 ? `<p class="muted">Showing 150 of ${escapeHtml(rows.length)} applications in this view. Use the finding filters for the complete evidence list.</p>` : ''}</div>`;
  panel.classList.remove('hidden');
  panel.querySelectorAll('[data-app-review-filter]').forEach((button) => button.addEventListener('click', () => {
    state.applicationReviewFilter = button.dataset.appReviewFilter;
    renderApplicationReview(review);
  }));
  panel.querySelectorAll('[data-review-finding]').forEach((button) => button.addEventListener('click', () => focusFinding(button.dataset.reviewFinding)));
  panel.querySelectorAll('[data-recheck-app]').forEach((button) => button.addEventListener('click', () => recheckApplication(button.dataset.recheckApp)));
  updateRunAvailability();
}

async function recheckApplication(path) {
  if (!path) return setMessage('The application path is unavailable.', true);
  setMessage(`Preparing a focused trust check for ${path.split('/').pop()}...`);
  await startScan(['application-trust'], path);
}

function renderDecisionSupport(decision) {
  const panel = $('#decision-support');
  if (!decision) { panel.classList.add('hidden'); panel.innerHTML = ''; return; }
  const changes = decision.changes || {};
  const counts = changes.counts || {};
  const comparisonMessage = changes.comparison_context?.message || '';
  const changeMetrics = changes.available ? [
    ['New apps', counts.new_applications || 0], ['Changed apps', counts.changed_applications || 0],
    ['Apps no longer present', counts.removed_applications || 0],
    ['Coverage updates', counts.application_coverage_changes || 0],
    ['New startup items', counts.new_startup_items || 0], ['Changed startup items', counts.changed_startup_items || 0],
    ['New listeners', counts.new_network_listeners || 0], ['Resolved findings', counts.resolved_findings || 0],
  ] : [];
  const highlights = (changes.highlights || []).slice(0, 8).map((item) => {
    const content = `<span>${escapeHtml(item.label)}</span><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.detail)}</small>${item.next_action ? `<small class="change-action">Next: ${escapeHtml(item.next_action)}</small>` : ''}`;
    return item.finding_id
      ? `<button type="button" class="decision-row change-${escapeHtml(item.priority || 'context')}" data-review-finding="${escapeHtml(item.finding_id)}">${content}</button>`
      : `<article class="decision-row change-${escapeHtml(item.priority || 'context')}">${content}</article>`;
  }).join('');
  const stories = (decision.stories || []).map((story) => `<article class="story-card"><span>${escapeHtml(story.confidence)} confidence correlation</span><h4>${escapeHtml(story.title)}</h4><p>${escapeHtml(story.narrative)}</p><details><summary>Signals and next steps</summary><ul>${(story.signals || []).map((signal) => `<li>${escapeHtml(signal.type)} | ${escapeHtml(signal.detail)}</li>`).join('')}</ul><ol>${(story.next_actions || []).map((action) => `<li>${escapeHtml(action)}</li>`).join('')}</ol></details></article>`).join('');
  panel.innerHTML = `<div class="decision-heading"><div><p class="eyebrow">DECISION SUPPORT</p><h3 id="decision-support-title">What changed and how the evidence connects</h3><p>${escapeHtml(changes.message || '')}</p></div><button type="button" class="secondary-button" id="export-investigation-summary">Export investigation summary</button></div>${comparisonMessage ? `<p class="comparison-caveat"><strong>Comparison note</strong>${escapeHtml(comparisonMessage)}</p>` : ''}${changeMetrics.length ? `<div class="change-metrics">${changeMetrics.map(([label,value]) => `<span><strong>${escapeHtml(value)}</strong>${escapeHtml(label)}</span>`).join('')}</div>` : ''}<div class="decision-columns"><section><h4>Changes since last comparable scan</h4>${highlights || `<p class="muted">${escapeHtml(changes.message || 'No high-signal changes were identified.')}</p>`}</section><section><h4>Correlated investigation stories</h4>${stories || '<p class="muted">No finding is currently connected across multiple evidence types.</p>'}</section></div>`;
  panel.classList.remove('hidden');
  panel.querySelectorAll('[data-review-finding]').forEach((button) => button.addEventListener('click', () => focusFinding(button.dataset.reviewFinding)));
  $('#export-investigation-summary').addEventListener('click', exportInvestigationSummary);
}

async function exportInvestigationSummary() {
  if (!state.currentScanId) return;
  const button = $('#export-investigation-summary');
  button.disabled = true;
  try {
    const result = await api('/api/investigation-summary', writeOptions('POST', {scan_id:state.currentScanId}));
    window.open(result.report, '_blank', 'noopener,noreferrer');
    setMessage(`Investigation summary created: ${result.filename}`);
  } catch (error) { setMessage(error.message, true); }
  finally { button.disabled = false; }
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

function renderExperience(experience) {
  const panel = $('#experience-summary');
  if (!experience?.assessment) { panel.classList.add('hidden'); panel.innerHTML = ''; return; }
  const assessment = experience.assessment;
  const actions = (experience.next_actions || []).map((item, index) => `<article class="experience-action"><div><span>${index + 1}</span><strong>${escapeHtml(item.title)}</strong><em class="verdict verdict-${escapeHtml(item.verdict || 'information')}">${escapeHtml(item.label || 'Review')}</em></div><p>${escapeHtml(item.observed)}</p><details><summary>Why this matters and how to verify it</summary><dl><div><dt>Why it matters</dt><dd>${escapeHtml(item.why_it_matters)}</dd></div><div><dt>What this does not prove</dt><dd>${escapeHtml(item.not_proof)}</dd></div><div><dt>Next safe step</dt><dd>${escapeHtml(item.verify)}</dd></div><div><dt>Action risk</dt><dd>${escapeHtml(item.action_risk)}</dd></div></dl></details>${item.finding_id ? `<button type="button" class="text-button" data-review-finding="${escapeHtml(item.finding_id)}">Open technical result</button>` : '<button type="button" class="text-button" data-switch-analyst>Open collection details</button>'}</article>`).join('');
  const empty = '<p class="experience-clear">Keep this report as a baseline. Run the same scope again if the Mac changes or unfamiliar behavior appears.</p>';
  panel.className = `experience-summary experience-${assessment.id || 'needs-review'}`;
  panel.innerHTML = `<div class="experience-heading"><div><p class="eyebrow">CURRENT ASSESSMENT</p><span class="experience-state">${escapeHtml(assessment.label)}</span><h3 id="experience-summary-title">${escapeHtml(assessment.headline)}</h3><p>${escapeHtml(assessment.explanation)}</p></div><button type="button" class="secondary-button" data-switch-analyst>Show analyst view</button></div><div class="experience-actions"><h4>What to do next</h4>${actions || empty}</div>`;
  panel.classList.remove('hidden');
  panel.querySelectorAll('[data-review-finding]').forEach((button) => button.addEventListener('click', () => focusFinding(button.dataset.reviewFinding)));
  panel.querySelectorAll('[data-switch-analyst]').forEach((button) => button.addEventListener('click', () => setViewMode('analyst')));
}

function renderSummary(summary, experience = null) {
  const axes = experience?.axes || {};
  const cards = [
    ['Review priority', axes.priority?.label || 'Not calculated'],
    ['Collection coverage', axes.coverage ? `${axes.coverage.percent == null ? 'N/A' : `${axes.coverage.percent}%`} | ${axes.coverage.label}` : 'Not calculated'],
    ['Evidence confidence', axes.confidence?.label || 'Not calculated'],
    ['Findings shown', `${summary.finding_count} of ${summary.total_finding_count ?? summary.finding_count}`],
  ];
  $('#summary').innerHTML = cards.map(([label, value]) => `<div class="summary-item"><span class="summary-label">${escapeHtml(label)}</span><span class="summary-value">${escapeHtml(value)}</span></div>`).join('') + `<p class="summary-note">${escapeHtml(experience?.score_note || 'Priority, coverage, and evidence confidence answer different questions.')}</p>`;
  $('#summary').classList.remove('hidden');
}

function renderGuidance(guidance) {
  const panel = $('#guided-summary');
  if (!guidance) { panel.classList.add('hidden'); panel.innerHTML = ''; return; }
  const counts = guidance.counts || {};
  const priorities = guidance.priorities || [];
  const priorityRows = priorities.length ? priorities.map((item) => `<button type="button" class="guided-priority" data-review-finding="${escapeHtml(item.finding_id)}"><span class="verdict verdict-${escapeHtml(item.verdict || 'information')}">${escapeHtml(item.label)}</span><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.next_action)}</small></button>`).join('') : '<p class="guided-clear">No result currently requires immediate review.</p>';
  const workflow = (guidance.workflow || []).map((step, index) => `<span${index === 0 ? ' class="active"' : ''}>${escapeHtml(step)}</span>`).join('');
  panel.innerHTML = `<div class="guided-heading"><div><p class="eyebrow">GUIDED INVESTIGATION</p><h3 id="guided-summary-title">${escapeHtml(guidance.headline)}</h3><p>${escapeHtml(guidance.plain_language_note)}</p></div><div class="guided-counts"><span><strong>${escapeHtml(counts.attention || 0)}</strong> attention</span><span><strong>${escapeHtml(counts.unable_to_verify || 0)}</strong> not verified</span><span><strong>${escapeHtml(counts.not_assessed || 0)}</strong> not assessed</span><span><strong>${escapeHtml(counts.looks_normal_or_resolved || 0)}</strong> normal or resolved</span><span><strong>${escapeHtml(counts.recorded_observations || 0)}</strong> observations</span></div></div><div class="workflow-strip">${workflow}</div><div class="guided-priorities">${priorityRows}</div>`;
  panel.classList.remove('hidden');
  panel.querySelectorAll('[data-review-finding]').forEach((button) => button.addEventListener('click', () => focusFinding(button.dataset.reviewFinding)));
}

function focusFinding(findingId) {
  setViewMode('analyst');
  $('#finding-search').value = findingId;
  applyFindingFilters(true);
  const finding = document.querySelector('.finding');
  if (finding) {
    finding.classList.add('open');
    finding.scrollIntoView({behavior: 'smooth', block: 'center'});
  }
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
  } else {
    state.processCandidates = new Map();
    $('#findings').innerHTML = visible.map((finding, index) => {
    const severity = finding.severity.toLowerCase().replaceAll(' ', '-');
    const evidence = escapeHtml(JSON.stringify(finding.evidence || [], null, 2));
    const commands = (finding.commands_used || []).map((command) => `<li><code>${escapeHtml(command)}</code></li>`).join('') || '<li>None</li>';
    const references = (finding.references || []).map((reference) => `<li><a href="${escapeHtml(reference)}" target="_blank" rel="noreferrer">${escapeHtml(reference)}</a></li>`).join('') || '<li>None</li>';
    const responseControls = renderProcessResponseControls(finding);
    const guide = state.guidance?.findings?.[finding.finding_id];
    const verdict = guide ? `<span class="verdict verdict-${escapeHtml(guide.verdict)}">${escapeHtml(guide.label)}</span>` : '';
    const confidence = guide?.confidence ? `<span class="confidence confidence-${escapeHtml(guide.confidence.level)}" title="${escapeHtml(guide.confidence.rationale)}">${escapeHtml(guide.confidence.label)}</span>` : '';
    const explanation = guide?.simple_explanation || finding.observed_result;
    const actions = (guide?.next_actions || []).map((action) => `<li>${escapeHtml(action)}</li>`).join('');
    const context = renderInvestigationContext(guide?.context);
    const investigation = renderInvestigationControls(finding, guide?.investigation);
    const confidenceDetail = guide?.confidence ? `<section class="confidence-detail"><strong>${escapeHtml(guide.confidence.label)}</strong><p>${escapeHtml(guide.confidence.rationale)}</p>${(guide.confidence.missing || []).length ? `<small>Missing: ${escapeHtml(guide.confidence.missing.join(', '))}</small>` : '<small>No important evidence gap was identified for this observation.</small>'}</section>` : '';
    return `<article class="finding" data-finding-index="${start + index}" data-finding-id="${escapeHtml(finding.finding_id)}"><div class="finding-head"><span class="severity severity-${severity}">${escapeHtml(finding.severity)}</span><span class="finding-status">${escapeHtml(finding.status)}</span>${verdict}${confidence}<span class="finding-title">${escapeHtml(finding.title)}</span><span class="finding-id">${escapeHtml(finding.finding_id)}</span><button type="button" class="finding-toggle">Details</button></div><p class="finding-observed">${escapeHtml(explanation)}</p>${actions ? `<div class="next-action"><strong>What to do next</strong><ol>${actions}</ol></div>` : ''}<div class="finding-details">${investigation}${context}${confidenceDetail}<p><strong>Technical observation</strong><br>${escapeHtml(finding.observed_result)}</p><p><strong>Why it matters</strong><br>${escapeHtml(finding.why_it_matters)}</p><p><strong>Recommendation</strong><br>${escapeHtml(finding.recommendation)}</p>${responseControls}<p><strong>Commands used</strong></p><ul>${commands}</ul><p><strong>References</strong></p><ul>${references}</ul><p><strong>Evidence</strong></p><pre>${evidence}</pre></div></article>`;
    }).join('');
  }
  document.querySelectorAll('.finding-toggle').forEach((button) => button.addEventListener('click', () => button.closest('.finding').classList.toggle('open')));
  document.querySelectorAll('[data-process-action]').forEach((button) => button.addEventListener('click', () => respondToProcess(button)));
  document.querySelectorAll('[data-save-investigation]').forEach((button) => button.addEventListener('click', () => saveInvestigation(button)));
  document.querySelectorAll('[data-hash-reputation]').forEach((button) => button.addEventListener('click', () => lookupHashReputation(button)));
  $('#finding-range').textContent = total ? `${start + 1}-${Math.min(start + state.findingPageSize, total)} of ${total}` : '0 findings';
  $('#findings-prev').disabled = state.findingPage <= 1;
  $('#findings-next').disabled = start + state.findingPageSize >= total;
}

function renderInvestigationContext(context) {
  if (!context || context.kind === 'general') return '';
  if (context.kind === 'application') {
    const values = [
      ['Application', context.name], ['Version', context.version], ['Location', context.path],
      ['Publisher Team ID', context.publisher_team_id || 'Not available'],
      ['Signature', context.signature_valid === true ? 'Valid' : context.signature_valid === false ? 'Invalid' : 'Unknown'],
      ['Gatekeeper', context.gatekeeper_accepted === true ? 'Accepted' : context.gatekeeper_accepted === false ? 'Rejected' : 'Unknown'],
      ['Executable SHA-256', context.executable_sha256],
    ].filter(([, value]) => value !== null && value !== undefined && value !== '');
    const reputation = context.executable_sha256 ? `<div class="reputation-action"><button type="button" class="secondary-button" data-hash-reputation="${escapeHtml(context.executable_sha256)}">Check hash reputation</button><span data-reputation-result></span><small>Manual opt-in. Only the SHA-256 is sent to enabled providers; the file is never uploaded.</small></div>` : '';
    return `<section class="investigation-context"><strong>Application investigation</strong><div>${values.map(([label, value]) => `<span><small>${escapeHtml(label)}</small><code>${escapeHtml(value)}</code></span>`).join('')}</div>${reputation}</section>`;
  }
  if (context.kind === 'process') {
    return `<section class="investigation-context"><strong>Process investigation</strong><p>Review the executable, owner, parent relationship, signature, persistence, and network activity before containment. Current actionable candidates are listed below.</p></section>`;
  }
  return '';
}

function renderInvestigationControls(finding, investigation = {}) {
  const statuses = ['New', 'Investigating', 'Expected', 'Suspicious', 'Contained', 'Resolved'];
  const current = investigation.current !== false;
  const status = current ? (investigation.status || 'New') : 'New';
  const stale = current ? '' : `<p class="investigation-stale">This item changed since it was marked ${escapeHtml(investigation.previous_status || 'reviewed')}. Review the new evidence before trusting the previous decision.</p>`;
  return `<section class="investigation-box"><div><strong>Investigation status</strong><span>Stored locally and kept separate from scan evidence.</span></div>${stale}<label>Status<select class="field" data-investigation-status>${statuses.map((value) => `<option value="${value}"${value === status ? ' selected' : ''}>${value}</option>`).join('')}</select></label><label>Analyst note<textarea class="field textarea" data-investigation-note maxlength="2000" placeholder="Why is this expected or suspicious?">${escapeHtml(current ? investigation.note || '' : '')}</textarea></label><button type="button" class="secondary-button" data-save-investigation="${escapeHtml(finding.finding_id)}">Save investigation state</button><span class="investigation-message" role="status"></span></section>`;
}

async function saveInvestigation(button) {
  const box = button.closest('.investigation-box');
  if (!box || !state.currentScanId) return;
  button.disabled = true;
  const message = box.querySelector('.investigation-message');
  message.textContent = 'Saving locally...';
  try {
    const result = await api('/api/investigations', writeOptions('POST', {
      scan_id: state.currentScanId,
      finding_id: button.dataset.saveInvestigation,
      status: box.querySelector('[data-investigation-status]').value,
      note: box.querySelector('[data-investigation-note]').value,
    }));
    state.decisionSupport = await api(`/api/decision-support/${encodeURIComponent(state.currentScanId)}`);
    state.guidance = state.decisionSupport.guidance || result.guidance;
    renderGuidance(state.guidance);
    renderApplicationReview(state.decisionSupport.application_review);
    renderDecisionSupport(state.decisionSupport);
    renderFindingPage();
    setMessage('Investigation state saved locally. Scan evidence was not changed.');
  } catch (error) {
    message.textContent = error.message;
    message.classList.add('error');
    button.disabled = false;
  }
}

async function lookupHashReputation(button) {
  const digest = button.dataset.hashReputation;
  if (!window.confirm(`Send only this SHA-256 to the enabled reputation providers?\n\n${digest}\n\nThe application file will not be uploaded.`)) return;
  const resultBox = button.closest('.reputation-action').querySelector('[data-reputation-result]');
  button.disabled = true;
  resultBox.textContent = 'Checking enabled providers...';
  try {
    const response = await api('/api/reputation/hash', writeOptions('POST', {sha256:digest}));
    resultBox.innerHTML = (response.providers || []).map((provider) => {
      if (provider.status === 'error') return `<span class="reputation-provider error"><strong>${escapeHtml(provider.provider)}</strong>${escapeHtml(provider.error)}</span>`;
      if (provider.status === 'not_found') return `<span class="reputation-provider"><strong>${escapeHtml(provider.provider)}</strong>No matching record. This does not prove the file is safe.</span>`;
      const stats = provider.analysis_stats || {};
      const detail = provider.provider === 'VirusTotal' ? `${stats.malicious || 0} malicious | ${stats.suspicious || 0} suspicious | ${stats.harmless || 0} harmless` : provider.signature ? `Known sample | ${provider.signature}` : provider.matches !== undefined ? `${provider.matches} ThreatFox match(es)` : 'Known sample';
      return `<span class="reputation-provider alert"><strong>${escapeHtml(provider.provider)}</strong>${escapeHtml(detail)}</span>`;
    }).join('');
  } catch (error) { resultBox.textContent = error.message; resultBox.classList.add('error'); }
  finally { button.disabled = false; }
}

function processCandidates(finding) {
  if (!['LIVE-PROCESS-TREE', 'LIVE-NETWORK-PROCESSES'].includes(finding.finding_id) || finding.status !== 'Review') return [];
  const candidates = new Map();
  (finding.evidence || []).forEach((evidence) => {
    const rows = evidence?.value?.review_candidates;
    if (!Array.isArray(rows)) return;
    rows.forEach((candidate) => {
      const pid = Number(candidate?.pid);
      if (Number.isInteger(pid) && pid > 1 && !candidates.has(pid)) candidates.set(pid, candidate);
    });
  });
  return [...candidates.values()];
}

function renderProcessResponseControls(finding) {
  const candidates = processCandidates(finding);
  if (!candidates.length) return '';
  const capability = state.config?.feature_capabilities?.process_response || {available:true, reason:''};
  const rows = candidates.map((candidate) => {
    const key = `${finding.finding_id}:${candidate.pid}`;
    state.processCandidates.set(key, {...candidate, finding_id:finding.finding_id});
    const reasons = Array.isArray(candidate.reasons) ? candidate.reasons.join(' | ') : '';
    const zombie = Boolean(candidate.zombie) || String(candidate.stat || '').toUpperCase().includes('Z');
    const legacy = !Number.isInteger(candidate.uid);
    const disabled = capability.available === false || zombie || legacy;
    const note = zombie ? 'Zombie process: it has already exited. Review or restart its parent so it can be reaped.' : legacy ? 'Run Live Triage again with the current version before using process response.' : capability.reason;
    const actions = disabled
      ? `<span class="process-action-note">${escapeHtml(note || 'Process response unavailable.')}</span>`
      : `<div class="process-buttons"><button type="button" data-process-key="${escapeHtml(key)}" data-process-action="terminate">Terminate</button><button type="button" class="force" data-process-key="${escapeHtml(key)}" data-process-action="kill">Force kill</button></div>`;
    return `<div class="process-action-row"><div><strong>PID ${escapeHtml(candidate.pid)} | ${escapeHtml(candidate.user || `UID ${candidate.uid}`)}</strong><code>${escapeHtml(candidate.executable || 'unknown')}</code><small>${escapeHtml(reasons || 'Live Triage review candidate')}</small></div>${actions}<span class="process-action-result" aria-live="polite"></span></div>`;
  }).join('');
  return `<section class="process-response"><div class="process-response-heading"><strong>Process response</strong><span>Evidence is a review signal, not a malware verdict. Preserve what you need before containment.</span></div>${rows}</section>`;
}

async function respondToProcess(button) {
  const candidate = state.processCandidates.get(button.dataset.processKey);
  if (!candidate || !state.currentScanId) return setMessage('The process action is not tied to a loaded scan. Reload the report.', true);
  const mode = button.dataset.processAction;
  const force = mode === 'kill';
  const prompt = force
    ? `Force kill PID ${candidate.pid} with SIGKILL?\n\n${candidate.executable}\n\nThe process cannot clean up and unsaved data may be lost. This finding is not proof of malware.`
    : `Terminate PID ${candidate.pid} with SIGTERM?\n\n${candidate.executable}\n\nPreserve volatile evidence first. This finding is not proof of malware.`;
  if (!window.confirm(prompt)) return;
  const row = button.closest('.process-action-row');
  const result = row.querySelector('.process-action-result');
  row.querySelectorAll('button').forEach((item) => { item.disabled = true; });
  result.textContent = force ? 'Sending SIGKILL...' : 'Sending SIGTERM...';
  try {
    const response = await api('/api/processes/terminate', writeOptions('POST', {
      scan_id: state.currentScanId, pid: Number(candidate.pid), mode,
    }));
    const auditNote = response.audit_logged === false ? ` ${response.audit_error}` : ' The action was recorded in the local response log.';
    result.textContent = `${response.signal} sent at ${response.timestamp}.${auditNote} Run Live Triage again to confirm current state.`;
    row.classList.add('process-action-complete');
    setMessage(`${response.signal} sent to PID ${response.pid}.${response.audit_logged === false ? ' The local audit log could not be updated.' : ' The action was recorded locally.'}`, response.audit_logged === false);
  } catch (error) {
    result.textContent = error.message;
    result.classList.add('error');
    row.querySelectorAll('button').forEach((item) => { item.disabled = false; });
    setMessage(error.message, true);
  }
}

async function loadHistory() {
  try {
    const payload = await api('/api/scans');
    state.historyScans = payload.scans;
    renderHistory();
  } catch (error) { $('#history').innerHTML = `<p class="muted">${escapeHtml(error.message)}</p>`; }
}

function setInline(selector, message, error = false) {
  const element = $(selector);
  if (!element) return;
  element.textContent = message || '';
  element.classList.toggle('error', error);
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KiB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
}

async function loadOperationsData() {
  try {
    const [settings, cases, packs, rules, cache] = await Promise.all([
      api('/api/settings'), api('/api/cases'), api('/api/ioc-packs'), api('/api/yara-rules'), api('/api/osint-cache')
    ]);
    state.settings = settings;
    state.cases = cases.cases || [];
    applyEnglishCopy();
    renderCases();
    renderSettings();
    renderManagedFiles(packs.packs || [], rules.rules || []);
    renderCache(cache.entries || []);
  } catch (error) {
    setInline('#osint-settings-message', error.message, true);
  }
}

function renderCases() {
  const options = `<option value="">${escapeHtml(t('noSavedCase'))}</option>` + state.cases.map((item) => `<option value="${escapeHtml(item.id)}">${item.archived ? '◌ ' : ''}${escapeHtml(item.reference)} | ${escapeHtml(item.title)}</option>`).join('');
  $('#case-select').innerHTML = options;
  $('#scan-case-select').innerHTML = options;
  if (state.activeCaseId && state.cases.some((item) => item.id === state.activeCaseId)) $('#case-select').value = state.activeCaseId;
}

function loadCaseIntoEditor(caseId) {
  state.activeCaseId = caseId || '';
  const item = state.cases.find((entry) => entry.id === caseId) || {};
  $('#managed-case-reference').value = item.reference || '';
  $('#managed-case-title').value = item.title || '';
  $('#managed-case-analyst').value = item.analyst || '';
  $('#managed-case-notes').value = item.notes || '';
  $('#managed-case-archived').checked = Boolean(item.archived);
}

function attachCaseToScan(caseId) {
  const item = state.cases.find((entry) => entry.id === caseId);
  if (!item) return;
  $('#case-reference').value = item.reference || '';
  $('#analyst').value = item.analyst || '';
  setMessage(`${item.reference} attached to the next scan.`);
}

async function saveCase() {
  setInline('#case-message', 'Saving...');
  try {
    const saved = await api('/api/cases', writeOptions('POST', {
      id: state.activeCaseId || undefined,
      reference: $('#managed-case-reference').value,
      title: $('#managed-case-title').value,
      analyst: $('#managed-case-analyst').value,
      notes: $('#managed-case-notes').value,
      archived: $('#managed-case-archived').checked,
    }));
    state.activeCaseId = saved.id;
    const payload = await api('/api/cases');
    state.cases = payload.cases || [];
    renderCases();
    $('#case-select').value = saved.id;
    $('#scan-case-select').value = saved.id;
    attachCaseToScan(saved.id);
    setInline('#case-message', `Saved ${saved.reference}.`);
  } catch (error) { setInline('#case-message', error.message, true); }
}

function renderSettings() {
  const settings = state.settings || {};
  document.querySelectorAll('[data-provider]').forEach((input) => { input.checked = Boolean(settings.providers?.[input.dataset.provider]?.enabled); });
  $('#cache-hours').value = settings.cache_hours || 24;
  $('#nvd-key-state').textContent = settings.providers?.nvd?.api_key_configured ? `| ${t('configured')}` : `| ${t('notConfigured')}`;
  $('#threatfox-key-state').textContent = settings.providers?.threatfox?.auth_key_configured ? `| ${t('configured')}` : `| ${t('notConfigured')}`;
  $('#virustotal-key-state').textContent = settings.providers?.virustotal?.api_key_configured ? `| ${t('configured')}` : `| ${t('notConfigured')}`;
  $('#malwarebazaar-key-state').textContent = settings.providers?.malwarebazaar?.auth_key_configured ? `| ${t('configured')}` : `| ${t('notConfigured')}`;
  $('#yara-enabled').checked = Boolean(settings.yara?.enabled);
  $('#yara-targets').value = (settings.yara?.targets || []).join('\n');
  $('#signing-enabled').checked = Boolean(settings.signing?.enabled);
  const signingAlgorithm = settings.signing?.algorithm || 'HMAC-SHA256 / Ed25519';
  $('#signing-status').innerHTML = settings.signing?.key_configured ? `<strong>${escapeHtml(signingAlgorithm)}</strong><br>${escapeHtml(t('configured'))} | signing material stored locally` : `<strong>${escapeHtml(signingAlgorithm)}</strong><br>${escapeHtml(t('notConfigured'))}`;
  const signingCapability = state.config?.feature_capabilities?.signing || {available:true, reason:''};
  $('#generate-signing-key').disabled = signingCapability.available === false;
  $('#generate-signing-key').title = signingCapability.reason || '';
  const yaraCapability = state.config?.feature_capabilities?.yara || {available:true, reason:''};
  $('#yara-enabled').title = yaraCapability.reason || '';
}

async function saveOsintSettings() {
  const providers = {};
  document.querySelectorAll('[data-provider]').forEach((input) => { providers[input.dataset.provider] = {enabled: input.checked}; });
  if ($('#nvd-api-key').value) providers.nvd.api_key = $('#nvd-api-key').value;
  if ($('#threatfox-auth-key').value) providers.threatfox.auth_key = $('#threatfox-auth-key').value;
  if ($('#virustotal-api-key').value) providers.virustotal.api_key = $('#virustotal-api-key').value;
  if ($('#malwarebazaar-auth-key').value) providers.malwarebazaar.auth_key = $('#malwarebazaar-auth-key').value;
  try {
    state.settings = await api('/api/settings', writeOptions('POST', {cache_hours:Number($('#cache-hours').value), providers}));
    $('#nvd-api-key').value = '';
    $('#threatfox-auth-key').value = '';
    $('#virustotal-api-key').value = '';
    $('#malwarebazaar-auth-key').value = '';
    renderSettings();
    setInline('#osint-settings-message', 'Settings saved locally.');
  } catch (error) { setInline('#osint-settings-message', error.message, true); }
}

async function saveYaraSettings() {
  try {
    const targets = $('#yara-targets').value.split('\n').map((value) => value.trim()).filter(Boolean);
    state.settings = await api('/api/settings', writeOptions('POST', {yara:{enabled:$('#yara-enabled').checked, targets}}));
    renderSettings();
    setInline('#rules-message', 'YARA scope saved locally.');
  } catch (error) { setInline('#rules-message', error.message, true); }
}

async function updateSigningEnabled() {
  try {
    state.settings = await api('/api/settings', writeOptions('POST', {signing:{enabled:$('#signing-enabled').checked}}));
    renderSettings();
    setInline('#signing-message', 'Signing preference saved.');
  } catch (error) { setInline('#signing-message', error.message, true); }
}

async function generateSigningKey() {
  const replace = Boolean(state.settings?.signing?.key_configured);
  if (replace && !window.confirm('Replace the current signing identity? Keep the old identity if you must verify earlier HMAC-signed manifests.')) return;
  try {
    const result = await api('/api/signing/generate', writeOptions('POST', {replace}));
    state.settings = await api('/api/settings');
    renderSettings();
    setInline('#signing-message', result.public_key_sha256 ? `${result.algorithm} ready | fingerprint ${result.public_key_sha256}` : `${result.algorithm} ready | local secret stored with 0600 permissions.`);
  } catch (error) { setInline('#signing-message', error.message, true); }
}

async function importManagedFile(kind, input) {
  const file = input.files?.[0];
  if (!file) return;
  setInline('#rules-message', `Validating ${file.name}...`);
  try {
    const text = await file.text();
    const content = kind === 'ioc-packs' ? JSON.parse(text) : text;
    await api(`/api/${kind}`, writeOptions('POST', {filename:file.name, content}));
    input.value = '';
    const [packs, rules] = await Promise.all([api('/api/ioc-packs'), api('/api/yara-rules')]);
    renderManagedFiles(packs.packs || [], rules.rules || []);
    setInline('#rules-message', `${file.name} imported locally.`);
  } catch (error) { setInline('#rules-message', error.message, true); }
}

function renderManagedFiles(packs, rules) {
  const row = (kind, item, detail) => `<div class="managed-row"><span><strong>${escapeHtml(item.filename)}</strong><small>${escapeHtml(detail)}</small></span><button type="button" data-delete-kind="${kind}" data-delete-name="${escapeHtml(item.filename)}">Delete</button></div>`;
  $('#ioc-pack-list').innerHTML = packs.length ? packs.map((item) => row('ioc-packs', item, item.valid ? `${item.name} | v${item.version} | ${item.indicator_count} indicators | ${formatBytes(item.size)}` : item.error)).join('') : '<p class="muted">No imported IOC packs.</p>';
  $('#yara-rule-list').innerHTML = rules.length ? rules.map((item) => row('yara-rules', item, item.valid ? formatBytes(item.size) : item.error)).join('') : '<p class="muted">No imported YARA rules.</p>';
  document.querySelectorAll('[data-delete-kind]').forEach((button) => button.addEventListener('click', () => deleteManagedFile(button.dataset.deleteKind, button.dataset.deleteName)));
}

async function deleteManagedFile(kind, filename) {
  if (!window.confirm(`Delete local managed file ${filename}?`)) return;
  try {
    await api(`/api/${kind}/${encodeURIComponent(filename)}`, {method:'DELETE', headers:{'X-MacOS-Inspector':'1'}});
    const [packs, rules] = await Promise.all([api('/api/ioc-packs'), api('/api/yara-rules')]);
    renderManagedFiles(packs.packs || [], rules.rules || []);
    setInline('#rules-message', `${filename} deleted.`);
  } catch (error) { setInline('#rules-message', error.message, true); }
}

function renderCache(entries) {
  $('#cache-list').innerHTML = entries.length ? entries.map((item) => `<div class="managed-row"><span><strong>${escapeHtml(item.provider || item.name)}</strong><small>${escapeHtml(item.fetched_at)} | ${formatBytes(item.size)} | SHA-256 ${escapeHtml(String(item.sha256).slice(0,16))}...</small></span></div>`).join('') : '<p class="muted">No cached intelligence yet.</p>';
}

async function clearOsintCache() {
  if (!window.confirm('Delete the local OSINT cache? Future online scans will download fresh public data.')) return;
  try {
    const result = await api('/api/osint-cache/clear', writeOptions('POST', {}));
    renderCache([]);
    setInline('#osint-settings-message', `${result.cleared} cache file(s) deleted.`);
  } catch (error) { setInline('#osint-settings-message', error.message, true); }
}

async function lookupThreatFox() {
  const indicator = $('#threatfox-indicator').value.trim();
  if (!indicator) return setInline('#osint-settings-message', 'Enter an indicator for the explicit lookup.', true);
  if (!window.confirm(`Send only this indicator to ThreatFox?\n\n${indicator}`)) return;
  $('#threatfox-result').innerHTML = '<p class="muted">Querying ThreatFox...</p>';
  try {
    const result = await api('/api/threatfox/lookup', writeOptions('POST', {indicator}));
    const rows = result.data || [];
    $('#threatfox-result').innerHTML = rows.length ? rows.slice(0,50).map((item) => `<div class="managed-row"><span><strong>${escapeHtml(item.ioc || item.id || indicator)}</strong><small>${escapeHtml(item.threat_type || item.malware_printable || result.query_status)} | confidence ${escapeHtml(item.confidence_level ?? 'N/A')}</small></span></div>`).join('') : `<p class="muted">${escapeHtml(result.query_status)} | no matching IOC returned.</p>`;
    setInline('#osint-settings-message', 'Explicit ThreatFox lookup complete. The result was not persisted automatically.');
  } catch (error) {
    $('#threatfox-result').innerHTML = '';
    setInline('#osint-settings-message', error.message, true);
  }
}

async function loadDashboardData() {
  if (state.loadingConfig) return;
  state.loadingConfig = true;
  try {
    state.config = await api('/api/config');
    renderCollectors();
    renderFormats();
    await loadApplications();
    await loadOperationsData();
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

function ruleOutcomeIndex(summary) {
  if (summary?.assessed_finding_count === 0) return 'N/A (no assessed findings)';
  return summary?.overall_score ?? 'N/A';
}

function renderHistory() {
  const query = $('#history-search').value.trim().toLowerCase();
  const matching = state.historyScans.filter((job) => !query || [job.scan_id, job.case_reference, job.analyst, job.target_application, job.state, ...(job.collectors || [])].join(' ').toLowerCase().includes(query));
  const visible = matching.slice(0, 50);
  $('#history-count').textContent = matching.length === state.historyScans.length ? `${matching.length} scan${matching.length === 1 ? '' : 's'}` : `${matching.length} of ${state.historyScans.length}`;
  if (!state.historyScans.length) { $('#history').innerHTML = '<p class="muted">No previous scans in this output directory.</p>'; return; }
  if (!visible.length) { $('#history').innerHTML = '<p class="muted">No scans match this search.</p>'; return; }
  $('#history').innerHTML = visible.map((job) => {
    const actions = job.reports?.json ? `<button type="button" class="history-baseline${state.baselineJob?.job_id === job.job_id ? ' selected' : ''}" data-baseline-id="${escapeHtml(job.job_id)}">Baseline</button><button type="button" class="history-compare" data-compare-id="${escapeHtml(job.job_id)}">Compare</button><button type="button" class="history-open" data-history-id="${escapeHtml(job.job_id)}">View</button>` : '';
    const target = job.target_application ? ` | target ${job.target_application.split('/').pop()}` : '';
    return `<div class="history-row"><div class="history-main"><strong>${job.case_reference ? `<span class="case-tag">${escapeHtml(job.case_reference)}</span> ` : ''}${escapeHtml((job.collectors || []).join(' | '))}</strong><small>${escapeHtml(job.completed_at || job.created_at || '')} | rule outcome index ${escapeHtml(ruleOutcomeIndex(job.summary))}${escapeHtml(target)}${job.analyst ? ` | ${escapeHtml(job.analyst)}` : ''}${job.error ? ` | ${escapeHtml(job.error)}` : ''}<code>${escapeHtml(job.scan_id || '')}</code></small></div><span class="status-pill status-${escapeHtml(job.state)}">${escapeHtml(job.state)}</span>${actions}</div>`;
  }).join('') + (matching.length > 50 ? `<p class="muted">Showing the 50 most recent matches.</p>` : '');
  document.querySelectorAll('[data-history-id]').forEach((button) => button.addEventListener('click', () => loadHistoryJob(state.historyScans.find((item) => item.job_id === button.dataset.historyId))));
  document.querySelectorAll('[data-baseline-id]').forEach((button) => button.addEventListener('click', () => setBaseline(state.historyScans.find((item) => item.job_id === button.dataset.baselineId))));
  document.querySelectorAll('[data-compare-id]').forEach((button) => button.addEventListener('click', () => compareWithBaseline(state.historyScans.find((item) => item.job_id === button.dataset.compareId))));
}

function setBaseline(job) {
  if (!job?.scan_id || !job.reports?.json) return setMessage('This scan has no JSON report and cannot be used as a baseline.', true);
  state.baselineJob = job;
  setMessage(`Baseline selected: ${job.scan_id.slice(0, 8)} | rule outcome index ${ruleOutcomeIndex(job.summary)}. Choose Compare on another scan.`);
  document.querySelectorAll('[data-baseline-id]').forEach((button) => button.classList.toggle('selected', button.dataset.baselineId === job.job_id));
}

async function compareWithBaseline(job) {
  if (!state.baselineJob) return setMessage('Select a baseline scan first.', true);
  if (!job?.scan_id || !job.reports?.json) return setMessage('This scan has no JSON report and cannot be compared.', true);
  if (job.scan_id === state.baselineJob.scan_id) return setMessage('Choose a different scan to compare with the baseline.', true);
  setMessage('Comparing normalized findings...');
  try {
    const comparison = await api('/api/compare', writeOptions('POST', {baseline: state.baselineJob.scan_id, current: job.scan_id}));
    renderComparison(comparison);
    setViewMode('analyst');
    setMessage('Comparison complete.');
    document.querySelector('.results-panel').scrollIntoView({behavior: 'smooth', block: 'start'});
  } catch (error) { setMessage(error.message, true); }
}

function renderComparison(comparison) {
  const delta = comparison.score_delta === null ? 'N/A' : comparison.score_delta > 0 ? `+${comparison.score_delta}` : String(comparison.score_delta);
  $('#comparison-summary').innerHTML = [['Rule outcome index change', delta], ['New', comparison.counts.new], ['Resolved', comparison.counts.resolved], ['Changed', comparison.counts.changed]].map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join('');
  const rows = [
    ...comparison.new.map((finding) => ({kind: 'New', id: finding.finding_id, title: finding.title, detail: `${finding.severity} | ${finding.status}`})),
    ...comparison.resolved.map((finding) => ({kind: 'Resolved', id: finding.finding_id, title: finding.title, detail: `${finding.severity} | ${finding.status}`})),
    ...comparison.changed.map((finding) => ({kind: 'Changed', id: finding.finding_id, title: finding.title, detail: Object.entries(finding.changes).map(([field, values]) => `${field}: ${values.before} -> ${values.after}`).join(' | ')})),
  ];
  const targetChange = comparison.scope?.baseline_target_application || comparison.scope?.current_target_application ? ` Previous target: ${escapeHtml(comparison.scope.baseline_target_application || 'all applications')}. Current target: ${escapeHtml(comparison.scope.current_target_application || 'all applications')}.` : '';
  const scopeWarning = comparison.scope?.changed ? `<div class="comparison-warning"><strong>Collection scope changed.</strong> Added: ${escapeHtml(comparison.scope.added_collectors.join(', ') || 'none')}. Removed: ${escapeHtml(comparison.scope.removed_collectors.join(', ') || 'none')}.${targetChange} New and resolved counts may reflect collection coverage rather than a host-state change.</div>` : '';
  const exports = comparison.reports ? `<div class="comparison-exports"><strong>Comparison reports</strong><a href="${escapeHtml(comparison.reports.comparison_html)}" target="_blank" rel="noreferrer">Open HTML</a><a href="${escapeHtml(comparison.reports.comparison_json)}" target="_blank" rel="noreferrer">Open JSON</a></div>` : '';
  const indexNote = comparison.score_delta === null ? '<div class="comparison-warning">The index change is N/A because at least one scan had no assessed findings. Finding-level changes remain available.</div>' : '';
  $('#comparison-results').innerHTML = exports + indexNote + scopeWarning + (rows.length ? rows.slice(0, 200).map((row) => `<div class="comparison-row"><span class="comparison-kind comparison-${row.kind.toLowerCase()}">${escapeHtml(row.kind)}</span><div><strong>${escapeHtml(row.title)}</strong><code>${escapeHtml(row.id)}</code><small>${escapeHtml(row.detail)}</small></div></div>`).join('') + (rows.length > 200 ? `<p class="muted">Showing 200 of ${rows.length} changes.</p>` : '') : '<p class="muted">No finding-level changes were detected.</p>');
  $('#comparison-panel').classList.remove('hidden');
}

async function loadHistoryJob(job) {
  if (!job) return;
  renderProgress(job); renderReports(job); await loadReport(job);
  document.querySelector('.results-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

document.addEventListener('DOMContentLoaded', async () => {
  if (window.location.protocol === 'file:' || new URLSearchParams(window.location.search).has('source-preview')) {
    document.body.classList.add('file-mode');
    $('#local-launcher-help').classList.remove('hidden');
    applyEnglishCopy();
    return;
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
  $('#inspect-application').addEventListener('click', inspectSelectedApplication);
  $('#inspect-application-activity').addEventListener('click', inspectSelectedApplicationActivity);
  $('#application-search').addEventListener('input', renderApplications);
  $('#target-application').addEventListener('change', updateRunAvailability);
  $('#check-this-mac').addEventListener('click', startGuidedCheck);
  $('#dismiss-guide').addEventListener('click', dismissGuide);
  $('#show-guide').addEventListener('click', () => setGuideVisible(true));
  $('#view-simple').addEventListener('click', () => setViewMode('simple'));
  $('#view-analyst').addEventListener('click', () => setViewMode('analyst'));
  $('#case-select').addEventListener('change', () => loadCaseIntoEditor($('#case-select').value));
  $('#scan-case-select').addEventListener('change', () => attachCaseToScan($('#scan-case-select').value));
  $('#save-case').addEventListener('click', saveCase);
  $('#save-osint-settings').addEventListener('click', saveOsintSettings);
  $('#clear-osint-cache').addEventListener('click', clearOsintCache);
  $('#lookup-threatfox').addEventListener('click', lookupThreatFox);
  $('#save-yara-settings').addEventListener('click', saveYaraSettings);
  $('#ioc-pack-file').addEventListener('change', () => importManagedFile('ioc-packs', $('#ioc-pack-file')));
  $('#yara-rule-file').addEventListener('change', () => importManagedFile('yara-rules', $('#yara-rule-file')));
  $('#generate-signing-key').addEventListener('click', generateSigningKey);
  $('#signing-enabled').addEventListener('change', updateSigningEnabled);
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
  applyEnglishCopy();
  try { setViewMode(window.localStorage.getItem('macos-inspector-view-mode') || 'simple', false); } catch (error) { setViewMode('simple', false); }
  try { if (window.localStorage.getItem('macos-inspector-guide-1.3.0') === 'dismissed') setGuideVisible(false); } catch (error) { /* Show the guide when local preferences are unavailable. */ }
  const health = await checkHealth();
  if (!health) setMessage('Dashboard server unavailable. Retrying automatically...', true);
  state.healthPoll = setInterval(checkHealth, 4000);
});
