const state = { config: null, settings: null, cases: [], activeCaseId: '', language: 'ro', activeJob: null, baselineJob: null, poll: null, healthPoll: null, online: false, starting: false, loadingConfig: false, findings: [], filteredFindings: [], findingPage: 1, findingPageSize: 50, historyScans: [] };

const I18N = {
  ro: {
    manage:'Administrare', introTitle:'Colectează dovezi fără comenzi în Terminal', introText:'Alege secțiunile, rulează scanarea read-only și analizează constatările și rapoartele într-un singur loc.', safety:'Local-first · OSINT online doar cu acord · fără remediere', operationsTitle:'Cazuri, surse și reguli', localSettings:'Configurări locale · permisiuni private', casesTitle:'Management cazuri', casesHelp:'Organizează scanările, analistul și notele investigației.', activeCase:'Caz activ', caseReference:'Referință', caseTitle:'Titlu caz', analyst:'Analist', archived:'Arhivat', caseNotes:'Note locale', saveCase:'Salvează cazul', osintHelp:'Activează providerii și verifică proveniența copiilor locale.', cacheHours:'Cache (ore)', saveSettings:'Salvează configurarea', clearCache:'Golește cache-ul', rulesHelp:'Importă pachete versionate și scanează doar ținte explicite.', chooseFile:'Alege fișier', enableYara:'Activează scanarea YARA', yaraOptional:'Necesită executabilul yara într-o cale de încredere.', yaraTargets:'Ținte YARA explicite · o cale pe linie', saveYara:'Salvează țintele YARA', evidenceProtection:'Protecția dovezilor', evidenceHelp:'HMAC inclus, Ed25519 și AES-256-GCM când suportul criptografic este disponibil.', generateKey:'Generează identitatea de semnare', signManifests:'Semnează manifestele automat', keyPrivacy:'Secretul sau cheia privată rămâne local, cu permisiuni 0600, și nu este inclusă în rapoarte sau arhive.', attachCase:'Atașează un caz salvat', bundlePassword:'Parolă arhivă criptată · minimum 12 caractere', noSavedCase:'Fără caz salvat', configured:'configurată', notConfigured:'neconfigurată',
    publicNoKey:'Sursă publică · fără cheie', optionalKey:'API public · cheie opțională', optionalFreeKey:'Opțional · Auth-Key gratuit', optional:'opțional', explicitLookup:'Căutare IOC explicită în ThreatFox', lookup:'Caută', threatfoxPrivacy:'Doar indicatorul introdus mai sus este trimis la ThreatFox după apăsarea butonului. Nu se transmite nimic automat.', iocPacks:'Pachete IOC', yaraRules:'Reguli YARA', readinessTitle:'Pregătirea colectării', recheck:'Reverifică', checkingAccess:'Verific accesul local…', runningDiagnostics:'Rulez diagnostice read-only…', auditSections:'Secțiuni de audit', all:'Toate', clear:'Golește', scanProfiles:'Profiluri de scanare', individualSections:'Secțiuni individuale', reportFormats:'Formate de raport', caseReferenceOptional:'Referință caz', analystOptional:'Analist', optionalLabel:'opțional', casePlaceholder:'ID incident sau caz', analystPlaceholder:'Nume sau echipă', minimumSeverity:'Severitatea minimă afișată', severityAll:'Toate constatările', severityLow:'Low și mai sus', severityMedium:'Medium și mai sus', severityHigh:'High și mai sus', severityCritical:'Doar Critical', runSelected:'Rulează auditul selectat', cancelScan:'Anulează scanarea', scanResults:'Rezultatele scanării', ready:'Pregătit', readyTitle:'Totul este pregătit.', readyHelp:'Selectează o secțiune și pornește un audit.', scanComparison:'Compararea scanărilor', close:'Închide', searchFindings:'Caută în constatări', searchFindingsPlaceholder:'Titlu, ID, dovadă…', status:'Stare', allStatuses:'Toate stările', category:'Categorie', allCategories:'Toate categoriile', previous:'Anterior', next:'Următor', noScan:'Nicio scanare selectată', noScanHelp:'Constatările vor apărea aici cu dovezi, comenzi și recomandări.', previousScans:'Scanări anterioare', refresh:'Actualizează', findScan:'Caută o scanare', findScanPlaceholder:'Caz, analist, colector sau ID scanare', interfaceLanguage:'Limba interfeței', onlineOptIn:'Online cu acord', run:'Rulează', sections:'secțiuni', unavailable:'Indisponibil'
  },
  en: {
    manage:'Manage', introTitle:'Collect evidence without terminal commands', introText:'Choose audit sections, run a read-only scan, then inspect findings and reports in one place.', safety:'Local-first · online OSINT is opt-in · no remediation', operationsTitle:'Cases, sources and rules', localSettings:'Local settings · private permissions', casesTitle:'Case management', casesHelp:'Organize scans, analyst identity and investigation notes.', activeCase:'Active case', caseReference:'Reference', caseTitle:'Case title', analyst:'Analyst', archived:'Archived', caseNotes:'Local notes', saveCase:'Save case', osintHelp:'Enable providers and inspect local-cache provenance.', cacheHours:'Cache (hours)', saveSettings:'Save settings', clearCache:'Clear cache', rulesHelp:'Import versioned packs and scan explicit targets only.', chooseFile:'Choose file', enableYara:'Enable YARA scanning', yaraOptional:'Requires the yara executable in a trusted path.', yaraTargets:'Explicit YARA targets · one path per line', saveYara:'Save YARA targets', evidenceProtection:'Evidence protection', evidenceHelp:'Built-in HMAC, with Ed25519 and AES-256-GCM when cryptographic support is available.', generateKey:'Generate signing identity', signManifests:'Sign manifests automatically', keyPrivacy:'The secret or private key remains local with 0600 permissions and is never included in reports or bundles.', attachCase:'Attach a saved case', bundlePassword:'Encrypted bundle password · minimum 12 characters', noSavedCase:'No saved case', configured:'configured', notConfigured:'not configured',
    publicNoKey:'Public source · no key', optionalKey:'Public API · optional key', optionalFreeKey:'Optional · free Auth-Key', optional:'optional', explicitLookup:'Explicit ThreatFox IOC lookup', lookup:'Lookup', threatfoxPrivacy:'Only the indicator entered above is sent to ThreatFox after you press Lookup. Nothing is submitted automatically.', iocPacks:'IOC packs', yaraRules:'YARA rules', readinessTitle:'Collection readiness', recheck:'Recheck', checkingAccess:'Checking local access…', runningDiagnostics:'Running read-only diagnostics…', auditSections:'Audit sections', all:'All', clear:'Clear', scanProfiles:'Scan profiles', individualSections:'Individual sections', reportFormats:'Report formats', caseReferenceOptional:'Case reference', analystOptional:'Analyst', optionalLabel:'optional', casePlaceholder:'Incident or case ID', analystPlaceholder:'Name or team', minimumSeverity:'Minimum severity shown', severityAll:'All findings', severityLow:'Low and above', severityMedium:'Medium and above', severityHigh:'High and above', severityCritical:'Critical only', runSelected:'Run selected audit', cancelScan:'Cancel running scan', scanResults:'Scan results', ready:'Ready', readyTitle:'Ready when you are.', readyHelp:'Select a section and start an audit.', scanComparison:'Scan comparison', close:'Close', searchFindings:'Search findings', searchFindingsPlaceholder:'Title, ID, evidence…', status:'Status', allStatuses:'All statuses', category:'Category', allCategories:'All categories', previous:'Previous', next:'Next', noScan:'No scan selected', noScanHelp:'Your findings will appear here with evidence, commands and recommendations.', previousScans:'Previous scans', refresh:'Refresh', findScan:'Find a scan', findScanPlaceholder:'Case, analyst, collector or scan ID', interfaceLanguage:'Interface language', onlineOptIn:'Online opt-in', run:'Run', sections:'sections', unavailable:'Unavailable'
  }
};

const COLLECTOR_TITLES_RO = { 'accounts-access':'Conturi și acces administrativ', 'application-trust':'Încrederea aplicațiilor', 'background-items':'Elemente de login și fundal', 'browser-artifacts':'Artefacte din browsere', ioc:'Pachete IOC', 'live-triage':'Triaj live al incidentului', persistence:'Mecanisme de persistență', privacy:'Permisiuni TCC și confidențialitate', network:'Rețea și certificate', 'osint-intelligence':'Inteligență OSINT gratuită', 'vulnerability-exposure':'Expunere la vulnerabilități', 'yara-rules':'Reguli YARA administrate', 'management-profiles':'Management și profiluri de configurare', 'system-extensions':'Extensii de sistem', security:'Controale de securitate' };
const PROFILE_COPY_RO = { quick:['Triaj rapid','Conturi, procese live, persistență, întărire, management, rețea, extensii și verificări IOC.'], 'application-trust':['Application Trust','Analiză detaliată de încredere, semnătură și integritate pentru aplicațiile instalate.'], 'privacy-browser':['Confidențialitate și browsere','Permisiuni TCC plus istoric și descărcări din browserele acceptate.'], 'online-osint':['Inteligență despre vulnerabilități','Corelare opțională Apple, CISA KEV, FIRST EPSS și NIST NVD, cu cache last-known-good.'], 'threat-hunting':['Threat Hunting','Triaj live de procese și rețea plus IOC și reguli YARA opționale.'], full:['Colectare locală completă','Toate secțiunile locale, inclusiv analiza aplicațiilor; exclude OSINT online.'] };

const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
const t = (key) => I18N[state.language]?.[key] || I18N.en[key] || key;
const writeOptions = (method, body) => ({method, headers:{'Content-Type':'application/json', 'X-MacOS-Inspector':'1'}, body:JSON.stringify(body)});

function applyLanguage(language) {
  state.language = language === 'en' ? 'en' : 'ro';
  document.documentElement.lang = state.language;
  $('#language-select').value = state.language;
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

function renderCollectors(preserve = false) {
  const previouslySelected = preserve ? new Set(selectedCollectors()) : new Set();
  $('#collectors').innerHTML = state.config.collectors.map((collector) => `
    <div class="collector-card${collector.external_network ? ' external' : ''}">
      <input type="checkbox" id="collector-${escapeHtml(collector.id)}" data-collector="${escapeHtml(collector.id)}">
      <label for="collector-${escapeHtml(collector.id)}"><span class="collector-title">${escapeHtml(state.language === 'ro' ? (COLLECTOR_TITLES_RO[collector.id] || collector.title) : collector.title)}${collector.external_network ? `<em class="online-badge">${escapeHtml(t('onlineOptIn'))}</em>` : ''}</span><span class="collector-id">${escapeHtml(collector.id)}</span>${collector.privacy_note ? `<small class="collector-note">${escapeHtml(collector.privacy_note)}</small>` : ''}</label>
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
  $('#scan-profiles').innerHTML = profiles.map((profile) => { const copy = state.language === 'ro' ? PROFILE_COPY_RO[profile.id] : null; const title = copy?.[0] || profile.title, description = copy?.[1] || profile.description; return `<button type="button" class="profile-card" data-profile="${escapeHtml(profile.id)}" title="${escapeHtml(description)}"><strong>${escapeHtml(title)}</strong><small>${escapeHtml(description)}</small><span>${escapeHtml(profile.collectors.length)} ${escapeHtml(t('sections'))}</span></button>`; }).join('');
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
  if (announce) setMessage(`${profile.title} selected · ${profile.collectors.length} audit section${profile.collectors.length === 1 ? '' : 's'}. Review the scope, then run the audit.`);
}

function renderFormats(preserve = false) {
  const selectedBefore = preserve ? new Set(selectedValues('format')) : new Set();
  const labels = state.language === 'ro'
    ? { html: 'HTML interactiv', json: 'JSON', markdown: 'Markdown', csv: 'CSV', sarif: 'SARIF', manifest: 'Manifest de dovezi', pdf: 'PDF', bundle: 'Arhivă ZIP de caz', 'encrypted-bundle': 'Arhivă de caz criptată' }
    : { html: 'Interactive HTML', json: 'JSON', markdown: 'Markdown', csv: 'CSV', sarif: 'SARIF', manifest: 'Evidence manifest', pdf: 'PDF', bundle: 'Case bundle ZIP', 'encrypted-bundle': 'Encrypted case bundle' };
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
  if (formats.includes('encrypted-bundle') && $('#bundle-password').value.length < 12) return setMessage('Encrypted bundle password must contain at least 12 characters.', true);
  const onlineCollectors = (state.config.collectors || []).filter((collector) => collectors.includes(collector.id) && collector.external_network);
  if (onlineCollectors.length && !window.confirm(`This scan will access the internet for: ${onlineCollectors.map((collector) => collector.title).join(', ')}. No host, case, hash, or file data is sent. Continue?`)) return;
  state.starting = true;
  updateRunAvailability();
  $('#cancel-scan').classList.remove('hidden');
  $('#cancel-scan').disabled = false;
  setMessage('Starting read-only collection…');
  try {
    const job = await api('/api/scans', writeOptions('POST', { collectors, formats, minimum: $('#minimum').value, case_reference: $('#case-reference').value, analyst: $('#analyst').value, bundle_password: $('#bundle-password').value }));
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
    applyLanguage(settings.language || state.language);
    renderCases();
    renderSettings();
    renderManagedFiles(packs.packs || [], rules.rules || []);
    renderCache(cache.entries || []);
  } catch (error) {
    setInline('#osint-settings-message', error.message, true);
  }
}

function renderCases() {
  const options = `<option value="">${escapeHtml(t('noSavedCase'))}</option>` + state.cases.map((item) => `<option value="${escapeHtml(item.id)}">${item.archived ? '◌ ' : ''}${escapeHtml(item.reference)} · ${escapeHtml(item.title)}</option>`).join('');
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
  setInline('#case-message', 'Saving…');
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
  $('#nvd-key-state').textContent = settings.providers?.nvd?.api_key_configured ? `· ${t('configured')}` : `· ${t('notConfigured')}`;
  $('#threatfox-key-state').textContent = settings.providers?.threatfox?.auth_key_configured ? `· ${t('configured')}` : `· ${t('notConfigured')}`;
  $('#yara-enabled').checked = Boolean(settings.yara?.enabled);
  $('#yara-targets').value = (settings.yara?.targets || []).join('\n');
  $('#signing-enabled').checked = Boolean(settings.signing?.enabled);
  const signingAlgorithm = settings.signing?.algorithm || 'HMAC-SHA256 / Ed25519';
  $('#signing-status').innerHTML = settings.signing?.key_configured ? `<strong>${escapeHtml(signingAlgorithm)}</strong><br>${escapeHtml(t('configured'))} · signing material stored locally` : `<strong>${escapeHtml(signingAlgorithm)}</strong><br>${escapeHtml(t('notConfigured'))}`;
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
  try {
    state.settings = await api('/api/settings', writeOptions('POST', {cache_hours:Number($('#cache-hours').value), providers}));
    $('#nvd-api-key').value = '';
    $('#threatfox-auth-key').value = '';
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
    setInline('#signing-message', result.public_key_sha256 ? `${result.algorithm} ready · fingerprint ${result.public_key_sha256}` : `${result.algorithm} ready · local secret stored with 0600 permissions.`);
  } catch (error) { setInline('#signing-message', error.message, true); }
}

async function importManagedFile(kind, input) {
  const file = input.files?.[0];
  if (!file) return;
  setInline('#rules-message', `Validating ${file.name}…`);
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
  $('#ioc-pack-list').innerHTML = packs.length ? packs.map((item) => row('ioc-packs', item, item.valid ? `${item.name} · v${item.version} · ${item.indicator_count} indicators · ${formatBytes(item.size)}` : item.error)).join('') : '<p class="muted">No imported IOC packs.</p>';
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
  $('#cache-list').innerHTML = entries.length ? entries.map((item) => `<div class="managed-row"><span><strong>${escapeHtml(item.provider || item.name)}</strong><small>${escapeHtml(item.fetched_at)} · ${formatBytes(item.size)} · SHA-256 ${escapeHtml(String(item.sha256).slice(0,16))}…</small></span></div>`).join('') : '<p class="muted">No cached intelligence yet.</p>';
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
  $('#threatfox-result').innerHTML = '<p class="muted">Querying ThreatFox…</p>';
  try {
    const result = await api('/api/threatfox/lookup', writeOptions('POST', {indicator}));
    const rows = result.data || [];
    $('#threatfox-result').innerHTML = rows.length ? rows.slice(0,50).map((item) => `<div class="managed-row"><span><strong>${escapeHtml(item.ioc || item.id || indicator)}</strong><small>${escapeHtml(item.threat_type || item.malware_printable || result.query_status)} · confidence ${escapeHtml(item.confidence_level ?? '—')}</small></span></div>`).join('') : `<p class="muted">${escapeHtml(result.query_status)} · no matching IOC returned.</p>`;
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
  $('#language-select').addEventListener('change', async () => {
    applyLanguage($('#language-select').value);
    try { state.settings = await api('/api/settings', writeOptions('POST', {language:state.language})); } catch (error) { setMessage(error.message, true); }
  });
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
  applyLanguage('ro');
  const health = await checkHealth();
  if (!health) setMessage('Dashboard server unavailable. Retrying automatically…', true);
  state.healthPoll = setInterval(checkHealth, 4000);
});
