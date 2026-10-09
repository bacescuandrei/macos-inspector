const { test, expect } = require('@playwright/test');
const { execFileSync } = require('node:child_process');
const { default: AxeBuilder } = require('@axe-core/playwright');
const { readFileSync } = require('node:fs');

function pdfInspectionFixture() {
  return {report: {
    tool_version: 'fixture', analyzed_at: '2026-10-09T10:00:00Z',
    file: {name: '<img src=x onerror=window.pdfInjected=true>' + 'a'.repeat(200), bytes: 42, sha256: 'a'.repeat(64)},
    structure: {header: '%PDF-1.7', header_offset: 0, object_count: 3, compressed_object_count: 1,
      final_eof_marker: true, encrypted_or_indicated: false, xref_validation: 'Not full PDF conformance validation.'},
    assessment: {label: 'Review features', explanation: 'Review declared actions, not a malware verdict.', next_step: 'Keep the original closed and validate its source.'},
    boundary: 'No code was executed, no pages rendered, and no destinations contacted.',
    answers: [{question: 'Does it contain JavaScript?', answer: 'JavaScript is present or indicated.', note: 'Not proof of malware. Analysis is limited.'}, {question: 'Does anything run when it opens?', answer: 'Active document or page-open features are declared.', note: 'Reader execution was not tested.'}],
    privacy: 'Original not retained. Reports may contain sensitive metadata.',
    actions: [{type: 'JavaScript', trigger: 'Document open', target: 'Not recorded', context: 'Object 1 /OpenAction'}],
    javascript: [{context: 'Object 2 /JS', bytes: 40, sha256: 'b'.repeat(64), preview: '<script>window.pdfInjected=true</script>' + 'b'.repeat(300), preview_truncated: true, indicators: ['Possible URL opening or form submission']}],
    destinations: [{value: 'https://example.invalid/' + 'c'.repeat(300), kind: 'String in JavaScript; execution not established', context: 'Object 2'}],
    attachments: [{filename: '<svg onload=window.pdfInjected=true>', context: 'Object 3', note: 'Not extracted or executed.'}],
    name_counts: {JavaScript: 1, JS: 1, OpenAction: 1}, metadata: {Author: '<script>window.pdfInjected=true</script>'},
    limitations: ['Unsupported stream filter; absence claims unavailable.'],
  }, reports: {html: '/reports/macos-inspector-pdf-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.html', json: '/reports/macos-inspector-pdf-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.json'}};
}

async function openPdfPage(page) {
  await page.getByRole('link', {name: 'PDF Inspector', exact: true}).click();
  await page.waitForFunction(() => typeof state !== 'undefined' && state.healthPoll !== null);
  await expect(page.locator('#connection')).toHaveText('Offline | retrying');
  await page.evaluate(() => clearInterval(state.healthPoll));
}

test('PDF sharing ignores delayed previews after a file or privacy option changes', async ({page}) => {
  await openPdfPage(page);
  await page.route('**/api/pdf-inspector', route => route.fulfill({status: 201, json: pdfInspectionFixture()}));
  await page.route('**/api/pdf-inspections', route => route.fulfill({json: {inspections: []}}));
  let release;
  let started = false;
  let pending = new Promise(resolve => { release = resolve; });
  const summary = {report_kind: 'pdf-sharing-summary', redaction: {warning: 'Reduced summary, not anonymization.'}, assessment: {label: 'Review features'}, observations: {javascript_records: 1}};
  await page.route('**/api/pdf-sharing-copy', async route => {
    started = true;
    await pending;
    await route.fulfill({json: {summary, html: '<!doctype html><html lang="en"><body>Reduced summary</body></html>'}});
  });
  await page.evaluate(() => { state.online = true; updatePdfAvailability(); });
  const file = {name: 'sample.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-1.7\nsynthetic fixture')};
  await page.locator('#pdf-file').setInputFiles(file);
  await page.locator('#inspect-pdf').click();
  await expect(page.locator('#prepare-pdf-sharing')).toBeEnabled();
  await page.locator('#prepare-pdf-sharing').click();
  await expect.poll(() => started).toBe(true);
  await expect(page.locator('#prepare-pdf-sharing')).toBeDisabled();
  await page.locator('#pdf-file').setInputFiles({...file, name: 'other.pdf'});
  const firstResponse = page.waitForResponse('**/api/pdf-sharing-copy');
  release();
  await firstResponse;
  await expect(page.locator('#pdf-result')).toBeHidden();
  expect(await page.evaluate(() => pdfState.sharingCopy)).toBeNull();
  started = false;
  pending = new Promise(resolve => { release = resolve; });
  await page.locator('#inspect-pdf').click();
  await expect(page.locator('#prepare-pdf-sharing')).toBeEnabled();
  await page.locator('#prepare-pdf-sharing').click();
  await expect.poll(() => started).toBe(true);
  await page.locator('#pdf-sharing-hash').check();
  await expect(page.locator('#prepare-pdf-sharing')).toBeEnabled();
  const secondResponse = page.waitForResponse('**/api/pdf-sharing-copy');
  release();
  await secondResponse;
  await expect(page.locator('#pdf-sharing-preview')).toBeHidden();
  expect(await page.evaluate(() => pdfState.sharingCopy)).toBeNull();
  await expect(page.locator('#pdf-sharing-message')).toContainText('Prepare a new preview');
});

test('extension permission explanations are escaped, responsive and distinguish optional or missing access evidence', async ({page}, info) => {
  const profile = {browser: 'Chrome', profile: 'Default', collection_notes: ['One declaration was unavailable; not a clean result.'], extensions: [{
    id: 'example-extension', name: '<img src=x onerror=window.extensionInjected=true>' + 'x'.repeat(120), version: '1.10', active: null,
    permission_analysis: {schema_version: 1, complete: true, source: 'Manifest; highest observed directory, not confirmed active version',
      required: {api_permissions: ['activeTab'], host_patterns: ['https://example.invalid/' + 'p'.repeat(300)], content_script_matches: [], content_script_exclusions: []},
      optional: {available: true, api_permissions: ['cookies'], host_patterns: ['<all_urls>']},
      features: [{key: 'activeTab', label: 'Temporary access after user interaction', scope: 'Declared requirement', explanation: 'Not persistent access to every site.'},
        {key: 'cookies', label: 'Cookie access', scope: 'Optional declaration', explanation: 'Optional does not mean granted.'}],
      limitations: [], effective_access: 'Not established; verify actual access in the browser.', boundary: 'Requirements are not grants or a malware verdict.'},
  }, {id: 'legacy', version: '1.0', active: false}]};
  await page.evaluate(profile => renderBrowserExtensionReview([{evidence: [{kind: 'browser_profile', value: profile}]}]), profile);
  const panel = page.locator('#browser-extension-review');
  await expect(panel).toBeVisible();
  await expect(panel).toContainText('Optional declaration');
  await expect(panel).toContainText('Enabled state not verified');
  await expect(panel).toContainText('Disabled in recorded addon metadata');
  await expect(panel).toContainText('Permission analysis limited');
  await expect(panel).toContainText('Run a new browser audit');
  expect(await page.evaluate(() => window.extensionInjected)).toBeUndefined();
  expect(await panel.locator('img,script,iframe,a[href^="https:"]').count()).toBe(0);
  await panel.locator('.extension-review-row').first().getByText('Declared permission details and limits', {exact: true}).click();
  await expect(panel).toContainText('<all_urls>');
  for (const mode of ['simple', 'analyst']) {
    await page.evaluate(mode => setViewMode(mode), mode);
    await expect(panel).toBeVisible();
    for (const width of [320,375,768,1280]) {
      await page.setViewportSize({width,height:850});
      expect(await panel.evaluate(element => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(1);
    }
  }
  expect((await new AxeBuilder({page}).include('#browser-extension-review').withTags(['wcag2a','wcag2aa','wcag21aa']).analyze()).violations).toEqual([]);
  await page.setViewportSize({width:375,height:900});
  await panel.screenshot({path: info.outputPath('browser-extension-permissions-mobile.png')});
  await page.evaluate(() => renderFindings([]));
  await expect(panel).toBeHidden();
  await page.evaluate(() => renderBrowserExtensionReview([{evidence: [{kind: 'browser_profile', value: {browser: 'Safari', profile: 'Default', extensions: [], collection_notes: ['Safari permissions not assessed.']}}]}]));
  await expect(panel).toContainText('not proof that no extension exists');
  await expect(panel).toContainText('Safari permissions not assessed.');
});

test('PDF inspection is explicit, bounded, escaped and responsive on its own page', async ({ page }) => {
  await openPdfPage(page);
  let calls = 0;
  let upload;
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  await page.route('**/api/pdf-inspector', async route => {
    calls += 1;
    upload = route.request();
    await pending;
    await route.fulfill({status: 201, json: pdfInspectionFixture()});
  });
  await page.route('**/api/pdf-inspections', route => route.fulfill({json: {inspections: []}}));
  await page.evaluate(() => { state.online = true; updatePdfAvailability(); });
  await page.evaluate(() => {
    const originalFetch = window.fetch;
    window.fetch = async (url, options) => {
      if (url === '/api/pdf-inspector' && options?.body instanceof File) window.pdfUploadText = await options.body.text();
      return originalFetch(url, options);
    };
  });
  await page.locator('#pdf-file').setInputFiles({name: 'sample.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-1.7\nsynthetic fixture')});
  expect(calls).toBe(0);
  await page.getByRole('button', {name: 'Inspect PDF', exact: true}).click();
  await expect(page.locator('#pdf-file')).toBeDisabled();
  await expect(page.locator('#inspect-pdf')).toBeDisabled();
  release();
  await expect(page.locator('#pdf-result')).toContainText('Review features');
  expect(upload.headers()['content-type']).toBe('application/pdf');
  expect(await page.evaluate(() => window.pdfUploadText)).toContain('%PDF-1.7');
  expect(calls).toBe(1);
  await expect(page.locator('#pdf-result')).toContainText('Document open');
  await expect(page.locator('#pdf-result')).toContainText('Unsupported stream filter');
  expect(await page.evaluate(() => window.pdfInjected)).toBeUndefined();
  expect(await page.locator('#pdf-result img, #pdf-result svg, #pdf-result script, #pdf-result iframe').count()).toBe(0);
  expect(await page.locator('#pdf-result a[href^="https:"]').count()).toBe(0);
  await page.locator('#pdf-result').getByText('Destinations, not observed requests', {exact: true}).click();
  await page.locator('#pdf-result').getByText('Attachments', {exact: true}).click();
  await page.locator('#pdf-result').getByText('Parsed structural names and declared metadata', {exact: true}).click();
  await page.locator('#pdf-result').getByText(/JavaScript \| Object 2/).click();
  await expect(page.locator('#pdf-inspector')).toBeVisible();
  for (const width of [320, 375, 768, 1280]) {
      await page.setViewportSize({width, height: 850});
      expect(await page.locator('#pdf-inspector').evaluate(element => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(1);
  }
  const results = await new AxeBuilder({page}).include('#pdf-inspector').withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(results.violations.map(row => row.id)).toEqual([]);
});

test('PDF invalid sizes and failed analysis do not leave a previous verdict visible', async ({ page }) => {
  await openPdfPage(page);
  await page.evaluate(() => { state.online = true; updatePdfAvailability(); });
  await page.locator('#pdf-file').setInputFiles({name: 'empty.pdf', mimeType: 'application/pdf', buffer: Buffer.alloc(0)});
  await expect(page.locator('#inspect-pdf')).toBeDisabled();
  await expect(page.locator('#pdf-message')).toContainText('nonempty');
  await page.locator('#pdf-file').setInputFiles({name: 'large.pdf', mimeType: 'application/pdf', buffer: Buffer.alloc(25 * 1024 * 1024 + 1)});
  await expect(page.locator('#inspect-pdf')).toBeDisabled();
  await page.evaluate(payload => renderPdfInspection(payload), pdfInspectionFixture());
  await page.route('**/api/pdf-inspector', route => route.fulfill({status: 400, json: {error: 'Analysis resource limit reached. No complete result is available.'}}));
  await page.locator('#pdf-file').setInputFiles({name: 'broken.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-broken')});
  await expect(page.locator('#pdf-result')).toBeHidden();
  await page.locator('#inspect-pdf').click();
  await expect(page.locator('#pdf-message')).toContainText('No complete result');
  await expect(page.locator('#pdf-result')).toBeHidden();
  await expect(page.locator('#inspect-pdf')).toBeEnabled();
});

test('PDF page is isolated, deep-linkable and does not load Mac audit code or data', async ({page}) => {
  const calls = [];
  page.on('request', request => { if (new URL(request.url()).pathname.startsWith('/api/')) calls.push(new URL(request.url()).pathname); });
  await page.route('**/api/health', route => route.fulfill({json: {version: 'fixture', session_required: false}}));
  await page.route('**/api/pdf-inspections', route => route.fulfill({json: {inspections: []}}));
  await page.goto('/pdf-inspector.html');
  await expect(page.locator('#connection')).toContainText('Connected');
  await expect(page.locator('#pdf-history-list')).toContainText('No PDF inspections');
  await expect(page.locator('#collectors, #history, #response-history-list, #view-simple, #show-guide')).toHaveCount(0);
  await expect(page.locator('script[src="app.js"]')).toHaveCount(0);
  expect(await page.evaluate(() => typeof startScan)).toBe('undefined');
  await expect(page.getByRole('heading', {name: 'Previous scans', exact: true})).toHaveCount(0);
  await expect(page.getByRole('heading', {name: 'Audit sections', exact: true})).toHaveCount(0);
  await expect(page.locator('[data-workspace-link="pdf"]')).toHaveAttribute('aria-current', 'page');
  expect(calls.filter(path => !['/api/health', '/api/pdf-inspections'].includes(path))).toEqual([]);
  await page.reload();
  await expect(page.locator('#pdf-inspector')).toBeVisible();
  expect(calls.filter(path => !['/api/health', '/api/pdf-inspections'].includes(path))).toEqual([]);
  for (const width of [320,375,768,1280]) {
    await page.setViewportSize({width,height:850});
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1);
  }
  const result = await new AxeBuilder({page}).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(result.violations.map(row => row.id)).toEqual([]);
  let launchToken;
  await page.route('**/api/session', route => { launchToken = route.request().postDataJSON().token; return route.fulfill({json: {api_token: 'synthetic-page-session'}}); });
  calls.length = 0;
  await page.goto('/?workspace=pdf#launch=synthetic-page-launch');
  await expect(page).toHaveURL(/\/pdf-inspector\.html$/);
  await expect.poll(() => launchToken).toBe('synthetic-page-launch');
  await expect(page.locator('#pdf-history-list')).toContainText('No PDF inspections');
  expect(calls.filter(path => !['/api/session', '/api/health', '/api/pdf-inspections'].includes(path))).toEqual([]);
});

test('PDF page asks before leaving a running inspection and allows navigation when finished', async ({page}) => {
  await openPdfPage(page);
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  await page.route('**/api/pdf-inspector', async route => { await pending; await route.fulfill({status: 201, json: pdfInspectionFixture()}); });
  await page.route('**/api/pdf-inspections', route => route.fulfill({json: {inspections: []}}));
  await page.evaluate(() => { state.online = true; updatePdfAvailability(); });
  await page.locator('#pdf-file').setInputFiles({name: 'waiting.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-1.7')});
  await page.locator('#inspect-pdf').click();
  await expect(page.locator('#inspect-pdf')).toBeDisabled();
  let dialogType;
  page.once('dialog', async dialog => { dialogType = dialog.type(); await dialog.dismiss(); });
  await page.getByRole('link', {name: 'Back to Mac audit', exact: true}).click({noWaitAfter: true});
  await expect.poll(() => dialogType).toBe('beforeunload');
  expect(new URL(page.url()).pathname).toBe('/pdf-inspector.html');
  release();
  await expect(page.locator('#pdf-result')).toContainText('Review features');
  await expect(page.locator('#inspect-pdf')).toBeEnabled();
  await page.getByRole('link', {name: 'Back to Mac audit', exact: true}).click();
  await expect(page).toHaveURL(/\/index\.html$/);
});

test('separate pages have reciprocal navigation, browser history and reduced motion', async ({page}) => {
  await openPdfPage(page);
  expect(new URL(page.url()).pathname).toBe('/pdf-inspector.html');
  await page.getByRole('link', {name: 'Back to Mac audit', exact: true}).click();
  await expect(page.locator('#pdf-file, #pdf-result, script[src="pdf-inspector.js"]')).toHaveCount(0);
  await expect(page.getByRole('heading', {name: 'Audit sections', exact: true})).toBeVisible();
  expect(new URL(page.url()).pathname).toBe('/index.html');
  await page.goBack();
  await expect(page.locator('#pdf-inspector')).toBeVisible();
  expect(new URL(page.url()).pathname).toBe('/pdf-inspector.html');
  await page.goForward();
  await expect(page.getByRole('heading', {name: 'Audit sections', exact: true})).toBeVisible();
  await openPdfPage(page);
  await page.locator('#pdf-file').setInputFiles({name: 'example.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-1.7')});
  await page.evaluate(payload => renderPdfInspection(payload), pdfInspectionFixture());
  await page.emulateMedia({reducedMotion: 'reduce'});
  expect(await page.locator('#pdf-inspector').evaluate(element => parseFloat(getComputedStyle(element).animationDuration))).toBeLessThanOrEqual(.001);
  await page.locator('#clear-pdf').click();
  await expect(page.locator('#pdf-result')).toBeHidden();
  await expect(page.locator('#pdf-result')).toBeEmpty();
  await expect(page.locator('#pdf-empty')).toBeVisible();
  await expect(page.locator('#pdf-file')).toBeFocused();
  await expect(page.locator('#inspect-pdf')).toBeDisabled();
  await expect(page.locator('#pdf-step-select')).toHaveAttribute('aria-current', 'step');
});

test('launch credential is removed from the address and API credentials stay same-origin', async ({ page }) => {
  let token;
  let authorization;
  let externalCalls = 0;
  await page.route('**/api/session', route => { token = route.request().postDataJSON().token; return route.fulfill({json: {authorized: true, api_token: 'synthetic-session-secret'}}); });
  await page.route('**/api/config', route => { authorization = route.request().headers()['authorization']; return route.fulfill({json: {fixture: true}}); });
  await page.route('https://example.invalid/**', route => { externalCalls += 1; return route.abort(); });
  await page.goto('/#launch=synthetic-launch-secret');
  await expect.poll(() => token).toBe('synthetic-launch-secret');
  await page.waitForFunction(() => window.sessionStorage.getItem('macos-inspector-session') === 'synthetic-session-secret');
  expect(new URL(page.url()).hash).toBe('');
  await page.evaluate(() => api('/api/config'));
  expect(authorization).toBe('Bearer synthetic-session-secret');
  await page.evaluate(() => api('https://example.invalid/').catch(() => null));
  expect(externalCalls).toBe(0);
  expect(await page.locator('body').textContent()).not.toContain('synthetic-session-secret');
});

test('offline setup help is responsive and accessible without a running dashboard', async ({ page }) => {
  const body = readFileSync('docs/START_HERE.html', 'utf8');
  await page.route('**/setup-help.html', route => route.fulfill({contentType: 'text/html', body}));
  await page.goto('/setup-help.html');
  await expect(page.getByRole('heading', {name: 'Start macOS Inspector', exact: true})).toBeVisible();
  await expect(page.locator('body')).toContainText('does not download or install anything');
  for (const width of [320, 375, 768, 1280]) {
    await page.setViewportSize({width, height: 850});
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1);
  }
  const results = await new AxeBuilder({page}).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(results.violations.map(row => row.id)).toEqual([]);
});

test('synthetic validation is available from HTML with a downloadable report', async ({ page }) => {
  let calls = 0;
  await page.route('**/api/detection-validation', route => { calls += 1; return route.fulfill({json: {
    tool_version: 'fixture', scenario_count: 18, passed: 18, failed: 0, false_alerts_in_expected_pass_cases: 0,
    missed_review_in_declared_review_cases: 0, limitation: 'Synthetic fixtures only, not real-world accuracy.',
    results: [{id: 'synthetic-signature', expected: 'Pass', observed: 'Pass', passed: true}],
  }}); });
  await page.getByText('Detection regression validation', {exact: true}).click();
  await page.getByRole('button', {name: 'Run detection validation'}).click();
  await expect(page.locator('#detection-validation-result')).toContainText('18 of 18 scenarios passed');
  await expect(page.locator('#detection-validation-result')).toContainText('not real-world accuracy');
  const downloaded = page.waitForEvent('download');
  await page.getByRole('button', {name: 'Download validation JSON'}).click();
  const download = await downloaded;
  expect(download.suggestedFilename()).toBe('macos-inspector-fixture-detection-validation.json');
  expect(calls).toBe(1);
});

test('response history is escaped, responsive, and available in both views', async ({ page }) => {
  await page.evaluate(() => renderResponseHistory({actions: [{
    action_id: 'synthetic-action', scan_id: 'synthetic-source', pid: 4242, signal: 'SIGTERM', timestamp: '2026-01-01T00:00:00Z',
    executable: '<img src=x onerror=window.responseInjected=true>' + 'a'.repeat(180),
    recheck: {scan_id: 'later', timestamp: '2026-01-01T00:02:00Z', outcome: 'not_observed', explanation: 'Absence is not confirmed remediation.'},
  }], note: 'Stored locally. Sending a signal does not confirm exit.'}));
  const panel = page.locator('#response-history-list');
  await expect(panel).toContainText('Original PID not observed');
  await expect(panel.getByRole('button', {name: 'View preserved source'})).toBeVisible();
  await expect(panel.getByRole('button', {name: 'Recheck process outcome'})).toBeDisabled();
  for (const mode of ['simple', 'analyst']) {
    await page.evaluate((view) => setViewMode(view), mode);
    await expect(panel).toBeVisible();
    for (const width of [320, 375, 768, 1280]) {
      await page.setViewportSize({width, height: 850});
      expect(await panel.evaluate(element => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(1);
    }
  }
  expect(await page.evaluate(() => window.responseInjected)).toBeUndefined();
});

test('response follow-up starts a linked read-only scan without sending a signal', async ({ page }) => {
  let request;
  let signals = 0;
  await page.route('**/api/scans', async (route) => {
    request = route.request().postDataJSON();
    await route.fulfill({status: 202, json: {job_id: 'synthetic-followup'}});
  });
  await page.route('**/api/scans/synthetic-followup', route => route.fulfill({json: {job_id: 'synthetic-followup', state: 'running', collectors: ['live-triage'], total_collectors: 1}}));
  await page.route('**/api/processes/terminate', route => { signals += 1; return route.fulfill({status: 403, json: {error: 'No process action authorized'}}); });
  await page.evaluate(() => {
    state.online = true;
    state.config = {collectors: [{id: 'live-triage', title: 'Live Triage', external_network: false}], formats: ['html', 'json']};
    renderFormats();
    $('#minimum').value = 'High';
    renderResponseHistory({actions: [{action_id: 'synthetic-action', scan_id: 'source', pid: 4242, signal: 'SIGTERM', timestamp: '2026-01-01T00:00:00Z', executable: '/synthetic/tool'}]});
  });
  await page.getByRole('button', {name: 'Recheck process outcome'}).click();
  await expect.poll(() => request?.response_action_id).toBe('synthetic-action');
  expect(request.collectors).toEqual(['live-triage']);
  expect(request.minimum).toBe('Informational');
  expect(signals).toBe(0);
});

test('response follow-up explains another PID without claiming restart or remediation', async ({ page }) => {
  await page.evaluate(() => renderResponseHistory({actions: [{
    action_id: 'synthetic-action', scan_id: 'source', pid: 4242, signal: 'SIGTERM',
    timestamp: '2026-01-01T00:00:00Z', executable: '/synthetic/tool',
    recheck: {scan_id: 'later', timestamp: '2026-01-01T00:02:00Z', outcome: 'executable_observed',
      explanation: 'Original PID absent; path and owner observed under PID 5000. Existing instance or restart, not confirmed remediation.'},
  }]}));
  const panel = page.locator('#response-history-list');
  await expect(panel).toContainText('Same executable observed under another PID');
  await expect(panel).toContainText('not confirmed remediation');
  await expect(panel.getByRole('button', {name: 'View later snapshot'})).toBeVisible();
  for (const mode of ['simple', 'analyst']) {
    await page.evaluate(view => setViewMode(view), mode);
    await page.setViewportSize({width: 320, height: 850});
    await expect(panel).toBeVisible();
    expect(await panel.evaluate(element => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(1);
  }
});

test('dashboard controls and response history pass targeted WCAG accessibility checks', async ({ page }) => {
  await page.evaluate(() => renderResponseHistory({actions: [{action_id: 'synthetic-action', scan_id: 'source', pid: 4242, signal: 'SIGTERM', timestamp: '2026-01-01T00:00:00Z', executable: '/synthetic/tool'}]}));
  for (const mode of ['simple', 'analyst']) {
    await page.evaluate((view) => setViewMode(view), mode);
    const results = await new AxeBuilder({page}).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
    expect(results.violations.map(item => ({id: item.id, nodes: item.nodes.map(node => node.target)}))).toEqual([]);
  }
  const button = page.getByRole('button', {name: 'View preserved source'});
  await button.focus();
  await expect(button).toBeFocused();
  expect(await button.evaluate(element => getComputedStyle(element).outlineStyle)).not.toBe('none');
});

test('manual comparison shows report-only records without implying resolution', async ({ page }) => {
  await page.evaluate(() => {
    setViewMode('analyst');
    renderComparison({
      score_delta: null, counts: {new: 1, resolved: 1, changed: 1},
      scope: {changed: false},
      comparison_context: {
        baseline_completed_at: '2026-01-01T00:00:00Z', current_completed_at: '2026-01-02T00:00:00Z',
        limitations: ['Comparison report uses a severity filter.', '<img src=x onerror=window.manualInjected=true>'],
        index_note: 'N/A: selected reports have incomplete comparison context.',
      },
      new: [{finding_id: 'NEW', title: 'Example' + 'a'.repeat(160), severity: 'High', status: 'Review'}],
      resolved: [{finding_id: 'OLDER', title: 'Earlier observation', severity: 'High', status: 'Fail'}],
      changed: [{finding_id: 'CONTROL-SIP', title: 'System Integrity Protection', changes: {status: {before: 'Pass', after: 'Unknown'}}}],
    });
  });
  const panel = page.locator('#comparison-panel');
  await expect(panel).toBeVisible();
  await expect(panel).toContainText('Only in baseline');
  await expect(panel).toContainText('Baseline only');
  await expect(panel).toContainText('Comparison only');
  await expect(panel).toContainText('not confirmed additions, removals, or resolved incidents');
  await expect(page.locator('#comparison-summary')).not.toContainText('Resolved');
  await panel.getByText('Why the index comparison is unavailable', {exact: true}).click();
  for (const width of [320, 375, 768, 1280]) {
    await page.setViewportSize({width, height: 850});
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1);
    expect(await panel.evaluate(element => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(1);
  }
  expect(await page.evaluate(() => window.manualInjected)).toBeUndefined();
});

test('exported manual comparison is responsive and retains context without scripts', async ({ page }) => {
  const comparison = {
    baseline_scan_id: 'base', current_scan_id: 'current', baseline_score: 80, current_score: 100, score_delta: null,
    counts: {new: 1, resolved: 1, changed: 0}, scope: {changed: false}, category_deltas: {['Security' + 'a'.repeat(120)]: null},
    comparison_context: {limitations: ['Filtered report: ' + 'b'.repeat(200), '<script>window.exportInjected=true</script>'], baseline_completed_at: '2026-01-01T00:00:00Z'},
    new: [{finding_id: 'CURRENT-ONLY', title: 'Application' + 'c'.repeat(180), severity: 'High', status: 'Review'}],
    resolved: [{finding_id: 'BASELINE-ONLY', title: 'Earlier observation', severity: 'High', status: 'Fail'}], changed: [],
  };
  const body = execFileSync('python3', ['-c', `
import json, sys, tempfile
from pathlib import Path
from macos_inspector.reporters.comparison_reporter import write_comparison_reports
with tempfile.TemporaryDirectory() as directory:
    report = write_comparison_reports(json.load(sys.stdin), Path(directory))['comparison_html']
    print(report.read_text(encoding='utf-8'))
`], {input: JSON.stringify(comparison), encoding: 'utf8', env: {...process.env, PYTHONPATH: 'src'}});
  await page.route('**/exported-comparison.html', (route) => route.fulfill({contentType: 'text/html', body}));
  await page.goto('/exported-comparison.html');
  await expect(page.locator('body')).toContainText('Baseline only');
  await expect(page.locator('body')).toContainText('Index comparison unavailable');
  await expect(page.locator('body')).toContainText('not confirmed additions, removals, or resolved incidents');
  await expect(page.locator('script')).toHaveCount(0);
  for (const width of [320, 375, 768, 1280]) {
    await page.setViewportSize({width, height: 850});
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1);
  }
  expect(await page.evaluate(() => window.exportInjected)).toBeUndefined();
  await page.setViewportSize({width: 375, height: 850});
  await page.screenshot({path: 'test-results/manual-comparison-export-375.png', fullPage: true});
});

test('snapshot comparison is visible in both views and wraps recorded values', async ({ page }) => {
  await page.evaluate(() => renderDecisionSupport({
    changes: {
      available: true, baseline_scan_id: '<img src=x onerror=window.comparisonInjected=true>' + 'a'.repeat(100),
      baseline_completed_at: '2026-01-04T13:59:00+02:00',
      message: 'Compared with the most recent earlier scan with matching scope and host.',
      counts: { new_applications: 1, resolved_findings: 2 },
      comparison_context: { message: 'Collector coverage can differ between tool versions.' },
      highlights: Array.from({length: 5}, (_, index) => ({
        label: 'Signing identity changed', title: 'Example.app' + 'b'.repeat(90),
        detail: '<script>window.comparisonInjected=true</script>',
        next_action: 'Confirm the publisher before making changes.', priority: index === 0 ? 'high' : 'review',
      })),
    },
    stories: [{title: 'Related evidence', narrative: 'Activity is not proof of malware.', confidence: 'medium'}],
  }));
  const panel = page.locator('#decision-support');
  await expect(panel).toBeVisible();
  await expect(panel).toContainText('Earlier scan completed');
  await expect(panel.locator('time')).toHaveAttribute('datetime', '2026-01-04T13:59:00+02:00');
  await expect(panel).toContainText('not confirmed security incidents or fixes');
  await expect(panel).not.toContainText('Resolved findings');
  await expect(panel.getByText('Related evidence', {exact: true})).toBeHidden();
  await panel.getByText('All comparison counts', {exact: true}).click();
  await expect(panel).toContainText('Findings no longer recorded');
  await panel.getByText('More recorded changes (2)', {exact: true}).click();
  for (const mode of ['simple', 'analyst']) {
    await page.evaluate((mode) => setViewMode(mode), mode);
    await expect(panel).toBeVisible();
    for (const width of [320, 375, 768, 1280]) {
      await page.setViewportSize({width, height: 850});
      expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1);
    }
  }
  await expect(panel.getByText('Related evidence', {exact: true})).toBeVisible();
  expect(await page.evaluate(() => window.comparisonInjected)).toBeUndefined();
  await page.evaluate(() => setViewMode('simple'));
  await page.setViewportSize({width: 320, height: 850});
  await panel.screenshot({path: 'test-results/comparison-simple-320.png'});
});

test('view earlier scan opens the actual automatic baseline without starting a scan', async ({ page }) => {
  const writes = [];
  page.on('request', (request) => { if (request.method() === 'POST') writes.push(request.url()); });
  await page.route('**/api/scans', (route) => route.fulfill({json: {scans: [
    {scan_id: 'unrelated', state: 'completed', reports: {json: '/reports/unrelated.json'}},
    {scan_id: 'automatic-baseline', state: 'completed', reports: {json: '/reports/automatic-baseline.json'}},
  ]}}));
  await page.route('**/reports/automatic-baseline.json', (route) => route.fulfill({json: {
    metadata: {scan_id: 'automatic-baseline', collectors: ['security'], completed_at: '2026-01-01T00:00:00Z'},
    summary: {finding_count: 0, total_finding_count: 0}, findings: [], timeline: [],
  }}));
  await page.route('**/api/decision-support/automatic-baseline', (route) => route.fulfill({json: {
    scan_id: 'automatic-baseline',
    changes: {available: false, message: 'No usable earlier scan is available.'},
  }}));
  await page.evaluate(() => {
    state.currentScanId = 'newer';
    state.baselineJob = {scan_id: 'unrelated'};
    renderDecisionSupport({changes: {available: true, baseline_scan_id: 'automatic-baseline', counts: {}, highlights: []}});
  });
  await page.getByRole('button', {name: 'View earlier scan', exact: true}).click();
  await expect(page.locator('#case-banner')).toContainText('automatic-baseline');
  await expect(page.locator('#decision-support')).toContainText('No usable earlier scan is available.');
  expect(writes).toEqual([]);
  expect(await page.evaluate(() => state.baselineJob.scan_id)).toBe('unrelated');
});

test('comparison distinguishes missing baseline and zero highlights without claiming resolution', async ({ page }) => {
  await page.evaluate(() => renderDecisionSupport({changes: {available: false, message: 'No usable earlier scan is available.'}}));
  await expect(page.locator('#decision-support')).toBeVisible();
  await expect(page.getByRole('button', {name: 'View earlier scan', exact: true})).toHaveCount(0);
  await page.route('**/api/scans', (route) => route.fulfill({json: {scans: []}}));
  await page.evaluate(() => renderDecisionSupport({changes: {
    available: true, baseline_scan_id: 'missing', baseline_completed_at: '2026-02-31T00:00:00Z',
    counts: {}, highlights: [],
  }}));
  await expect(page.locator('#decision-support')).toContainText('Not recorded with a usable timezone');
  await expect(page.locator('#decision-support')).toContainText('not proof that the Mac is safe');
  await page.getByRole('button', {name: 'View earlier scan', exact: true}).click();
  await expect(page.locator('#decision-support [data-scan-message]')).toContainText('not available in dashboard history');
  await expect(page.getByRole('button', {name: 'View earlier scan', exact: true})).toBeEnabled();
});

test('incomplete comparison shows unavailable counts instead of zero or resolution', async ({ page }) => {
  await page.evaluate(() => {
    renderDecisionSupport({changes: {
      available: true, baseline_scan_id: 'older', baseline_completed_at: '2026-01-01T00:00:00Z',
      counts: {removed_applications: null, new_applications: null, closed_network_listeners: null, resolved_findings: null, changed_applications: 1, new_startup_items: '0'},
      comparison_context: {limited: true, limitations: ['Later scan: Application Trust collection is incomplete.', '<script>window.limitInjected=true</script>']},
      highlights: [{kind: 'changed-application', label: 'Signing identity changed', title: 'Example', detail: 'Recorded publishers differ.', finding_id: 'APP-TRUST-EXAMPLE', priority: 'high'}],
    }});
    state.currentReportMetadata = {scan_id: 'current', collectors: ['application-trust'], minimum_severity: 'High'};
    renderReportContext();
  });
  const panel = page.locator('#decision-support');
  await expect(panel).toBeVisible();
  await expect(panel).toContainText('Some changes are not comparable');
  await expect(panel).toContainText('Signing identity changed');
  await expect(page.locator('#report-context')).toContainText('High and above');
  await panel.getByText('All comparison counts', {exact: true}).click();
  const missingApps = panel.locator('.change-metrics span').filter({hasText: 'Apps no longer present'});
  await expect(missingApps).toContainText('Not comparable');
  await expect(missingApps).not.toContainText('0');
  await panel.getByText('Why these counts are unavailable', {exact: true}).click();
  for (const width of [320, 375, 768, 1280]) {
    await page.setViewportSize({width, height: 850});
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1);
  }
  expect(await page.evaluate(() => window.limitInjected)).toBeUndefined();
  await page.setViewportSize({width: 320, height: 850});
  await panel.screenshot({path: 'test-results/comparison-limited-320.png'});
  await page.evaluate(() => renderDecisionSupport({changes: {available: true, counts: {}, comparison_context: {limitations: ['Earlier scan incomplete.']}, highlights: []}}));
  await expect(panel).toContainText('Some changes could not be assessed');
  await expect(panel).not.toContainText('No highlighted application');
});

test.beforeEach(async ({ page }) => {
  await page.route('**/api/health', async (route) => {
    await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"Test server is read-only"}' });
  });
  await page.goto('/');
  // Finish the real initialization before tests replace connection state with synthetic fixtures.
  await page.waitForFunction(() => state.healthPoll !== null);
  await expect(page.locator('#connection')).toHaveText('Offline | retrying');
  await page.evaluate(() => clearInterval(state.healthPoll));
});

test('incomplete scans stay visible in simple and analyst views', async ({ page }) => {
  const experience = {
    assessment: {
      id: 'scan-incomplete',
      label: 'Scan incomplete',
      headline: 'Some checks did not finish.',
      explanation: 'Do not treat missing evidence as a pass.',
    },
    next_actions: [{
      title: 'Complete the missing checks',
      label: 'Scan incomplete',
      verdict: 'unable-to-verify',
      observed: 'Selected sections with incomplete evidence: Application Trust.',
      why_it_matters: 'A missing result can hide an issue.',
      not_proof: 'Missing evidence does not mean the Mac is safe or compromised.',
      verify: 'Review readiness, then rerun the same scan.',
      action_risk: 'Reviewing is read-only.',
    }],
    axes: {
      priority: { label: 'Unknown' },
      coverage: { percent: 50, label: 'Partial for selected scope' },
      confidence: { label: 'Low' },
    },
    score_note: 'Coverage is not a safety score.',
  };
  await page.route('**/reports/incomplete.json', async (route) => {
    await route.fulfill({ json: {
      metadata: { scan_id: 'test-incomplete' },
      summary: { finding_count: 0, total_finding_count: 0 },
      findings: [], timeline: [],
    } });
  });
  await page.route('**/api/decision-support/test-incomplete', async (route) => {
    await route.fulfill({ json: { scan_id: 'test-incomplete', experience, changes: { message: 'No comparison is available.' } } });
  });
  await page.evaluate(() => loadReport({ reports: { json: '/reports/incomplete.json' } }));

  await expect(page.locator('#experience-summary')).toContainText('Scan incomplete');
  await expect(page.locator('#report-context')).toBeVisible();
  await expect(page.locator('#report-context')).toContainText('no complete section list');
  await expect(page.locator('#experience-summary')).toContainText('Application Trust');
  await expect(page.locator('#summary')).toContainText('50% | Partial for selected scope');
  await page.getByRole('button', { name: 'Show analyst view' }).click();
  await expect(page.locator('#view-analyst')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#experience-summary')).toContainText('Some checks did not finish.');
  await page.locator('#view-simple').click();
  await expect(page.locator('#view-simple')).toHaveAttribute('aria-pressed', 'true');
});

test('review copy and cards fit narrow and wide viewports', async ({ page }) => {
  await page.evaluate(() => renderExperience({
    assessment: {
      id: 'action-recommended',
      label: 'Action recommended',
      headline: 'Review the highest-priority evidence before making changes.',
      explanation: 'A signature integrity failure is not proof of malware.',
    },
    next_actions: [{
      title: 'Application trust: Xcode',
      label: 'High-priority trust issue',
      verdict: 'high-priority',
      observed: 'The app failed a signature integrity check.',
      why_it_matters: 'Signed files may have changed.',
      not_proof: 'This does not prove compromise.',
      verify: 'Recheck the app and confirm the source.',
      action_risk: 'Reviewing is read-only.',
    }, {
      title: 'IOC path match',
      label: 'Indicator match to validate',
      verdict: 'indicator-match',
      observed: 'A local path matched a rule.',
      why_it_matters: 'The rule might be relevant.',
      not_proof: 'A rule match requires validation.',
      verify: 'Inspect the matching file and rule source.',
      action_risk: 'Reviewing is read-only.',
    }],
  }));

  for (const width of [320, 375, 768, 1280]) {
    await page.setViewportSize({ width, height: 850 });
    await expect(page.locator('#experience-summary')).toContainText('High-priority trust issue');
    await expect(page.locator('#experience-summary')).toContainText('Indicator match to validate');
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, `Horizontal overflow at ${width}px`).toBeLessThanOrEqual(1);
  }
});

test('historical trust findings show a recheck cue without changing the recorded status', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 850 });
  await page.evaluate(() => renderApplicationReview({
    available: true,
    conclusion: 'Review recorded trust results in context.',
    total: 1,
    counts: { review_first: 1 },
    applications: [{
      finding_id: 'APP-TRUST-LEGACY',
      group: 'review_first', group_label: 'Review first',
      name: 'Example', path: '/Applications/Example.app',
      explanation: 'This older report recorded a trust result without confirming whether every verification check finished.',
      legacy_verification: true,
      signature_valid: null, gatekeeper_accepted: true,
      signals: [],
    }],
  }));

  await expect(page.locator('#application-review')).toContainText('Historical check: recheck required');
  await expect(page.locator('#application-review')).toContainText('Signature completion not recorded');
  await expect(page.locator('#application-review')).toContainText('Recheck this app');
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});

test('Apple components that Gatekeeper cannot assess are not labeled rejected or unknown', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 850 });
  await page.evaluate(() => renderApplicationReview({
    available: true, conclusion: 'Review recorded trust results in context.', total: 1,
    counts: { checks_passed: 1 },
    applications: [{
      finding_id: 'APP-TRUST-APPLE', group: 'checks_passed', group_label: 'Checks passed',
      name: 'Apple component', path: '/System/Applications/Example.app',
      explanation: 'The Apple signature is valid. Gatekeeper cannot assess this component independently.',
      signature_valid: true, gatekeeper_accepted: null, gatekeeper_applicable: false,
      notarized: null, signals: [],
    }],
  }));
  await page.getByRole('button', { name: 'All applications 1' }).click();

  const card = page.locator('#application-review');
  await expect(card).toContainText('Gatekeeper not applicable');
  await expect(card).not.toContainText('Gatekeeper rejected');
  await expect(card).not.toContainText('Gatekeeper unknown');
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});

test('process response requires a recent snapshot with process start identity', async ({ page }) => {
  const controls = await page.evaluate(() => {
    const candidate = { pid: 4242, ppid: 12, uid: 501, user: 'alice', stat: 'S',
      executable: '/private/tmp/agent', process_start: 'Sun Sep 27 12:00:00 2026' };
    const finding = (row, collectedAt) => ({
      finding_id: 'LIVE-PROCESS-TREE', status: 'Review',
      evidence: [{ collected_at: collectedAt, value: { review_candidates: [row] } }],
    });
    const fresh = renderProcessResponseControls(finding(candidate, new Date().toISOString()));
    const legacy = renderProcessResponseControls(finding({ ...candidate, process_start: null }, new Date().toISOString()));
    const stale = renderProcessResponseControls(finding(candidate, new Date(Date.now() - 16 * 60 * 1000).toISOString()));
    return { fresh, legacy, stale };
  });
  expect(controls.fresh).toContain('>Terminate</button>');
  expect(controls.legacy).not.toContain('>Terminate</button>');
  expect(controls.legacy).toContain('record this process start identity');
  expect(controls.stale).not.toContain('>Terminate</button>');
  expect(controls.stale).toContain('older than 15 minutes');
});

test('report time and exact scope remain visible at narrow widths', async ({ page }) => {
  const metadata = {
    scan_id: 'historical-snapshot', tool_version: '1.4.2',
    started_at: new Date(Date.now() - 3 * 86400000 - 60000).toISOString(),
    completed_at: new Date(Date.now() - 3 * 86400000).toISOString(),
    collectors: ['application-trust', 'persistence'],
    target_application: `/Applications/${'LongApplicationName'.repeat(15)}<img src=x>.app`,
  };
  await page.evaluate((record) => {
    state.config = { collectors: [{ id: 'application-trust', title: 'Application Trust' }, { id: 'persistence', title: 'Persistence' }] };
    state.online = true;
    state.currentReportMetadata = record;
    renderReportContext();
    renderExperience({ assessment: { id: 'no-immediate-warning', label: 'No immediate warning identified', headline: 'No immediate review item was identified in this scan.' } });
  }, metadata);
  await expect(page.locator('#report-age')).toHaveText('3 days ago');
  await expect(page.locator('#report-context')).toContainText('Application Trust, Persistence');
  await expect(page.locator('#report-context')).toContainText(metadata.target_application);
  await expect(page.locator('#report-context img')).toHaveCount(0);
  await expect(page.locator('#experience-summary')).toContainText('ASSESSMENT FROM THIS SCAN');
  await expect(page.locator('#rerun-report')).toBeEnabled();
  for (const width of [320, 375, 768, 1280]) {
    await page.setViewportSize({ width, height: 850 });
    await expect(page.locator('#report-context')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1);
    if (width === 320 || width === 1280) await page.locator('#report-context').screenshot({ path: test.info().outputPath(`report-context-${width}.png`) });
  }
  await page.locator('#view-analyst').click();
  await expect(page.locator('#report-context')).toBeVisible();
  expect(await page.evaluate(() => state.currentReportMetadata)).toEqual(metadata);
});

test('rule provenance separates stable fingerprints from skipped checks in both views', async ({ page }) => {
  await page.evaluate(() => {
    state.currentReportMetadata = {scan_id: 'rules-fixture', collectors: ['ioc', 'yara-rules']};
    state.decisionSupport = {scan_id: 'rules-fixture', rule_context: {
      available: true, note: 'Fingerprints do not validate rule quality. No source is contacted.', source_note: 'Pack provenance is declared, not independently verified.',
      rows: [{collector: 'ioc', title: 'Local IOC packs', label: 'Rule snapshot stable', file_count: 1,
        fingerprint: 'a'.repeat(64), result_note: 'Matches recorded; some checks could not complete.', limitations: ['<img src=x onerror=window.ruleInjected=true>'],
        source_count: 1, sources: [{name: '<img src=x>' + 'x'.repeat(200), version: 'fixture', updated_at: '2026-01-01', source_host: 'example.invalid'}]},
        {collector: 'yara-rules', title: 'Managed YARA rules', label: 'Rule snapshot stable', file_count: 1,
          fingerprint: 'b'.repeat(64), result_note: 'Not run. YARA scanning is disabled.', limitations: [], sources: [], source_count: 0}],
    }};
    renderReportContext();
  });
  const panel = page.locator('#report-context .rule-context');
  await expect(panel).toContainText('Not run. YARA scanning is disabled.');
  await panel.locator('summary').first().click();
  await expect(panel).toContainText('example.invalid');
  await expect(panel.locator('img')).toHaveCount(0);
  await expect(panel.locator('a')).toHaveCount(0);
  for (const mode of ['simple', 'analyst']) {
    await page.evaluate(view => setViewMode(view), mode);
    for (const width of [320, 375, 768, 1280]) {
      await page.setViewportSize({width, height: 850});
      expect(await panel.evaluate(element => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(1);
    }
    const result = await new AxeBuilder({page}).include('#report-context').withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
    expect(result.violations.map(row => row.id)).toEqual([]);
  }
  expect(await page.evaluate(() => window.ruleInjected)).toBeUndefined();
});

test('rule context from another scan is never reused and missing context is explicit', async ({ page }) => {
  await page.evaluate(() => {
    state.currentReportMetadata = {scan_id: 'other-report', collectors: ['ioc']};
    state.decisionSupport = {scan_id: 'prior-report', rule_context: {available: true, rows: [{label: 'Stale rule label'}]}};
    renderReportContext();
  });
  await expect(page.locator('#report-context')).toContainText('Rule context is unavailable');
  await expect(page.locator('#report-context')).not.toContainText('Stale rule label');
  await page.evaluate(() => { state.currentReportMetadata.collectors = ['security']; renderReportContext(); });
  await expect(page.locator('#report-context .rule-context')).toHaveCount(0);
});

test('latest report selection wins when JSON responses arrive out of order', async ({ page }) => {
  let earlier;
  const report = id => ({metadata: {scan_id: id, collectors: ['security']}, summary: {finding_count: 0}, findings: [], timeline: []});
  await page.route('**/reports/earlier.json', route => { earlier = route; });
  await page.route('**/reports/recent.json', route => route.fulfill({json: report('recent')}));
  await page.route('**/api/decision-support/recent', route => route.fulfill({json: {scan_id: 'recent', changes: {message: 'Recent scan context'}}}));
  await page.evaluate(() => { window.earlierLoad = loadReport({reports: {json: '/reports/earlier.json'}}); });
  await expect.poll(() => Boolean(earlier)).toBe(true);
  await page.evaluate(() => loadReport({reports: {json: '/reports/recent.json'}}));
  await earlier.fulfill({json: report('earlier')});
  await page.evaluate(() => window.earlierLoad);
  expect(await page.evaluate(() => state.currentScanId)).toBe('recent');
  await expect(page.locator('#decision-support')).toContainText('Recent scan context');
  await expect(page.locator('#report-links a')).toHaveAttribute('href', '/reports/recent.json');
  expect(await page.evaluate(() => state.loadingReport)).toBe(false);
});

test('late decision support cannot replace a newer scan or unlock its pending load', async ({ page }) => {
  let oldDecision;
  let newReport;
  const report = id => ({metadata: {scan_id: id, collectors: ['security']}, summary: {finding_count: 0}, findings: [], timeline: []});
  await page.route('**/reports/old.json', route => route.fulfill({json: report('old')}));
  await page.route('**/reports/new.json', route => { newReport = route; });
  await page.route('**/api/decision-support/old', route => { oldDecision = route; });
  await page.route('**/api/decision-support/new', route => route.fulfill({json: {scan_id: 'new', changes: {message: 'New context'}}}));
  await page.evaluate(() => { window.oldLoad = loadReport({reports: {json: '/reports/old.json'}}); });
  await expect.poll(() => Boolean(oldDecision)).toBe(true);
  await page.evaluate(() => { window.newLoad = loadReport({reports: {json: '/reports/new.json'}}); });
  await expect.poll(() => Boolean(newReport)).toBe(true);
  await oldDecision.fulfill({json: {scan_id: 'old', changes: {message: 'Old context'}}});
  await page.evaluate(() => window.oldLoad);
  expect(await page.evaluate(() => state.loadingReport)).toBe(true);
  await newReport.fulfill({json: report('new')});
  await page.evaluate(() => window.newLoad);
  await expect(page.locator('#decision-support')).toContainText('New context');
  await expect(page.locator('#decision-support')).not.toContainText('Old context');
  expect(await page.evaluate(() => state.currentScanId)).toBe('new');
});

test('process response is blocked while another report loads and old candidates are discarded', async ({ page }) => {
  let pending;
  let signals = 0;
  await page.route('**/reports/pending.json', route => { pending = route; });
  await page.route('**/api/decision-support/pending', route => route.fulfill({json: {scan_id: 'pending'}}));
  await page.route('**/api/processes/terminate', route => { signals += 1; return route.fulfill({json: {}}); });
  await page.evaluate(() => {
    state.online = true;
    state.currentScanId = 'source';
    setViewMode('analyst');
    renderFindings([{finding_id: 'LIVE-PROCESS-TREE', category: 'Live Triage', severity: 'Medium', status: 'Review', title: 'Synthetic process',
      evidence: [{kind: 'process_snapshot', collected_at: new Date().toISOString(), value: {review_candidates: [{pid: 4242, uid: 501, process_start: 'fixture', executable: '/synthetic/tool'}]}}]}]);
    window.pendingLoad = loadReport({reports: {json: '/reports/pending.json'}});
  });
  await expect.poll(() => Boolean(pending)).toBe(true);
  await page.locator('.finding-toggle').click();
  await expect(page.getByRole('button', {name: 'Terminate', exact: true})).toBeDisabled();
  await page.evaluate(() => respondToProcess(document.querySelector('[data-process-action]')));
  expect(signals).toBe(0);
  await pending.fulfill({json: {metadata: {scan_id: 'pending', collectors: ['security']}, summary: {finding_count: 0}, findings: []}});
  await page.evaluate(() => window.pendingLoad);
  expect(await page.evaluate(() => state.processCandidates.size)).toBe(0);
});

test('mismatched decision support is rejected without losing the original report', async ({ page }) => {
  await page.route('**/reports/original.json', route => route.fulfill({json: {metadata: {scan_id: 'original', collectors: ['security']}, summary: {finding_count: 0}, findings: []}}));
  await page.route('**/api/decision-support/original', route => route.fulfill({json: {scan_id: 'other', changes: {message: 'Wrong report data'}}}));
  await page.evaluate(() => loadReport({reports: {json: '/reports/original.json'}}));
  expect(await page.evaluate(() => state.currentScanId)).toBe('original');
  await expect(page.locator('#action-message')).toContainText('different scan');
  await expect(page.locator('#decision-support')).toBeHidden();
  await expect(page.locator('#report-links a')).toHaveAttribute('href', '/reports/original.json');
});

test('an investigation save remains tied to its source after switching reports', async ({ page }) => {
  let saving;
  let body;
  let followups = 0;
  await page.route('**/api/investigations', route => { saving = route; body = route.request().postDataJSON(); });
  await page.route('**/api/decision-support/**', route => { followups += 1; return route.fulfill({json: {scan_id: 'source'}}); });
  await page.evaluate(() => {
    state.currentScanId = 'source';
    document.querySelector('#findings').innerHTML = '<div class="investigation-box"><select data-investigation-status><option>Investigating</option></select><textarea data-investigation-note>Fixture note</textarea><span class="investigation-message"></span><button data-save-investigation="fixture">Save</button></div>';
    window.savePending = saveInvestigation(document.querySelector('[data-save-investigation]'));
  });
  await expect.poll(() => Boolean(saving)).toBe(true);
  await page.evaluate(() => {
    state.reportLoadId += 1;
    state.currentScanId = 'new-selection';
    state.decisionSupport = {scan_id: 'new-selection'};
  });
  await saving.fulfill({json: {guidance: {headline: 'Old source guidance'}}});
  await page.evaluate(() => window.savePending);
  expect(body.scan_id).toBe('source');
  expect(followups).toBe(0);
  expect(await page.evaluate(() => state.decisionSupport.scan_id)).toBe('new-selection');
});

test('standalone investigation summary preserves responsive rule provenance without external links', async ({ page }) => {
  const body = execFileSync('python3', ['-c', `
import tempfile
from pathlib import Path
from macos_inspector.core.decision_support import build_decision_support, write_investigation_summary
report = {'metadata': {'scan_id': 'synthetic', 'collectors': ['ioc'], 'detection_context': {'ioc': {'schema_version': 1, 'fingerprint': 'a' * 64, 'file_count': 1, 'stable': False, 'complete': True}}}, 'findings': [], 'summary': {}}
with tempfile.TemporaryDirectory() as directory:
    path = write_investigation_summary(report, build_decision_support(report), Path(directory))
    print(path.read_text())
`], {encoding: 'utf8', env: {...process.env, PYTHONPATH: 'src'}});
  await page.route('**/rule-summary.html', route => route.fulfill({contentType: 'text/html', body}));
  await page.goto('/rule-summary.html');
  await expect(page.locator('.rule-context')).toContainText('Rules changed during collection');
  await page.getByText('Recorded rule details and provenance', {exact: true}).click();
  await expect(page.locator('.rule-context code')).toHaveText('a'.repeat(64));
  for (const width of [320, 375, 768, 1280]) {
    await page.setViewportSize({width, height: 850});
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1);
  }
  await expect(page.locator('.rule-context a')).toHaveCount(0);
});

test('repeating a report sends its sections and target with current settings', async ({ page }) => {
  const requests = [];
  await page.route('**/api/scans', async (route) => {
    requests.push(route.request().postDataJSON());
    await route.fulfill({ status: 400, json: { error: 'Collection prevented by test fixture' } });
  });
  await page.evaluate(() => {
    state.config = { collectors: [{ id: 'application-trust', title: 'Application Trust' }, { id: 'persistence', title: 'Persistence' }, { id: 'live-triage', title: 'Live Triage' }] };
    state.online = true;
    state.currentReportMetadata = { collectors: ['application-trust', 'persistence'], target_application: '/Applications/Example.app' };
    document.querySelector('#collectors').innerHTML = '<input type="checkbox" data-collector="live-triage" checked>';
    document.querySelector('#formats').innerHTML = '<input type="checkbox" data-format="json" checked>';
    document.querySelector('#minimum').value = 'high';
    document.querySelector('#case-reference').value = 'CURRENT-CASE';
    renderReportContext();
  });
  await page.locator('#rerun-report').click();
  await expect.poll(() => requests.length).toBe(1);
  expect(requests[0]).toMatchObject({ collectors: ['application-trust', 'persistence'], target_application: '/Applications/Example.app', formats: ['json'], minimum: 'high', case_reference: 'CURRENT-CASE' });
  await expect(page.locator('#action-message')).toContainText('Collection prevented');
  await expect(page.locator('#report-context [data-scan-message]')).toContainText('Collection prevented');
  await page.evaluate(() => { state.activeJob = 'already-running'; updateRunAvailability(); });
  await expect(page.locator('#rerun-report')).toBeDisabled();
  await page.evaluate(() => rerunReportScope());
  expect(requests).toHaveLength(1);
  await expect(page.locator('#action-message')).toContainText('A scan is already running');
});

test('repeating an online scope still requires confirmation', async ({ page }) => {
  const requests = [];
  await page.route('**/api/scans', async (route) => {
    requests.push(route.request().postDataJSON());
    await route.fulfill({ status: 400, json: { error: 'Collection prevented by test fixture' } });
  });
  await page.evaluate(() => {
    state.config = { collectors: [{ id: 'vulnerability-exposure', title: 'Vulnerability Intelligence', external_network: true }] };
    state.online = true;
    state.currentReportMetadata = { collectors: ['vulnerability-exposure'] };
    document.querySelector('#formats').innerHTML = '<input type="checkbox" data-format="json" checked>';
    renderReportContext();
  });
  page.once('dialog', (dialog) => dialog.dismiss());
  await page.locator('#rerun-report').click();
  expect(requests).toHaveLength(0);
  await expect(page.locator('#rerun-report')).toBeEnabled();
  page.once('dialog', (dialog) => {
    expect(dialog.message()).toContain('Vulnerability Intelligence');
    dialog.accept();
  });
  await page.locator('#rerun-report').click();
  await expect.poll(() => requests.length).toBe(1);
  expect(requests[0].collectors).toEqual(['vulnerability-exposure']);
});

test('unavailable sections and invalid timestamps do not imply a current scan', async ({ page }) => {
  await page.evaluate(() => {
    state.online = true;
    state.config = { collectors: [{ id: 'security', title: 'Security controls' }] };
    state.currentReportMetadata = { collectors: ['security', 'removed-section'], completed_at: '2026-02-31T12:00:00Z' };
    renderReportContext();
  });
  await expect(page.locator('#rerun-report')).toBeDisabled();
  await expect(page.locator('#report-context')).toContainText('recorded sections are unavailable: removed-section');
  await expect(page.locator('#report-age')).toHaveText('Unavailable');
  await page.evaluate(() => { state.currentReportMetadata = { collectors: ['security'], completed_at: '2026-10-01T12:00:00' }; renderReportContext(); });
  await expect(page.locator('#report-age')).toHaveText('Unavailable');
  await page.evaluate(() => { state.currentReportMetadata = { collectors: ['security'], completed_at: new Date(Date.now() + 3600000).toISOString() }; renderReportContext(); });
  await expect(page.locator('#report-age')).toHaveText('Recorded time is in the future');
  await expect(page.locator('#report-time-note')).toContainText('Check the clock');
  await page.evaluate(() => { state.currentReportMetadata = {}; renderReportContext(); });
  await expect(page.locator('#rerun-report')).toBeDisabled();
  await expect(page.locator('#report-context')).toContainText('no complete section list');
});

test('a stale process report can collect fresh live evidence without signaling a process', async ({ page }) => {
  const scans = [];
  let signals = 0;
  await page.route('**/api/scans', async (route) => {
    scans.push(route.request().postDataJSON());
    await route.fulfill({ status: 400, json: { error: 'Collection prevented by test fixture' } });
  });
  await page.route('**/api/processes/terminate', async (route) => { signals += 1; await route.fulfill({ status: 400, json: { error: 'No process action authorized' } }); });
  await page.evaluate(() => {
    state.online = true;
    state.config = { collectors: [{ id: 'live-triage', title: 'Live Triage' }] };
    document.querySelector('#formats').innerHTML = '<input type="checkbox" data-format="json" checked>';
    renderFindings([{
      finding_id: 'LIVE-PROCESS-TREE', category: 'Live Triage', title: 'Process snapshot', severity: 'Medium', status: 'Review',
      evidence: [{ collected_at: new Date(Date.now() - 16 * 60000).toISOString(), value: { review_candidates: [{ pid: 4242, uid: 501, ppid: 12, user: 'alice', stat: 'S', executable: '/private/tmp/agent', process_start: 'Fri Oct 2 12:00:00 2026' }] } }],
    }]);
    setViewMode('analyst');
  });
  await page.getByRole('button', { name: 'Details', exact: true }).click();
  await expect(page.locator('.process-response')).toContainText('older than 15 minutes');
  await page.getByRole('button', { name: 'Refresh Live Triage', exact: true }).click();
  await expect.poll(() => scans.length).toBe(1);
  expect(scans[0]).toMatchObject({ collectors: ['live-triage'], target_application: '' });
  expect(signals).toBe(0);
});

test('process response rechecks snapshot age when the button is pressed', async ({ page }) => {
  const result = await page.evaluate(async () => {
    const row = document.createElement('div');
    row.className = 'process-action-row';
    row.innerHTML = '<button type="button" data-process-key="candidate" data-process-action="terminate">Terminate</button><span class="process-action-result"></span>';
    document.body.append(row);
    state.currentScanId = 'test-scan';
    state.processCandidates.set('candidate', {
      pid: 4242, executable: '/private/tmp/agent',
      snapshot_at: new Date(Date.now() - 16 * 60 * 1000).toISOString(),
    });
    let confirmations = 0;
    const originalConfirm = window.confirm;
    window.confirm = () => { confirmations += 1; return true; };
    try {
      await respondToProcess(row.querySelector('button'));
      return { confirmations, disabled: row.querySelector('button').disabled,
        message: row.querySelector('.process-action-result').textContent };
    } finally {
      window.confirm = originalConfirm;
      row.remove();
    }
  });
  expect(result.confirmations).toBe(0);
  expect(result.disabled).toBe(true);
  expect(result.message).toContain('expired');
});

test('a skipped optional check is shown as limited scope, not a normal result', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 850 });
  await page.evaluate(() => {
    renderExperience({
      assessment: {
        id: 'limited-scope', label: 'Limited scan scope',
        headline: 'Some selected checks did not assess a target.',
        explanation: 'The checks ran, but one had no enabled rules.',
      },
      next_actions: [{
        title: 'Managed YARA local scan', label: 'Not assessed', verdict: 'not-assessed',
        observed: 'YARA scanning is disabled in local settings.',
        why_it_matters: 'No files were checked against YARA rules.',
        not_proof: 'This is not evidence that the Mac is safe or compromised.',
        verify: 'Enable YARA and select trusted rules and explicit targets.',
        action_risk: 'Changing YARA settings does not remove files.',
      }],
    });
    renderGuidance({
      headline: 'Some selected checks did not assess a target.',
      plain_language_note: 'A review result is a reason to investigate, not proof of malware.',
      counts: { attention: 0, unable_to_verify: 0, not_assessed: 1, looks_normal_or_resolved: 0, recorded_observations: 0 },
      priorities: [], workflow: [],
    });
  });

  await expect(page.locator('#experience-summary')).toContainText('Limited scan scope');
  await expect(page.locator('#experience-summary')).toContainText('Not assessed');
  await expect(page.locator('#guided-summary')).toContainText('1 not assessed');
  await expect(page.locator('#guided-summary')).toContainText('0 normal or resolved');
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});

test('history and comparisons do not show a numeric index for unassessed scans', async ({ page }) => {
  await page.evaluate(() => {
    state.historyScans = [{
      job_id: 'unassessed-job', scan_id: 'unassessed-scan', state: 'completed',
      collectors: ['yara-rules'], completed_at: '2026-01-01T00:00:00Z',
      summary: { overall_score: 100, assessed_finding_count: 0 },
      reports: { json: '/reports/unassessed.json' },
    }, {
      job_id: 'legacy-job', scan_id: 'legacy-scan', state: 'completed',
      collectors: ['security'], completed_at: '2025-01-01T00:00:00Z',
      summary: { overall_score: 85 }, reports: { json: '/reports/legacy.json' },
    }];
    renderHistory();
    renderComparison({
      score_delta: null, counts: { new: 0, resolved: 0, changed: 0 },
      scope: { changed: false }, new: [], resolved: [], changed: [],
    });
  });

  await expect(page.locator('#history')).toContainText('N/A (no assessed findings)');
  await expect(page.locator('#history')).toContainText('rule outcome index 85');
  await expect(page.locator('#comparison-summary')).toContainText('N/A');
  await expect(page.locator('#comparison-results')).toContainText('no assessed findings');
});

test('completion is labeled separately from target assessment', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 850 });
  await page.evaluate(() => renderSummary(
    { finding_count: 1, total_finding_count: 1 },
    { axes: {
      priority: { label: 'Check scan scope' },
      coverage: { percent: 100, label: 'Checks finished; some not assessed' },
      confidence: { label: 'Some selected checks have no target evidence' },
    } },
  ));

  await expect(page.locator('#summary')).toContainText('Collection completion');
  await expect(page.locator('#summary')).toContainText('100% | Checks finished; some not assessed');
  await expect(page.locator('#summary')).not.toContainText('Collection coverage');
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});
