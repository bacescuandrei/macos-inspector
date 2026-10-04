const { test, expect } = require('@playwright/test');
const { execFileSync } = require('node:child_process');
const { default: AxeBuilder } = require('@axe-core/playwright');
const { readFileSync } = require('node:fs');

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
    await route.fulfill({ json: { experience, changes: { message: 'No comparison is available.' } } });
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
