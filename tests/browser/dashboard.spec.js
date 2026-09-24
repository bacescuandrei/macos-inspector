const { test, expect } = require('@playwright/test');

test.beforeEach(async ({ page }) => {
  await page.route('**/api/health', async (route) => {
    await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"Test server is read-only"}' });
  });
  await page.goto('/');
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
