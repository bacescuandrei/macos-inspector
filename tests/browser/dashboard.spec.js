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
