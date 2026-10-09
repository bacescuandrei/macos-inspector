const {test, expect} = require('@playwright/test');
const {spawn} = require('node:child_process');
const {mkdtempSync, readFileSync, rmSync} = require('node:fs');
const {tmpdir} = require('node:os');
const {join, resolve} = require('node:path');

let server;
let directory;
let origin;
let launchUrl;

test.beforeAll(async () => {
  directory = mkdtempSync(join(tmpdir(), 'inspector-pdf-browser-'));
  const program = `import signal,sys
from pathlib import Path
from macos_inspector.web import DashboardState,DashboardServer
def stop(*args):
    raise KeyboardInterrupt
signal.signal(signal.SIGTERM,stop)
server=DashboardServer(('127.0.0.1',0),DashboardState(Path(sys.argv[1])))
print(server.server_port,flush=True)
try:
    server.serve_forever()
except KeyboardInterrupt:
    pass
finally:
    server.server_close()
`;
  server = spawn('python3', ['-u', '-c', program, directory], {env: {...process.env, PYTHONPATH: resolve('src'), PYTHONDONTWRITEBYTECODE: '1'}, stdio: ['ignore', 'pipe', 'pipe']});
  const port = await new Promise((accept, reject) => {
    let buffer = '';
    const timer = setTimeout(() => reject(new Error('Private test dashboard did not start.')), 10000);
    server.once('error', error => { clearTimeout(timer); reject(error); });
    server.stdout.on('data', data => {
      buffer += data;
      if (buffer.includes('\n')) {
        clearTimeout(timer);
        accept(Number(buffer.split('\n')[0]));
      }
    });
  });
  origin = `http://127.0.0.1:${port}`;
  launchUrl = JSON.parse(readFileSync(join(directory, `.macos-inspector-session-${port}.json`), 'utf8')).url;
});

test.afterAll(async () => {
  if (server && server.exitCode === null) {
    await new Promise(resolve => { server.once('exit', resolve); server.kill('SIGTERM'); });
  }
  if (directory) rmSync(directory, {recursive: true, force: true});
});

function activePdf() {
  const objects = ['<< /Type /Catalog /OpenAction 2 0 R >>', "<< /S /JavaScript /JS (app.launchURL\\('https://example.invalid/collect'\\);) >>"];
  let data = '%PDF-1.7\n';
  const offsets = [0];
  objects.forEach((value, index) => { offsets.push(Buffer.byteLength(data)); data += `${index + 1} 0 obj\n${value}\nendobj\n`; });
  const xref = Buffer.byteLength(data);
  data += `xref\n0 ${offsets.length}\n0000000000 65535 f \n`;
  for (const offset of offsets.slice(1)) data += `${String(offset).padStart(10, '0')} 00000 n \n`;
  data += `trailer\n<< /Root 1 0 R /Size ${offsets.length} >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(data);
}

test('real private dashboard uploads PDF bytes, preserves reports and never contacts targets', async ({page, request}, info) => {
  const external = [];
  page.on('request', row => { if (new URL(row.url()).origin !== origin) external.push(row.url()); });
  const macRequests = [];
  page.on('request', row => { if (/\/api\/(config|applications|scans|readiness|process-actions)(?:[/?]|$)/.test(row.url())) macRequests.push(row.url()); });
  expect((await request.get(`${origin}/api/config`)).status()).toBe(401);
  const pdfLaunch = new URL(launchUrl);
  pdfLaunch.pathname = '/pdf-inspector.html';
  await page.goto(pdfLaunch.href);
  await expect(page.locator('#connection')).toContainText('Connected | v2.0.0');
  expect(new URL(page.url()).hash).toBe('');
  expect(new URL(page.url()).pathname).toBe('/pdf-inspector.html');
  await expect(page.locator('#collectors, #history, script[src="app.js"]')).toHaveCount(0);
  await page.locator('#pdf-file').setInputFiles({name: 'static-fixture.pdf', mimeType: 'application/pdf', buffer: activePdf()});
  await expect(page.locator('#inspect-pdf')).toBeEnabled();
  await page.locator('#inspect-pdf').click();
  await expect(page.locator('#pdf-result')).toContainText('Review features');
  await expect(page.locator('#pdf-result')).toContainText('JavaScript is present or indicated.');
  await expect(page.locator('#pdf-result')).toContainText('Document open');
  await page.locator('#pdf-result').getByText(/JavaScript \| Object/).click();
  await expect(page.locator('#pdf-result')).toContainText('https://example.invalid/collect');
  const htmlUrl = await page.locator('#pdf-result').getByRole('link', {name: 'Open HTML report'}).getAttribute('href');
  expect(htmlUrl).toMatch(/^\/private-reports\/[0-9a-f]{48}\//);
  expect((await request.get(origin + htmlUrl)).status()).toBe(401);
  const popup = page.waitForEvent('popup');
  await page.locator('#pdf-result').getByRole('link', {name: 'Open HTML report'}).click();
  const report = await popup;
  await expect(report.locator('body')).toContainText('PDF Inspector');
  await expect(report.locator('body')).toContainText('https://example.invalid/collect');
  expect(await report.locator('script,iframe,object').count()).toBe(0);
  for (const width of [320,375,768,1280]) {
    await report.setViewportSize({width,height:850});
    expect(await report.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1);
  }
  await report.close();
  await page.locator('.pdf-history summary').click();
  await expect(page.locator('#pdf-history-list')).toContainText('static-fixture.pdf');
  await page.setViewportSize({width:1280,height:1000});
  await page.locator('#pdf-inspector').screenshot({path: info.outputPath('pdf-inspector-wide.png')});
  await page.setViewportSize({width:375,height:900});
  await page.locator('#pdf-inspector').screenshot({path: info.outputPath('pdf-inspector-mobile.png')});
  expect(external).toEqual([]);
  expect(macRequests).toEqual([]);
  await page.route('**/api/config', route => route.fulfill({status: 503, json: {error: 'Audit collection is outside this PDF browser fixture.'}}));
  await page.getByRole('link', {name: 'Back to Mac audit', exact: true}).click();
  await expect(page.locator('#connection')).toContainText('Connected | v2.0.0');
  await expect(page.getByRole('heading', {name: 'Audit sections', exact: true})).toBeVisible();
  await expect(page.locator('#pdf-file')).toHaveCount(0);
  await page.getByRole('link', {name: 'PDF Inspector', exact: true}).click();
  await expect(page.locator('#connection')).toContainText('Connected | v2.0.0');
  await page.locator('.pdf-history summary').click();
  await expect(page.locator('#pdf-history-list')).toContainText('static-fixture.pdf');
  expect(new URL(page.url()).hash).toBe('');
});
