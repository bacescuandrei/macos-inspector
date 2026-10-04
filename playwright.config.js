const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests/browser',
  workers: process.env.CI ? 1 : undefined,
  reporter: 'list',
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
    { name: 'webkit', use: { browserName: 'webkit' } },
  ],
  use: {
    baseURL: 'http://127.0.0.1:8876',
  },
  webServer: {
    command: 'python3 -m http.server 8876 --bind 127.0.0.1 --directory src/macos_inspector/webui',
    url: 'http://127.0.0.1:8876/',
    reuseExistingServer: false,
    timeout: 15000,
  },
});
