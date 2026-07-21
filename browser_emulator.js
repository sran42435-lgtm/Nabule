// browser_emulator.js
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const RecaptchaPlugin = require('puppeteer-extra-plugin-recaptcha');
const ProxyPlugin = require('puppeteer-extra-plugin-proxy');
const BlockResourcesPlugin = require('puppeteer-extra-plugin-block-resources');

puppeteer.use(StealthPlugin());
puppeteer.use(
  RecaptchaPlugin({
    provider: { id: '2captcha', token: 'YOUR_2CAPTCHA_TOKEN' },
    visualFeedback: true,
  })
);
puppeteer.use(
  ProxyPlugin({
    address: process.env.PROXY_ADDRESS || '',
    credentials: {
      username: process.env.PROXY_USER || '',
      password: process.env.PROXY_PASS || ''
    }
  })
);
puppeteer.use(
  BlockResourcesPlugin({
    blockedTypes: new Set(['stylesheet', 'font', 'image', 'media']),
  })
);

const url = process.argv[2];
if (!url) {
  console.error('URL required');
  process.exit(1);
}

(async () => {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-accelerated-2d-canvas',
      '--disable-gpu',
      '--window-size=1920,1080'
    ]
  });
  const page = await browser.newPage();

  const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
  ];
  const randomUA = userAgents[Math.floor(Math.random() * userAgents.length)];
  await page.setUserAgent(randomUA);

  await page.setRequestInterception(true);
  page.on('request', (req) => {
    const headers = req.headers();
    headers['Accept-Language'] = 'en-US,en;q=0.9';
    req.continue({ headers });
  });

  try {
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
    await page.mouse.move(100, 100);
    await page.mouse.wheel({ deltaY: 200 });
    await page.waitForTimeout(1000);

    const data = await page.evaluate(() => {
      const forms = [];
      document.querySelectorAll('form').forEach(f => {
        const inputs = [];
        f.querySelectorAll('input').forEach(inp => {
          inputs.push({
            name: inp.name,
            type: inp.type,
            value: inp.value
          });
        });
        forms.push({
          action: f.action,
          method: f.method,
          inputs: inputs
        });
      });
      return {
        title: document.title,
        url: window.location.href,
        forms: forms,
        cookies: document.cookie,
        local_storage: JSON.stringify(localStorage),
        session_storage: JSON.stringify(sessionStorage),
        links: Array.from(document.querySelectorAll('a')).map(a => a.href),
        scripts: Array.from(document.querySelectorAll('script')).map(s => s.src),
        images: Array.from(document.querySelectorAll('img')).map(img => img.src)
      };
    });

    const screenshot = await page.screenshot({ encoding: 'base64', fullPage: true });
    data.screenshot_base64 = screenshot;

    await browser.close();
    console.log(JSON.stringify({ status: 'success', data }));
  } catch (error) {
    await browser.close();
    console.error(JSON.stringify({ status: 'error', message: error.message }));
    process.exit(1);
  }
})();
