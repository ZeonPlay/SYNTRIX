import test from 'node:test';
import assert from 'node:assert/strict';
import { parseUserAgent } from '../src/core/useragent.js';

const UA = {
  chromeWindows: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  edgeWindows: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
  chromeAndroid: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
  androidTablet: 'Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
  safariIphone: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
  safariIpadDesktopMode: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
  firefoxLinux: 'Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0',
};

test('Chrome on Windows', () => {
  const info = parseUserAgent(UA.chromeWindows);
  assert.equal(info.browser, 'Chrome 126');
  assert.equal(info.os, 'Windows 10/11');
  assert.equal(info.deviceType, 'desktop');
  assert.equal(info.label, 'Chrome 126 · Windows 10/11');
});

test('Edge is not reported as Chrome', () => {
  assert.equal(parseUserAgent(UA.edgeWindows).browser, 'Edge 126');
});

test('Chrome on an Android phone', () => {
  const info = parseUserAgent(UA.chromeAndroid);
  assert.equal(info.browser, 'Chrome 126');
  assert.equal(info.os, 'Android 14');
  assert.equal(info.deviceType, 'mobile');
});

test('Android without "Mobile" is a tablet', () => {
  assert.equal(parseUserAgent(UA.androidTablet).deviceType, 'tablet');
});

test('Safari on iPhone', () => {
  const info = parseUserAgent(UA.safariIphone);
  assert.equal(info.browser, 'Safari 17');
  assert.equal(info.os, 'iOS 17');
  assert.equal(info.deviceType, 'mobile');
});

test('iPad in desktop mode is detected through touch points', () => {
  assert.equal(parseUserAgent(UA.safariIpadDesktopMode).os, 'macOS');
  const ipad = parseUserAgent(UA.safariIpadDesktopMode, { maxTouchPoints: 5 });
  assert.equal(ipad.os, 'iPadOS');
  assert.equal(ipad.deviceType, 'tablet');
});

test('Firefox on Linux', () => {
  const info = parseUserAgent(UA.firefoxLinux);
  assert.equal(info.browser, 'Firefox 127');
  assert.equal(info.os, 'Linux');
  assert.equal(info.deviceType, 'desktop');
});

test('empty or missing user agent falls back safely', () => {
  for (const value of ['', undefined, null]) {
    const info = parseUserAgent(value);
    assert.equal(info.browser, 'Browser');
    assert.equal(info.os, 'Perangkat lain');
    assert.equal(info.deviceType, 'desktop');
  }
});
