// Turns a browser User-Agent string into the details shown on the Security page.
// Pure function (no DOM access) so it can be unit-tested with node --test.

const BROWSERS = [
  ['Edge', /\bEdg(?:e|A|iOS)?\/(\d+)/],
  ['Opera', /\bOPR\/(\d+)/],
  ['Samsung Internet', /\bSamsungBrowser\/(\d+)/],
  ['Firefox', /\b(?:Firefox|FxiOS)\/(\d+)/],
  ['Chrome', /\b(?:Chrome|CriOS)\/(\d+)/],
  ['Safari', /\bVersion\/(\d+)[\d.]*.*\bSafari\//],
];

export function parseUserAgent(userAgent = '', { maxTouchPoints = 0 } = {}) {
  const ua = String(userAgent ?? '');

  let browser = 'Browser';
  for (const [name, pattern] of BROWSERS) {
    const match = ua.match(pattern);
    if (match) {
      browser = `${name} ${match[1]}`;
      break;
    }
  }

  // iPadOS 13+ sends a desktop Mac user agent; touch support is the only hint.
  const isIPadOS = /Macintosh/.test(ua) && maxTouchPoints > 1;

  let os = 'Perangkat lain';
  if (/Android/.test(ua)) {
    os = `Android ${ua.match(/Android (\d+)/)?.[1] ?? ''}`.trim();
  } else if (/iPhone|iPad|iPod/.test(ua)) {
    os = `iOS ${ua.match(/\bOS (\d+)[_\d]* like Mac OS X/)?.[1] ?? ''}`.trim();
  } else if (isIPadOS) {
    os = 'iPadOS';
  } else if (/Windows NT 1[01]\./.test(ua)) {
    os = 'Windows 10/11';
  } else if (/Windows/.test(ua)) {
    os = 'Windows';
  } else if (/CrOS/.test(ua)) {
    os = 'ChromeOS';
  } else if (/Mac OS X/.test(ua)) {
    os = 'macOS';
  } else if (/Linux|X11/.test(ua)) {
    os = 'Linux';
  }

  let deviceType = 'desktop';
  if (/iPad|Tablet/.test(ua) || isIPadOS || (/Android/.test(ua) && !/Mobile/.test(ua))) {
    deviceType = 'tablet';
  } else if (/iPhone|iPod|Mobi|Android/.test(ua)) {
    deviceType = 'mobile';
  }

  return { browser, os, deviceType, label: `${browser} · ${os}` };
}
