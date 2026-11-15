import assert from 'node:assert/strict';
import test from 'node:test';

import { translateValue } from '../src/i18n.js';

test('language dictionary translates interface text in both directions', () => {
  assert.equal(translateValue('Pengaturan', 'en'), 'Settings');
  assert.equal(translateValue('Keamanan', 'en'), 'Security');
  assert.equal(translateValue('Settings', 'id'), 'Pengaturan');
  assert.equal(translateValue('Security', 'id'), 'Keamanan');
});

test('dynamic device notices are translated with their counts', () => {
  assert.equal(
    translateValue('Ada 1 perangkat baru masuk ke akunmu', 'en'),
    '1 new device signed in to your account',
  );
  assert.equal(
    translateValue('Ada 3 perangkat baru masuk ke akunmu', 'en'),
    '3 new devices signed in to your account',
  );
});
