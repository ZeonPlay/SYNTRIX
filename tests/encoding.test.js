import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildFrames,
  decodeBitStream,
  nrziDecode,
  nrziEncode,
  textToBitStream,
  validateBitStream,
} from '../src/core/encoding.js';

test('creates one ten-bit frame per printable ASCII character', () => {
  const frames = buildFrames('SYNTRIX 123');
  assert.equal(frames.length, 11);
  for (const frame of frames) {
    assert.equal(frame.bits.length, 10);
    assert.equal(frame.bits[0], '0');
    assert.equal(frame.bits[9], '1');
    const ones = [...frame.bits.slice(1, 8)].filter((bit) => bit === '1').length;
    assert.equal(Number(frame.parity), ones % 2);
  }
});

test('encodes and decodes text through the NRZ-I signal', () => {
  const samples = [
    'HELLO',
    'SYNTRIX 123!',
    'Data Communication Lab',
    'A quick brown fox 0123456789.',
    '()[]{}:;,.!?+-*/=_',
  ];
  for (const sample of samples) {
    const bits = textToBitStream(sample);
    assert.equal(bits.length, sample.length * 10);
    assert.equal(decodeBitStream(bits), sample);
    assert.equal(nrziDecode(nrziEncode(bits)), sample);
  }
});

test('NRZ-I toggles only when the bit is one', () => {
  assert.deepEqual(nrziEncode('010110'), [1, 0, 0, 1, 0, 0]);
});

test('rejects malformed frames and parity errors', () => {
  const valid = textToBitStream('A');
  assert.equal(validateBitStream(valid), null);
  assert.match(validateBitStream(''), /kosong/i);
  assert.match(validateBitStream('010'), /kelipatan/i);
  assert.match(validateBitStream(`1${valid.slice(1)}`), /start/i);
  assert.match(validateBitStream(`${valid.slice(0, 9)}0`), /stop/i);
  const badParity = `${valid.slice(0, 8)}${valid[8] === '0' ? '1' : '0'}${valid.slice(9)}`;
  assert.match(validateBitStream(badParity), /parity/i);
});

test('rejects empty, non-ASCII, and overlong messages', () => {
  assert.throws(() => textToBitStream(''), /kosong/i);
  assert.throws(() => textToBitStream('emoji 😀'), /ASCII/i);
  assert.throws(() => textToBitStream('é'), /ASCII/i);
  assert.throws(() => textToBitStream('A'.repeat(501)), /maksimal/i);
});
