import test from 'node:test';
import assert from 'node:assert/strict';

import {
  PAYLOAD_PREFIX,
  WrongUnlockKeyError,
  decryptMessage,
  encryptMessage,
  generateIdentity,
  rewrapKeyBundle,
  unlockPrivateKey,
} from '../src/core/e2ee.js';
import {
  MAX_MESSAGE_LENGTH,
  MAX_PAYLOAD_LENGTH,
  decodeBitStream,
  textToBitStream,
} from '../src/core/encoding.js';

// Low iteration counts keep the tests fast. Production uses KDF_ITERATIONS.
const FAST = { iterations: 1000, minIterations: 1 };
const ALICE_ID = 'aaaaaaaa-0000-4000-8000-000000000001';
const BOB_ID = 'bbbbbbbb-0000-4000-8000-000000000002';

async function makePair() {
  const alice = await generateIdentity('alice-unlock-key', FAST);
  const bob = await generateIdentity('bob-unlock-key', FAST);
  return { alice, bob };
}

function envelope(sender, receiver, extra = {}) {
  return {
    privateKey: sender.privateKey,
    peerPublicKey: receiver.publicKey,
    senderId: ALICE_ID,
    receiverId: BOB_ID,
    ...extra,
  };
}

test('a message encrypted by the sender is readable by both participants', async () => {
  const { alice, bob } = await makePair();
  const payload = await encryptMessage({ text: 'Halo Bob!', ...envelope(alice, bob) });
  assert.ok(payload.startsWith(PAYLOAD_PREFIX));

  const asReceiver = await decryptMessage({
    payload, privateKey: bob.privateKey, peerPublicKey: alice.publicKey,
    senderId: ALICE_ID, receiverId: BOB_ID,
  });
  const asSender = await decryptMessage({ payload, ...envelope(alice, bob) });
  assert.equal(asReceiver, 'Halo Bob!');
  assert.equal(asSender, 'Halo Bob!');
});

test('the stored payload does not contain the plaintext and is different each time', async () => {
  const { alice, bob } = await makePair();
  const first = await encryptMessage({ text: 'rahasia sekali', ...envelope(alice, bob) });
  const second = await encryptMessage({ text: 'rahasia sekali', ...envelope(alice, bob) });
  assert.ok(!first.includes('rahasia'));
  assert.notEqual(first, second);
});

test('a third party cannot decrypt a message', async () => {
  const { alice, bob } = await makePair();
  const carol = await generateIdentity('carol-unlock-key', FAST);
  const payload = await encryptMessage({ text: 'hanya untuk Bob', ...envelope(alice, bob) });
  await assert.rejects(decryptMessage({
    payload, privateKey: carol.privateKey, peerPublicKey: alice.publicKey,
    senderId: ALICE_ID, receiverId: BOB_ID,
  }), /tidak dapat didekripsi/i);
});

test('tampering with the payload is detected', async () => {
  const { alice, bob } = await makePair();
  const payload = await encryptMessage({ text: 'jangan diubah', ...envelope(alice, bob) });
  const index = payload.length - 6;
  const flipped = `${payload.slice(0, index)}${payload[index] === 'A' ? 'B' : 'A'}${payload.slice(index + 1)}`;
  await assert.rejects(decryptMessage({ payload: flipped, ...envelope(alice, bob) }), /tidak dapat didekripsi/i);
});

test('a ciphertext cannot be replayed under different sender or receiver ids', async () => {
  const { alice, bob } = await makePair();
  const payload = await encryptMessage({ text: 'terikat ke percakapan', ...envelope(alice, bob) });
  await assert.rejects(decryptMessage({ payload, ...envelope(alice, bob, { senderId: BOB_ID, receiverId: ALICE_ID }) }));
});

test('rejects payloads without the expected prefix', async () => {
  const { alice, bob } = await makePair();
  await assert.rejects(decryptMessage({ payload: 'plain text', ...envelope(alice, bob) }), /format/i);
});

test('the private key unlocks only with the right unlock key', async () => {
  const identity = await generateIdentity('kunci-pembuka-benar', FAST);
  const bundle = {
    wrappedPrivateKey: identity.wrappedPrivateKey,
    kdfSalt: identity.kdfSalt,
    kdfIterations: identity.kdfIterations,
  };
  const bob = await generateIdentity('bob-unlock-key', FAST);

  const payload = await encryptMessage({
    text: 'uji buka kunci', privateKey: bob.privateKey, peerPublicKey: identity.publicKey,
    senderId: BOB_ID, receiverId: ALICE_ID,
  });

  const unlocked = await unlockPrivateKey(bundle, 'kunci-pembuka-benar', FAST);
  const text = await decryptMessage({
    payload, privateKey: unlocked, peerPublicKey: bob.publicKey, senderId: BOB_ID, receiverId: ALICE_ID,
  });
  assert.equal(text, 'uji buka kunci');

  await assert.rejects(unlockPrivateKey(bundle, 'kunci-pembuka-salah', FAST), WrongUnlockKeyError);
});

test('changing the unlock key keeps the same identity', async () => {
  const identity = await generateIdentity('kunci-lama-123', FAST);
  const bob = await generateIdentity('bob-unlock-key', FAST);
  const bundle = {
    wrappedPrivateKey: identity.wrappedPrivateKey,
    kdfSalt: identity.kdfSalt,
    kdfIterations: identity.kdfIterations,
  };
  const payload = await encryptMessage({
    text: 'sebelum ganti kunci', privateKey: bob.privateKey, peerPublicKey: identity.publicKey,
    senderId: BOB_ID, receiverId: ALICE_ID,
  });

  const next = await rewrapKeyBundle(bundle, 'kunci-lama-123', 'kunci-baru-456', FAST);
  await assert.rejects(unlockPrivateKey(next, 'kunci-lama-123', FAST), WrongUnlockKeyError);
  const unlocked = await unlockPrivateKey(next, 'kunci-baru-456', FAST);
  const text = await decryptMessage({
    payload, privateKey: unlocked, peerPublicKey: bob.publicKey, senderId: BOB_ID, receiverId: ALICE_ID,
  });
  assert.equal(text, 'sebelum ganti kunci');

  await assert.rejects(rewrapKeyBundle(bundle, 'kunci-salah-000', 'kunci-baru-456', FAST), WrongUnlockKeyError);
});

test('unlock keys that are too short are refused', async () => {
  await assert.rejects(generateIdentity('pendek', FAST), /minimal/i);
  const identity = await generateIdentity('kunci-panjang-ok', FAST);
  const bundle = {
    wrappedPrivateKey: identity.wrappedPrivateKey,
    kdfSalt: identity.kdfSalt,
    kdfIterations: identity.kdfIterations,
  };
  await assert.rejects(rewrapKeyBundle(bundle, 'kunci-panjang-ok', 'pendek', FAST), /minimal/i);
});

test('a key bundle with a weakened iteration count is not accepted', async () => {
  const identity = await generateIdentity('kunci-panjang-ok', FAST);
  const weakened = {
    wrappedPrivateKey: identity.wrappedPrivateKey,
    kdfSalt: identity.kdfSalt,
    kdfIterations: 1,
  };
  // Default minIterations applies here, as it does in the browser.
  await assert.rejects(unlockPrivateKey(weakened, 'kunci-panjang-ok'), /iterasi/i);
});

test('the longest message still fits the framing layer and survives NRZ-I', async () => {
  const { alice, bob } = await makePair();
  const text = 'A'.repeat(MAX_MESSAGE_LENGTH);
  const payload = await encryptMessage({ text, ...envelope(alice, bob) });
  assert.ok(payload.length <= MAX_PAYLOAD_LENGTH, `payload is ${payload.length} characters`);

  const bits = textToBitStream(payload, { maxLength: MAX_PAYLOAD_LENGTH });
  assert.equal(bits.length, payload.length * 10);
  assert.equal(decodeBitStream(bits), payload);
  assert.equal(await decryptMessage({ payload, ...envelope(alice, bob) }), text);
});

test('the "e1." prefix matches the constant used by the database constraint', () => {
  assert.equal(textToBitStream(PAYLOAD_PREFIX), '011001010100110001110010111001');
});
