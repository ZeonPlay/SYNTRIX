import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

globalThis.crypto = webcrypto;

const {
  createE2eeIdentity,
  unlockE2eePrivateKey,
  encryptE2eePayload,
  decryptE2eePayload,
} = await import('../src/core/e2ee-crypto.js');

test('E2EE round-trip works for sender and recipient, including passphrase-wrapped private keys', async () => {
  const [alice, bob] = await Promise.all([
    createE2eeIdentity('alice strong passphrase'),
    createE2eeIdentity('bob strong passphrase'),
  ]);
  const message = {
    sender_id: '11111111-1111-4111-8111-111111111111',
    receiver_id: '22222222-2222-4222-8222-222222222222',
  };
  const encrypted = await encryptE2eePayload({
    plaintext: 'HELLO SYNTRIX',
    privateKey: alice.privateKey,
    ownPublicKeyB64: alice.publicKeyB64,
    recipientPublicKeyB64: bob.publicKeyB64,
    senderId: message.sender_id,
    receiverId: message.receiver_id,
  });
  assert.notEqual(encrypted.payloadBits, 'HELLO SYNTRIX');
  assert.equal(encrypted.payloadBits.length % 10, 0);

  const aliceOpened = await decryptE2eePayload({
    payloadBits: encrypted.payloadBits,
    privateKey: alice.privateKey,
    ownPublicKeyB64: alice.publicKeyB64,
    peerPublicKeyB64: bob.publicKeyB64,
    userId: message.sender_id,
    message,
  });
  const bobOpened = await decryptE2eePayload({
    payloadBits: encrypted.payloadBits,
    privateKey: bob.privateKey,
    ownPublicKeyB64: bob.publicKeyB64,
    peerPublicKeyB64: alice.publicKeyB64,
    userId: message.receiver_id,
    message,
  });
  assert.equal(aliceOpened, 'HELLO SYNTRIX');
  assert.equal(bobOpened, 'HELLO SYNTRIX');

  const unlocked = await unlockE2eePrivateKey(
    'alice strong passphrase',
    alice.saltB64,
    alice.iterations,
    alice.wrappedKeyB64,
  );
  const afterReload = await decryptE2eePayload({
    payloadBits: encrypted.payloadBits,
    privateKey: unlocked.privateKey,
    ownPublicKeyB64: alice.publicKeyB64,
    peerPublicKeyB64: bob.publicKeyB64,
    userId: message.sender_id,
    message,
  });
  assert.equal(afterReload, 'HELLO SYNTRIX');
  await assert.rejects(
    unlockE2eePrivateKey('wrong passphrase', alice.saltB64, alice.iterations, alice.wrappedKeyB64),
    /Passphrase salah/,
  );
});
