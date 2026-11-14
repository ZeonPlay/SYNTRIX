import { decodeBitStream, textToBitStream } from './encoding.js';

export const E2EE_ITERATIONS = 600000;
export const E2EE_MAX_ENVELOPE_CHARACTERS = 1500;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

function webCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Browser ini tidak mendukung Web Crypto. Perbarui browser terlebih dahulu.');
  }
  return globalThis.crypto;
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  webCrypto().getRandomValues(bytes);
  return bytes;
}

export function bytesToBase64(bytes) {
  let binary = '';
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

export function base64ToBytes(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error('Data kunci E2EE tidak valid.');
  }
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function joinBytes(...parts) {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const joined = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.length;
  }
  return joined;
}

async function derivePassphraseMaterial(passphrase, salt, iterations) {
  if (typeof passphrase !== 'string' || passphrase.length < 10) {
    throw new Error('Passphrase E2EE minimal 10 karakter.');
  }
  if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 5000000) {
    throw new Error('Parameter penguatan kunci E2EE tidak valid.');
  }

  const subtle = webCrypto().subtle;
  const passphraseKey = await subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveBits']);
  const material = new Uint8Array(await subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    passphraseKey,
    512,
  ));
  return { wrapKeyBytes: material.slice(0, 32) };
}

async function createWrappedPrivateKey(pkcs8, passphrase, saltBytes, iterations) {
  const material = await derivePassphraseMaterial(passphrase, saltBytes, iterations);
  const subtle = webCrypto().subtle;
  const iv = randomBytes(12);
  const wrappingKey = await subtle.importKey('raw', material.wrapKeyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  const ciphertext = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode('SYNTRIX-E2EE-PRIVATE-v1') },
    wrappingKey,
    pkcs8,
  ));
  return { wrappedKey: bytesToBase64(joinBytes(iv, ciphertext)) };
}

export async function createE2eeIdentity(passphrase) {
  const subtle = webCrypto().subtle;
  const pair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const [privateKeyBytes, publicKeyBytes] = await Promise.all([
    subtle.exportKey('pkcs8', pair.privateKey),
    subtle.exportKey('raw', pair.publicKey),
  ]);
  const saltBytes = randomBytes(16);
  const wrapped = await createWrappedPrivateKey(privateKeyBytes, passphrase, saltBytes, E2EE_ITERATIONS);
  return {
    privateKey: pair.privateKey,
    publicKeyB64: bytesToBase64(new Uint8Array(publicKeyBytes)),
    wrappedKeyB64: wrapped.wrappedKey,
    saltB64: bytesToBase64(saltBytes),
    authToken: wrapped.authToken,
    iterations: E2EE_ITERATIONS,
  };
}

export async function unlockE2eePrivateKey(passphrase, saltB64, iterations, wrappedKeyB64) {
  const salt = base64ToBytes(saltB64);
  const material = await derivePassphraseMaterial(passphrase, salt, iterations);
  const wrapped = base64ToBytes(wrappedKeyB64);
  if (wrapped.length < 29) throw new Error('Backup private key E2EE rusak.');
  const iv = wrapped.slice(0, 12);
  const ciphertext = wrapped.slice(12);
  const subtle = webCrypto().subtle;
  const wrappingKey = await subtle.importKey('raw', material.wrapKeyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
  let privateKeyBytes;
  try {
    privateKeyBytes = await subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: encoder.encode('SYNTRIX-E2EE-PRIVATE-v1') },
      wrappingKey,
      ciphertext,
    );
  } catch {
    // Compatibility with earlier SYNTRIX key bundles that used AES-GCM
    // without additional authenticated data.
    try {
      privateKeyBytes = await subtle.decrypt(
        { name: 'AES-GCM', iv },
        wrappingKey,
        ciphertext,
      );
    } catch {
      throw new Error('Passphrase salah atau backup private key tidak dapat dibuka.');
    }
  }
  const privateKey = await subtle.importKey(
    'pkcs8',
    privateKeyBytes,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
  return { privateKey };
}

export async function rewrapE2eePrivateKey(privateKey, newPassphrase) {
  const privateKeyBytes = await webCrypto().subtle.exportKey('pkcs8', privateKey);
  const saltBytes = randomBytes(16);
  const wrapped = await createWrappedPrivateKey(privateKeyBytes, newPassphrase, saltBytes, E2EE_ITERATIONS);
  return {
    wrappedKeyB64: wrapped.wrappedKey,
    saltB64: bytesToBase64(saltBytes),
    iterations: E2EE_ITERATIONS,
  };
}

async function importPublicKey(publicKeyB64) {
  return webCrypto().subtle.importKey(
    'raw',
    base64ToBytes(publicKeyB64),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  );
}

function messageAad(senderId, receiverId) {
  return encoder.encode('SYNTRIX-E2EE-v1|' + senderId + '|' + receiverId);
}

function keyWrapAad(senderId, receiverId, side) {
  return encoder.encode('SYNTRIX-E2EE-WRAP-v1|' + senderId + '|' + receiverId + '|' + side);
}

async function deriveContentWrappingKey(privateKey, peerPublicKeyB64, salt, info) {
  const subtle = webCrypto().subtle;
  const peerPublicKey = await importPublicKey(peerPublicKeyB64);
  const sharedSecret = await subtle.deriveBits({ name: 'ECDH', public: peerPublicKey }, privateKey, 256);
  const hkdfKey = await subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function wrapContentKey(rawContentKey, privateKey, peerPublicKeyB64, senderId, receiverId, side) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const aad = keyWrapAad(senderId, receiverId, side);
  const wrappingKey = await deriveContentWrappingKey(privateKey, peerPublicKeyB64, salt, aad);
  const ciphertext = await webCrypto().subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    wrappingKey,
    rawContentKey,
  );
  return {
    s: bytesToBase64(salt),
    i: bytesToBase64(iv),
    c: bytesToBase64(new Uint8Array(ciphertext)),
  };
}

export async function encryptE2eePayload({
  plaintext,
  privateKey,
  ownPublicKeyB64,
  recipientPublicKeyB64,
  senderId,
  receiverId,
}) {
  // Keep the existing printable-ASCII chat limit; only ciphertext is framed.
  textToBitStream(plaintext);
  if (!privateKey || !ownPublicKeyB64 || !recipientPublicKeyB64) {
    throw new Error('E2EE belum siap. Pastikan kedua akun sudah mengaktifkannya.');
  }

  const subtle = webCrypto().subtle;
  const contentKey = randomBytes(32);
  const messageIv = randomBytes(12);
  const aesKey = await subtle.importKey('raw', contentKey, { name: 'AES-GCM' }, false, ['encrypt']);
  const aad = messageAad(senderId, receiverId);
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv: messageIv, additionalData: aad },
    aesKey,
    encoder.encode(plaintext),
  );

  const [senderWrap, receiverWrap] = await Promise.all([
    wrapContentKey(contentKey, privateKey, ownPublicKeyB64, senderId, receiverId, 'sender'),
    wrapContentKey(contentKey, privateKey, recipientPublicKeyB64, senderId, receiverId, 'receiver'),
  ]);
  const envelope = {
    v: 1,
    s: senderId,
    r: receiverId,
    i: bytesToBase64(messageIv),
    c: bytesToBase64(new Uint8Array(ciphertext)),
    sw: senderWrap,
    rw: receiverWrap,
  };
  const encodedEnvelope = bytesToBase64(encoder.encode(JSON.stringify(envelope)));
  const payloadBits = textToBitStream(encodedEnvelope, E2EE_MAX_ENVELOPE_CHARACTERS);
  return { payloadBits, frameCount: encodedEnvelope.length };
}

export async function decryptE2eePayload({
  payloadBits,
  privateKey,
  ownPublicKeyB64,
  peerPublicKeyB64,
  userId,
  message,
}) {
  const encodedEnvelope = decodeBitStream(payloadBits);
  const envelope = JSON.parse(decoder.decode(base64ToBytes(encodedEnvelope)));
  if (
    envelope?.v !== 1
    || envelope.s !== message.sender_id
    || envelope.r !== message.receiver_id
    || !envelope.i || !envelope.c || !envelope.sw || !envelope.rw
  ) {
    throw new Error('Format pesan E2EE tidak valid.');
  }

  const isSender = userId === message.sender_id;
  if (!isSender && userId !== message.receiver_id) {
    throw new Error('Pesan ini bukan bagian dari percakapan akunmu.');
  }
  const side = isSender ? 'sender' : 'receiver';
  const wrapped = isSender ? envelope.sw : envelope.rw;
  const peerKey = isSender ? ownPublicKeyB64 : peerPublicKeyB64;
  if (!peerKey) throw new Error('Public key kontak tidak tersedia.');

  const aad = keyWrapAad(message.sender_id, message.receiver_id, side);
  const wrappingKey = await deriveContentWrappingKey(
    privateKey,
    peerKey,
    base64ToBytes(wrapped.s),
    aad,
  );
  const subtle = webCrypto().subtle;
  let contentKeyBytes;
  try {
    contentKeyBytes = await subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(wrapped.i), additionalData: aad },
      wrappingKey,
      base64ToBytes(wrapped.c),
    );
  } catch {
    throw new Error('Kunci pesan tidak cocok dengan identitas percakapan.');
  }

  const contentKey = await subtle.importKey('raw', contentKeyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
  try {
    const plaintext = await subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: base64ToBytes(envelope.i),
        additionalData: messageAad(message.sender_id, message.receiver_id),
      },
      contentKey,
      base64ToBytes(envelope.c),
    );
    return decoder.decode(plaintext);
  } catch {
    throw new Error('Isi pesan tidak dapat didekripsi. Data mungkin rusak atau telah dimodifikasi.');
  }
}
