/**
 * End-to-end encryption helpers. WebCrypto only; no third-party code.
 *
 * Identity
 *   Every user has an ECDH P-256 key pair. The public key is published in
 *   profiles.public_key. The private key never leaves the browser in clear
 *   text: it is wrapped with AES-256-GCM under a key derived from the user's
 *   unlock key (PBKDF2-SHA-256), and only that wrapped copy is stored on the
 *   server. The server never receives the unlock key.
 *
 * Messages
 *   ECDH(own private key, peer public key) -> HKDF-SHA-256 -> AES-256-GCM key.
 *   Both participants derive the same key, so the sender can read their own
 *   messages too. Each message uses a fresh random 96-bit IV, and the sender
 *   and receiver ids are authenticated as additional data.
 *
 * The encrypted result is a printable-ASCII string ("e1." + base64), so it can
 * still be framed into 10-bit frames and NRZ-I encoded like any other text.
 *
 * Limits: there is no forward secrecy, and a user's public key is trusted as
 * the server delivers it (no safety-number verification yet).
 */

export const KDF_ITERATIONS = 600_000;
export const MIN_KDF_ITERATIONS = 100_000;
export const MAX_KDF_ITERATIONS = 5_000_000;
export const MIN_UNLOCK_KEY_LENGTH = 8;
export const MAX_UNLOCK_KEY_LENGTH = 128;
export const PAYLOAD_PREFIX = 'e1.';

const IV_BYTES = 12;
const SALT_BYTES = 16;
const TAG_BYTES = 16;
const CURVE = { name: 'ECDH', namedCurve: 'P-256' };
const KEY_AAD = utf8('syntrix-key-v1');
const HKDF_INFO = utf8('syntrix-e2ee-v1');

export class WrongUnlockKeyError extends Error {
  constructor() {
    super('Kunci pembuka salah.');
    this.name = 'WrongUnlockKeyError';
  }
}

function utf8(text) {
  return new TextEncoder().encode(text);
}

function subtle() {
  const api = globalThis.crypto?.subtle;
  if (!api) throw new Error('Enkripsi membutuhkan koneksi HTTPS atau localhost.');
  return api;
}

function randomBytes(length) {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function bytesToBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function base64ToBytes(text) {
  if (typeof text !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0) {
    throw new Error('Format data tidak valid.');
  }
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function assertUnlockKey(key) {
  if (typeof key !== 'string' || key.length < MIN_UNLOCK_KEY_LENGTH) {
    throw new Error(`Kunci minimal ${MIN_UNLOCK_KEY_LENGTH} karakter.`);
  }
  if (key.length > MAX_UNLOCK_KEY_LENGTH) {
    throw new Error(`Kunci maksimal ${MAX_UNLOCK_KEY_LENGTH} karakter.`);
  }
}

async function deriveWrappingKey(unlockKey, salt, iterations) {
  const material = await subtle().importKey(
    'raw', utf8(unlockKey.normalize('NFKC')), 'PBKDF2', false, ['deriveKey'],
  );
  return subtle().deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function wrapPkcs8(pkcs8, unlockKey, iterations) {
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const wrappingKey = await deriveWrappingKey(unlockKey, salt, iterations);
  const sealed = new Uint8Array(await subtle().encrypt(
    { name: 'AES-GCM', iv, additionalData: KEY_AAD }, wrappingKey, pkcs8,
  ));
  return {
    wrappedPrivateKey: bytesToBase64(concat(iv, sealed)),
    kdfSalt: bytesToBase64(salt),
    kdfIterations: iterations,
  };
}

async function openPkcs8(bundle, unlockKey, minIterations) {
  const iterations = bundle?.kdfIterations;
  if (!Number.isInteger(iterations) || iterations < minIterations || iterations > MAX_KDF_ITERATIONS) {
    // The bundle comes from the server, so never accept a weakened KDF.
    throw new Error('Jumlah iterasi kunci tidak aman atau tidak valid.');
  }
  const salt = base64ToBytes(bundle.kdfSalt);
  const raw = base64ToBytes(bundle.wrappedPrivateKey);
  if (salt.length !== SALT_BYTES || raw.length <= IV_BYTES + TAG_BYTES) {
    throw new Error('Data kunci tidak valid.');
  }
  const wrappingKey = await deriveWrappingKey(String(unlockKey ?? ''), salt, iterations);
  try {
    return new Uint8Array(await subtle().decrypt(
      { name: 'AES-GCM', iv: raw.slice(0, IV_BYTES), additionalData: KEY_AAD },
      wrappingKey,
      raw.slice(IV_BYTES),
    ));
  } catch {
    throw new WrongUnlockKeyError();
  }
}

function importPrivateKey(pkcs8) {
  return subtle().importKey('pkcs8', pkcs8, CURVE, false, ['deriveBits']);
}

/** Creates a new identity. `privateKey` is a non-extractable CryptoKey for this session. */
export async function generateIdentity(unlockKey, { iterations = KDF_ITERATIONS } = {}) {
  assertUnlockKey(unlockKey);
  const pair = await subtle().generateKey(CURVE, true, ['deriveBits']);
  const publicKey = bytesToBase64(new Uint8Array(await subtle().exportKey('raw', pair.publicKey)));
  const pkcs8 = new Uint8Array(await subtle().exportKey('pkcs8', pair.privateKey));
  try {
    const bundle = await wrapPkcs8(pkcs8, unlockKey, iterations);
    const privateKey = await importPrivateKey(pkcs8);
    return { publicKey, ...bundle, privateKey };
  } finally {
    pkcs8.fill(0);
  }
}

/** Opens the wrapped private key from the server. Throws WrongUnlockKeyError on a bad key. */
export async function unlockPrivateKey(bundle, unlockKey, { minIterations = MIN_KDF_ITERATIONS } = {}) {
  const pkcs8 = await openPkcs8(bundle, unlockKey, minIterations);
  try {
    return await importPrivateKey(pkcs8);
  } finally {
    pkcs8.fill(0);
  }
}

/** Re-wraps the same private key under a new unlock key. The public key does not change. */
export async function rewrapKeyBundle(bundle, oldUnlockKey, newUnlockKey, {
  iterations = KDF_ITERATIONS, minIterations = MIN_KDF_ITERATIONS,
} = {}) {
  assertUnlockKey(newUnlockKey);
  const pkcs8 = await openPkcs8(bundle, oldUnlockKey, minIterations);
  try {
    return await wrapPkcs8(pkcs8, newUnlockKey, iterations);
  } finally {
    pkcs8.fill(0);
  }
}

async function conversationKey(privateKey, peerPublicKey) {
  const peer = await subtle().importKey('raw', base64ToBytes(peerPublicKey), CURVE, false, []);
  const secret = await subtle().deriveBits({ name: 'ECDH', public: peer }, privateKey, 256);
  const material = await subtle().importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  return subtle().deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: HKDF_INFO },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

function messageAad(senderId, receiverId) {
  return utf8(`syntrix-msg-v1|${senderId}|${receiverId}`);
}

export async function encryptMessage({ text, privateKey, peerPublicKey, senderId, receiverId }) {
  if (typeof text !== 'string' || text.length === 0) throw new Error('Pesan tidak boleh kosong.');
  const key = await conversationKey(privateKey, peerPublicKey);
  const iv = randomBytes(IV_BYTES);
  const sealed = new Uint8Array(await subtle().encrypt(
    { name: 'AES-GCM', iv, additionalData: messageAad(senderId, receiverId) }, key, utf8(text),
  ));
  return PAYLOAD_PREFIX + bytesToBase64(concat(iv, sealed));
}

export async function decryptMessage({ payload, privateKey, peerPublicKey, senderId, receiverId }) {
  if (typeof payload !== 'string' || !payload.startsWith(PAYLOAD_PREFIX)) {
    throw new Error('Format pesan tidak dikenali.');
  }
  const raw = base64ToBytes(payload.slice(PAYLOAD_PREFIX.length));
  if (raw.length <= IV_BYTES + TAG_BYTES) throw new Error('Format pesan tidak valid.');
  const key = await conversationKey(privateKey, peerPublicKey);
  try {
    const plain = await subtle().decrypt(
      { name: 'AES-GCM', iv: raw.slice(0, IV_BYTES), additionalData: messageAad(senderId, receiverId) },
      key,
      raw.slice(IV_BYTES),
    );
    return new TextDecoder('utf-8', { fatal: true }).decode(plain);
  } catch {
    throw new Error('Pesan tidak dapat didekripsi.');
  }
}
