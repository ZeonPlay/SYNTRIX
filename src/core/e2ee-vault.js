const DB_NAME = 'syntrix-local-vault';
const STORE_NAME = 'e2ee-keys';
const DB_VERSION = 1;
// An unlocked key left in this browser expires; after that the passphrase is asked again.
const MAX_VAULT_AGE_MS = 7 * 24 * 60 * 60 * 1000;

function openVault() {
  return new Promise((resolve, reject) => {
    if (!globalThis.indexedDB) {
      reject(new Error('IndexedDB tidak tersedia di browser ini.'));
      return;
    }
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'userId' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('Gagal membuka penyimpanan lokal.'));
    request.onblocked = () => reject(new Error('Penyimpanan lokal sedang diblokir tab lain.'));
  });
}

export async function saveE2eeVault(userId, session) {
  if (!userId || !session?.privateKey || !session?.publicKeyB64) {
    throw new Error('Sesi private key tidak lengkap.');
  }
  const db = await openVault();
  try {
    await new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite');
      transaction.objectStore(STORE_NAME).put({
        userId,
        privateKey: session.privateKey,
        publicKeyB64: session.publicKeyB64,
        wrappedKeyB64: session.wrappedKeyB64 ?? null,
        savedAt: Date.now(),
      });
      transaction.oncomplete = resolve;
      transaction.onerror = () => reject(transaction.error || new Error('Gagal menyimpan private key lokal.'));
      transaction.onabort = () => reject(transaction.error || new Error('Penyimpanan private key dibatalkan.'));
    });
  } finally {
    db.close();
  }
}

export async function getE2eeVault(userId, expectedPublicKeyB64) {
  if (!userId || !expectedPublicKeyB64) return null;
  const db = await openVault();
  try {
    const record = await new Promise((resolve, reject) => {
      const request = db.transaction(STORE_NAME, 'readonly')
        .objectStore(STORE_NAME)
        .get(userId);
      request.onsuccess = () => resolve(request.result ?? null);
      request.onerror = () => reject(request.error || new Error('Gagal membaca private key lokal.'));
    });
    if (
      !record?.privateKey
      || record.publicKeyB64 !== expectedPublicKeyB64
      || record.privateKey.type !== 'private'
      || record.privateKey.algorithm?.name !== 'ECDH'
      || !Number.isFinite(record.savedAt)
      || Date.now() - record.savedAt > MAX_VAULT_AGE_MS
    ) return null;
    return {
      privateKey: record.privateKey,
      publicKeyB64: record.publicKeyB64,
      wrappedKeyB64: record.wrappedKeyB64,
    };
  } finally {
    db.close();
  }
}

export async function clearE2eeVault(userId) {
  if (!userId || !globalThis.indexedDB) return;
  const db = await openVault();
  try {
    await new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite');
      transaction.objectStore(STORE_NAME).delete(userId);
      transaction.oncomplete = resolve;
      transaction.onerror = () => reject(transaction.error || new Error('Gagal menghapus private key lokal.'));
      transaction.onabort = () => reject(transaction.error || new Error('Penghapusan private key lokal dibatalkan.'));
    });
  } finally {
    db.close();
  }
}
