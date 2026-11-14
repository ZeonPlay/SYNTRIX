import { supabase } from '../core/supabase.js';
import {
  createE2eeIdentity,
  decryptE2eePayload,
  deriveE2eeAuthToken,
  encryptE2eePayload,
  rewrapE2eePrivateKey,
  unlockE2eePrivateKey,
} from '../core/e2ee-crypto.js';

export async function getE2eeState() {
  const { data, error } = await supabase.rpc('get_e2ee_state');
  if (error) throw error;
  const state = Array.isArray(data) ? data[0] : data;
  if (!state) throw new Error('Status E2EE akun tidak ditemukan.');
  return state;
}

export async function enableE2ee(oldUnlockKey, passphrase) {
  const identity = await createE2eeIdentity(passphrase);
  const { data, error } = await supabase.rpc('enable_e2ee', {
    p_old_key: oldUnlockKey || null,
    p_auth: identity.authToken,
    p_public_key: identity.publicKeyB64,
    p_wrapped: identity.wrappedKeyB64,
    p_salt: identity.saltB64,
    p_iterations: identity.iterations,
  });
  if (error) throw error;
  if (data !== true) throw new Error('Kunci pembuka lama salah. Aktivasi E2EE dibatalkan.');
  return {
    privateKey: identity.privateKey,
    publicKeyB64: identity.publicKeyB64,
    authToken: identity.authToken,
    wrappedKeyB64: identity.wrappedKeyB64,
  };
}

export async function unlockE2ee(passphrase, e2eeState) {
  if (!e2eeState?.enabled || !e2eeState.salt || !e2eeState.public_key) {
    throw new Error('E2EE belum diaktifkan pada akun ini.');
  }
  const authToken = await deriveE2eeAuthToken(passphrase, e2eeState.salt, e2eeState.iterations);
  const { data, error } = await supabase.rpc('get_e2ee_backup', { p_auth: authToken });
  if (error) throw error;
  if (!data) throw new Error('Passphrase salah atau akses backup private key ditolak.');
  const opened = await unlockE2eePrivateKey(
    passphrase,
    e2eeState.salt,
    e2eeState.iterations,
    data,
  );
  return {
    privateKey: opened.privateKey,
    publicKeyB64: e2eeState.public_key,
    authToken: opened.authToken,
    wrappedKeyB64: data,
  };
}

export async function changeE2eePassphrase(session, oldPassphrase, newPassphrase, e2eeState) {
  if (!session?.privateKey) throw new Error('Buka E2EE terlebih dahulu sebelum mengganti passphrase.');
  const oldAuth = await deriveE2eeAuthToken(oldPassphrase, e2eeState.salt, e2eeState.iterations);
  const wrapped = await rewrapE2eePrivateKey(session.privateKey, newPassphrase);
  const { data, error } = await supabase.rpc('change_e2ee_passphrase', {
    p_old_auth: oldAuth,
    p_new_auth: wrapped.authToken,
    p_new_wrapped: wrapped.wrappedKeyB64,
    p_new_salt: wrapped.saltB64,
    p_iterations: wrapped.iterations,
  });
  if (error) throw error;
  if (data !== true) throw new Error('Passphrase lama salah.');
  return {
    ...session,
    authToken: wrapped.authToken,
    wrappedKeyB64: wrapped.wrappedKeyB64,
  };
}

export { encryptE2eePayload, decryptE2eePayload };
