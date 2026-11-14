import { supabase } from '../core/supabase.js';
import {
  createE2eeIdentity,
  decryptE2eePayload,
  encryptE2eePayload,
  rewrapE2eePrivateKey,
  unlockE2eePrivateKey,
} from '../core/e2ee-crypto.js';

function firstBundle(data) {
  return Array.isArray(data) ? data[0] ?? null : data ?? null;
}

export async function getE2eeState() {
  const { data, error } = await supabase.rpc('get_my_key_bundle');
  if (error) throw error;
  const bundle = firstBundle(data);
  return {
    enabled: Boolean(bundle?.wrapped_private_key && bundle?.public_key),
    has_legacy_key: false,
    salt: bundle?.kdf_salt ?? null,
    iterations: bundle?.kdf_iterations ?? null,
    public_key: bundle?.public_key ?? null,
    wrapped_private_key: bundle?.wrapped_private_key ?? null,
  };
}

export async function enableE2ee(_oldUnlockKey, passphrase) {
  const identity = await createE2eeIdentity(passphrase);
  const { error } = await supabase.rpc('set_my_key_bundle', {
    p_public_key: identity.publicKeyB64,
    p_wrapped: identity.wrappedKeyB64,
    p_salt: identity.saltB64,
    p_iterations: identity.iterations,
  });
  if (error) throw error;
  return {
    privateKey: identity.privateKey,
    publicKeyB64: identity.publicKeyB64,
    wrappedKeyB64: identity.wrappedKeyB64,
  };
}

export async function unlockE2ee(passphrase) {
  const { data, error } = await supabase.rpc('get_my_key_bundle');
  if (error) throw error;
  const bundle = firstBundle(data);
  if (!bundle?.wrapped_private_key || !bundle?.public_key) {
    throw new Error('E2EE belum diaktifkan pada akun ini.');
  }
  const opened = await unlockE2eePrivateKey(
    passphrase,
    bundle.kdf_salt,
    bundle.kdf_iterations,
    bundle.wrapped_private_key,
  );
  return {
    privateKey: opened.privateKey,
    publicKeyB64: bundle.public_key,
    wrappedKeyB64: bundle.wrapped_private_key,
  };
}

export async function changeE2eePassphrase(session, _oldPassphrase, newPassphrase) {
  if (!session?.privateKey || !session?.wrappedKeyB64) {
    throw new Error('Buka E2EE terlebih dahulu sebelum mengganti passphrase.');
  }
  const wrapped = await rewrapE2eePrivateKey(session.privateKey, newPassphrase);
  const { data, error } = await supabase.rpc('rewrap_my_key_bundle', {
    p_old_wrapped: session.wrappedKeyB64,
    p_wrapped: wrapped.wrappedKeyB64,
    p_salt: wrapped.saltB64,
    p_iterations: wrapped.iterations,
  });
  if (error) throw error;
  if (data !== true) throw new Error('Backup private key berubah. Buka ulang E2EE sebelum mengganti passphrase.');
  return {
    ...session,
    wrappedKeyB64: wrapped.wrappedKeyB64,
  };
}

export { encryptE2eePayload, decryptE2eePayload };
