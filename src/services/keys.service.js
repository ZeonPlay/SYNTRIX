import { supabase } from '../core/supabase.js';

/**
 * The server stores each user's public key and a wrapped (encrypted) copy of
 * their private key. It never sees the unlock key or the unwrapped private key.
 */

export async function fetchKeyBundle() {
  const { data, error } = await supabase.rpc('get_my_key_bundle');
  if (error) throw error;
  const row = data?.[0];
  if (!row) return null;
  return {
    publicKey: row.public_key,
    wrappedPrivateKey: row.wrapped_private_key,
    kdfSalt: row.kdf_salt,
    kdfIterations: row.kdf_iterations,
  };
}

function bundleParams(bundle) {
  return {
    p_public_key: bundle.publicKey,
    p_wrapped: bundle.wrappedPrivateKey,
    p_salt: bundle.kdfSalt,
    p_iterations: bundle.kdfIterations,
  };
}

/** First-time setup only. */
export async function saveKeyBundle(bundle) {
  const { error } = await supabase.rpc('set_my_key_bundle', bundleParams(bundle));
  if (error) throw error;
}

/** Same key pair, new unlock key. Returns false when the stored copy changed in the meantime. */
export async function replaceWrappedKey(previousWrapped, next) {
  const { data, error } = await supabase.rpc('rewrap_my_key_bundle', {
    p_old_wrapped: previousWrapped,
    p_wrapped: next.wrappedPrivateKey,
    p_salt: next.kdfSalt,
    p_iterations: next.kdfIterations,
  });
  if (error) throw error;
  return data === true;
}

/** New key pair. Deletes every message this user sent or received. */
export async function resetKeyBundle(bundle) {
  const { error } = await supabase.rpc('reset_my_key_bundle', bundleParams(bundle));
  if (error) throw error;
}
