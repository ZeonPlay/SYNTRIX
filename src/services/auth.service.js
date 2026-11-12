import { supabase } from '../core/supabase.js';

export async function signUp({ email, password, handle, displayName }) {
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: {
      data: {
        handle: handle.trim().toLowerCase(),
        display_name: displayName.trim(),
      },
    },
  });
  if (error) throw error;
  return data;
}

export async function signIn(email, password) {
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) throw error;
  return data;
}

export async function signOut() {
  const { error } = await supabase.auth.signOut();
  if (error) throw error;
}

export async function getProfile(userId) {
  const { data, error } = await supabase
    .from('profiles')
    .select('id, handle, display_name, created_at')
    .eq('id', userId)
    .single();
  if (error) throw error;
  return data;
}

export async function hasUnlockKey() {
  const { data, error } = await supabase.rpc('has_message_unlock_key');
  if (error) throw error;
  return data === true;
}

export async function setUnlockKey(key) {
  const { error } = await supabase.rpc('set_message_unlock_key', { p_key: key });
  if (error) throw error;
}

export async function changeUnlockKey(oldKey, newKey) {
  const { data, error } = await supabase.rpc('change_message_unlock_key', {
    p_old_key: oldKey,
    p_new_key: newKey,
  });
  if (error) throw error;
  return data === true;
}

export async function verifyUnlockKey(key) {
  const { data, error } = await supabase.rpc('verify_message_unlock_key', { p_key: key });
  if (error) throw error;
  return data === true;
}