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
  if (!error) return;

  // If global revocation fails (for example, a stale refresh token or network
  // issue), still clear this browser's persisted session so the user can exit.
  const { error: localError } = await supabase.auth.signOut({ scope: 'local' });
  if (localError) throw error;
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
