import { supabase } from '../core/supabase.js';
import { textToBitStream } from '../core/encoding.js';

const PROFILE_FIELDS = 'id, handle, display_name';

export async function listContactIds(userId) {
  const { data, error } = await supabase
    .from('contacts')
    .select('contact_id')
    .eq('owner_id', userId)
    .order('created_at', { ascending: false });
  if (error) throw error;
  return (data ?? []).map((row) => row.contact_id);
}

export async function getProfilesByIds(ids) {
  const uniqueIds = [...new Set(ids)].filter(Boolean);
  if (uniqueIds.length === 0) return [];
  const { data, error } = await supabase
    .from('profiles')
    .select(PROFILE_FIELDS)
    .in('id', uniqueIds);
  if (error) throw error;
  return data ?? [];
}

export async function findProfileByHandle(handle) {
  const normalized = handle.trim().replace(/^@/, '').toLowerCase();
  const { data, error } = await supabase
    .from('profiles')
    .select(PROFILE_FIELDS)
    .eq('handle', normalized)
    .maybeSingle();
  if (error) throw error;
  return data;
}

export async function saveContact(ownerId, contactId) {
  const { error } = await supabase
    .from('contacts')
    .insert({ owner_id: ownerId, contact_id: contactId });
  // A repeated add is harmless; the primary key protects duplicates.
  if (error && error.code !== '23505') throw error;
}

export async function listRecentMessages(userId) {
  const { data, error } = await supabase
    .from('messages')
    .select('id, sender_id, receiver_id, payload_bits, created_at, read_at')
    .or(`sender_id.eq.${userId},receiver_id.eq.${userId}`)
    .order('created_at', { ascending: false })
    .limit(1000);
  if (error) throw error;
  return (data ?? []).reverse();
}

export async function listConversation(userId, partnerId) {
  const { data, error } = await supabase
    .from('messages')
    .select('id, sender_id, receiver_id, payload_bits, created_at, read_at')
    .or(`and(sender_id.eq.${userId},receiver_id.eq.${partnerId}),and(sender_id.eq.${partnerId},receiver_id.eq.${userId})`)
    .order('created_at', { ascending: false })
    .limit(300);
  if (error) throw error;
  return (data ?? []).reverse();
}

export async function insertMessage(senderId, receiverId, text) {
  const payloadBits = textToBitStream(text);
  const { data, error } = await supabase
    .from('messages')
    .insert({ sender_id: senderId, receiver_id: receiverId, payload_bits: payloadBits })
    .select('id, sender_id, receiver_id, payload_bits, created_at, read_at')
    .single();
  if (error) throw error;
  return data;
}

export async function markConversationRead(userId, partnerId) {
  const { error } = await supabase
    .from('messages')
    .update({ read_at: new Date().toISOString() })
    .eq('sender_id', partnerId)
    .eq('receiver_id', userId)
    .is('read_at', null);
  if (error) throw error;
}
