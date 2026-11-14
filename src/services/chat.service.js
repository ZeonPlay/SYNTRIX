import { supabase } from '../core/supabase.js';
import { MAX_PAYLOAD_LENGTH, textToBitStream } from '../core/encoding.js';

const PROFILE_FIELDS = 'id, handle, display_name, public_key';
// payload_bits only ever holds ciphertext (end-to-end encrypted in the browser).
const MESSAGE_FIELDS = 'id, sender_id, receiver_id, payload_bits, frame_count, created_at, read_at';
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function assertUuid(value) {
  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) {
    throw new Error('Identitas pengguna tidak valid.');
  }
  return value;
}

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
  const { data, error } = await supabase.rpc('find_profile_by_handle', { p_handle: normalized });
  if (error) throw error;
  return data?.[0] ?? null;
}

export async function saveContact(ownerId, contactId) {
  const { error } = await supabase
    .from('contacts')
    .insert({ owner_id: ownerId, contact_id: contactId });
  // A repeated add is harmless; the primary key protects duplicates.
  if (error && error.code !== '23505') throw error;
}

export async function listRecentMessages(userId) {
  assertUuid(userId);
  const { data, error } = await supabase
    .from('messages')
    .select(MESSAGE_FIELDS)
    .or(`sender_id.eq.${userId},receiver_id.eq.${userId}`)
    .order('created_at', { ascending: false })
    .limit(1000);
  if (error) throw error;
  return (data ?? []).reverse();
}

export async function listConversation(userId, partnerId) {
  assertUuid(userId);
  assertUuid(partnerId);
  const { data, error } = await supabase
    .from('messages')
    .select(MESSAGE_FIELDS)
    .or(`and(sender_id.eq.${userId},receiver_id.eq.${partnerId}),and(sender_id.eq.${partnerId},receiver_id.eq.${userId})`)
    .order('created_at', { ascending: false })
    .limit(300);
  if (error) throw error;
  return (data ?? []).reverse();
}

export async function fetchMessageMeta(messageId) {
  const { data, error } = await supabase
    .from('messages')
    .select(MESSAGE_FIELDS)
    .eq('id', messageId)
    .maybeSingle();
  if (error) throw error;
  return data;
}

/** `payload` is the encrypted string from encryptMessage(), not the plain text. */
export async function insertMessage(senderId, receiverId, payload) {
  const payloadBits = textToBitStream(payload, { maxLength: MAX_PAYLOAD_LENGTH });
  const { data, error } = await supabase
    .from('messages')
    .insert({ sender_id: senderId, receiver_id: receiverId, payload_bits: payloadBits })
    .select(MESSAGE_FIELDS)
    .single();
  if (error) throw error;
  return data;
}

/** Deletes a message for both participants. Returns false when nothing was deleted. */
export async function deleteMessage(messageId) {
  const { data, error } = await supabase
    .from('messages')
    .delete()
    .eq('id', messageId)
    .select('id');
  if (error) throw error;
  return (data ?? []).length > 0;
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