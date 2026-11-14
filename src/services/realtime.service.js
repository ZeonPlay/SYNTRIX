import { supabase } from '../core/supabase.js';

export function connectRealtime({ userId, onMessage, onMessageUpdate, onMessageDelete, onPresence, onStatus, onDevice }) {
  const channel = supabase
    .channel('syntrix:live', {
      config: {
        private: true,
        presence: { key: userId },
      },
    })
    .on('postgres_changes', {
      event: 'INSERT', schema: 'public', table: 'messages',
    }, (payload) => onMessage?.(payload.new))
    .on('postgres_changes', {
      event: 'UPDATE', schema: 'public', table: 'messages',
    }, (payload) => onMessageUpdate?.(payload.new))
    .on('postgres_changes', {
      event: 'DELETE', schema: 'public', table: 'messages',
      filter: 'sender_id=eq.' + userId,
    }, (payload) => onMessageDelete?.(payload.old?.id))
    .on('postgres_changes', {
      event: 'DELETE', schema: 'public', table: 'messages',
      filter: 'receiver_id=eq.' + userId,
    }, (payload) => onMessageDelete?.(payload.old?.id))
    // Supabase cannot filter DELETE events, so devices are never deleted when
    // rejected: they get revoked_at, which arrives here as an UPDATE.
    .on('postgres_changes', {
      event: 'INSERT', schema: 'public', table: 'user_devices', filter: `user_id=eq.${userId}`,
    }, (payload) => onDevice?.({ type: 'INSERT', row: payload.new }))
    .on('postgres_changes', {
      event: 'UPDATE', schema: 'public', table: 'user_devices', filter: `user_id=eq.${userId}`,
    }, (payload) => onDevice?.({ type: 'UPDATE', row: payload.new }))
    .on('presence', { event: 'sync' }, () => {
      const snapshot = channel.presenceState();
      const users = Object.values(snapshot).flat().map((entry) => ({
        userId: entry.user_id,
        handle: entry.handle,
      })).filter((entry) => entry.userId);
      onPresence?.(users);
    })
    .subscribe(async (status) => {
      onStatus?.(status);
      if (status === 'SUBSCRIBED') {
        // Only the user id is shared; handle and timestamps stay out of Presence.
        const { error } = await channel.track({ user_id: userId });
        if (error) console.error('Presence tracking failed:', error.message);
      }
    });

  return async () => {
    await supabase.removeChannel(channel);
  };
}