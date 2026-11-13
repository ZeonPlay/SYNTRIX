import { supabase } from '../core/supabase.js';

export function connectRealtime({ userId, onMessage, onMessageUpdate, onPresence, onStatus, onDevice }) {
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
      event: '*', schema: 'public', table: 'user_devices', filter: `user_id=eq.${userId}`,
    }, () => onDevice?.())
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