import { supabase } from '../core/supabase.js';

const STORAGE_KEY = 'syntrix-device-id';
let memoryId = null;

export function getDeviceId() {
  try {
    let id = localStorage.getItem(STORAGE_KEY);
    if (!id) {
      id = crypto.randomUUID();
      localStorage.setItem(STORAGE_KEY, id);
    }
    return id;
  } catch {
    memoryId ||= crypto.randomUUID();
    return memoryId;
  }
}

export function describeDevice() {
  const ua = navigator.userAgent || '';
  const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera'
    : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome'
      : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Android/.test(ua) ? 'Android' : /iPhone|iPad|iPod/.test(ua) ? 'iOS'
    : /Windows/.test(ua) ? 'Windows' : /Mac OS X/.test(ua) ? 'macOS'
      : /Linux/.test(ua) ? 'Linux' : 'Perangkat lain';
  return `${browser} · ${os}`;
}

// Also used as the heartbeat: it refreshes last_seen_at and the approximate
// location, and the server rejects it with "session_revoked" once this session
// has been removed from another device.
export async function registerDevice() {
  const { data, error } = await supabase.rpc('register_device', {
    p_device_id: getDeviceId(),
    p_label: describeDevice(),
  });
  if (error) throw error;
  return data;
}

export function isSessionRevoked(error) {
  return /session_revoked/i.test(String(error?.message ?? ''));
}

// Only a trusted (acknowledged) device sees alerts about newer devices. The
// server returns location and times only to a trusted device, so an unknown
// session can never read where the real owner is.
export async function fetchDeviceAlerts() {
  const { data, error } = await supabase.rpc('list_pending_devices', {
    p_device_id: getDeviceId(),
  });
  if (error) throw error;
  return data ?? [];
}

export async function acknowledgeDevices() {
  const { error } = await supabase.rpc('acknowledge_devices', { p_device_id: getDeviceId() });
  if (error) throw error;
}

export async function rejectDevices() {
  const { data, error } = await supabase.rpc('reject_devices', { p_device_id: getDeviceId() });
  if (error) throw error;
  // The server revokes the sessions of the devices it knows. Unknown devices
  // from before session tracking cannot be matched, so fall back to signing
  // every other session out. A failure here must not hide the result above.
  if (data?.unmapped > 0) {
    const { error: signOutError } = await supabase.auth.signOut({ scope: 'others' });
    if (signOutError) console.warn('Unable to sign out other sessions:', signOutError.message);
  }
  return data;
}
