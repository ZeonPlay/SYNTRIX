import { supabase } from '../core/supabase.js';

const STORAGE_KEY = 'syntrix-device-id';
let memoryId = null;
let ownRowId = null;

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

export async function registerDevice() {
  const { data, error } = await supabase.rpc('register_device', {
    p_device_id: getDeviceId(),
    p_label: describeDevice(),
  });
  if (error) throw error;
  ownRowId = data;
  return data;
}

// Only a trusted (acknowledged) device sees alerts about newer devices.
export async function fetchDeviceAlerts() {
  const { data, error } = await supabase
    .from('user_devices')
    .select('id,label,first_seen_at,acknowledged_at')
    .order('first_seen_at', { ascending: false });
  if (error) throw error;
  const own = data.find((row) => row.id === ownRowId);
  if (!own?.acknowledged_at) return [];
  return data.filter((row) => !row.acknowledged_at && row.id !== ownRowId);
}

export async function acknowledgeDevices() {
  const { error } = await supabase.rpc('acknowledge_devices', { p_device_id: getDeviceId() });
  if (error) throw error;
}

export async function rejectDevices() {
  const { error } = await supabase.rpc('reject_devices', { p_device_id: getDeviceId() });
  if (error) throw error;
  const { error: signOutError } = await supabase.auth.signOut({ scope: 'others' });
  if (signOutError) throw signOutError;
}
