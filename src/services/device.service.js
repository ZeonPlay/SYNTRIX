import { supabase } from '../core/supabase.js';
import { parseUserAgent } from '../core/useragent.js';

const STORAGE_KEY = 'syntrix-device-id';
let memoryId = null;
let persistentDeviceId = false;

export function getDeviceId() {
  try {
    let id = localStorage.getItem(STORAGE_KEY);
    if (!id || id.length < 8 || id.length > 64) {
      id = crypto.randomUUID();
      localStorage.setItem(STORAGE_KEY, id);
    }
    persistentDeviceId = true;
    return id;
  } catch {
    // Keep the current tab usable, but do not pretend this ID will survive a
    // reload. The UI warns the user that the browser cannot remember this device.
    persistentDeviceId = false;
    memoryId ||= crypto.randomUUID();
    return memoryId;
  }
}

export function hasPersistentDeviceId() {
  return persistentDeviceId;
}

// Details sent with every heartbeat. The browser can only describe itself, so
// these are for display; trust is decided by the owner's "Ini aku" button.
export function collectDeviceInfo() {
  const { label, browser, os, deviceType } = parseUserAgent(navigator.userAgent, {
    maxTouchPoints: navigator.maxTouchPoints || 0,
  });
  let timezone = '';
  try {
    timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
  } catch { /* the time zone is optional */ }
  return {
    label,
    info: { browser, os, device_type: deviceType, language: navigator.language || '', timezone },
  };
}

// Also used as the heartbeat: it refreshes last_seen_at and the approximate
// location, and the server rejects it with "session_revoked" once this session
// has been removed from another device. Resolves to this device's row id.
export async function registerDevice() {
  const { label, info } = collectDeviceInfo();
  const { data, error } = await supabase.rpc('register_device', {
    p_device_id: getDeviceId(),
    p_label: label,
    p_info: info,
  });
  if (error) throw error;
  return data;
}

export function isSessionRevoked(error) {
  return /session_revoked/i.test(String(error?.message ?? '')) || error?.code === 'PT401';
}

// A trusted device receives every active device with IP, location and times.
// An unknown device only receives its own row, so a stolen login can never
// read where the real owner is.
export async function fetchDevices() {
  const { data, error } = await supabase.rpc('list_devices', { p_device_id: getDeviceId() });
  if (error) throw error;
  return data ?? [];
}

export async function acknowledgeDevice(targetId) {
  const { data, error } = await supabase.rpc('acknowledge_device', {
    p_device_id: getDeviceId(),
    p_target: targetId,
  });
  if (error) throw error;
  return data === true;
}

export async function rejectDevice(targetId) {
  const { data, error } = await supabase.rpc('reject_device', {
    p_device_id: getDeviceId(),
    p_target: targetId,
  });
  if (error) throw error;
  // The server revokes the session it knows. A device from before session
  // tracking cannot be matched, so fall back to signing every other session
  // out. A failure here must not hide the result above.
  if (data?.unmapped > 0) {
    const { error: signOutError } = await supabase.auth.signOut({ scope: 'others' });
    if (signOutError) console.warn('Unable to sign out other sessions:', signOutError.message);
  }
  return data;
}
