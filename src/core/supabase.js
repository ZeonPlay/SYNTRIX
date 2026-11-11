import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.119.0?bundle';
import { SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY } from '../config.js';

if (!SUPABASE_URL || !SUPABASE_PUBLISHABLE_KEY) {
  throw new Error('Konfigurasi Supabase belum diisi. Periksa src/config.js.');
}

export const supabase = createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
  auth: {
    autoRefreshToken: true,
    persistSession: true,
    detectSessionInUrl: true,
  },
  realtime: {
    params: { eventsPerSecond: 8 },
  },
});
