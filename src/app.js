import { supabase } from './core/supabase.js';
import {
  decodeBitStream, nrziEncode, summarizeFrames,
  validateBitStream, MAX_MESSAGE_LENGTH,
} from './core/encoding.js';
import {
  $, escapeHTML, formatTime, initials, openDialog, closeDialog, setBusy, showToast,
} from './core/dom.js';
import {
  getProfile, signIn, signOut, signUp,
} from './services/auth.service.js';
import {
  deleteMessageForEveryone, fetchMessageMeta, fetchMessagePayloads,
  findProfileByHandle, getProfilesByIds, insertMessage, listContactIds,
  listRecentMessages, markConversationRead, saveContact,
} from './services/chat.service.js';
import { connectRealtime } from './services/realtime.service.js';
import { clearE2eeVault, getE2eeVault, saveE2eeVault } from './core/e2ee-vault.js';
import {
  changeE2eePassphrase, decryptE2eePayload, enableE2ee, encryptE2eePayload,
  getE2eeState, unlockE2ee,
} from './services/e2ee.service.js';
import {
  acknowledgeDevice, fetchDevices, hasPersistentDeviceId, isSessionRevoked, registerDevice, rejectDevice,
} from './services/device.service.js';

const state = {
  user: null, profile: null, contacts: [], messages: [], activeContactId: null,
  onlineUsers: new Set(), disconnectRealtime: null, decodedMessages: new Map(), bitsByMessage: new Map(),
  messageViewModes: new Map(), bootingUserId: null, sending: false,
  e2eeState: null, e2eeSession: null, e2eeUnlocked: false, deletingMessageIds: new Set(),
  deviceRowId: null, knownPendingIds: null, endingSession: false,
  workspaceLoaded: false, workspaceLoading: false,
};

const THEME_STORAGE_KEY = 'syntrix-theme';
const themeToggle = $('#themeToggle');
const themeModeLabel = $('#themeModeLabel');
const themeRoot = document.documentElement;

function readSavedTheme() {
  try {
    return localStorage.getItem(THEME_STORAGE_KEY) === 'dark' ? 'dark' : 'light';
  } catch {
    return 'light';
  }
}

const initialTheme = readSavedTheme();
themeRoot.dataset.theme = initialTheme;
themeRoot.style.colorScheme = initialTheme;

function syncThemeControl(theme) {
  if (themeToggle) themeToggle.checked = theme === 'dark';
  if (themeModeLabel) themeModeLabel.textContent = theme === 'dark' ? 'Dark' : 'Light';
}

function applyTheme(theme) {
  const nextTheme = theme === 'dark' ? 'dark' : 'light';
  const currentTheme = themeRoot.dataset.theme === 'dark' ? 'dark' : 'light';
  if (nextTheme === currentTheme) {
    syncThemeControl(currentTheme);
    return;
  }

  // Persist before starting the visual transition so an immediate reload
  // cannot restore the previous theme while the animation is still running.
  try {
    localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
  } catch (error) {
    console.warn('Unable to persist theme preference:', error.message);
  }

  const updateTheme = () => {
    themeRoot.dataset.theme = nextTheme;
    themeRoot.style.colorScheme = nextTheme;
    syncThemeControl(nextTheme);
  };

  const canAnimate = typeof document.startViewTransition === 'function'
    && !window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  if (canAnimate) {
    try {
      // Keep the outgoing snapshot aligned with the currently selected switch state.
      if (themeToggle) themeToggle.checked = currentTheme === 'dark';
      const transition = document.startViewTransition(updateTheme);
      transition.finished.then(() => {}, () => {});
      return;
    } catch (error) {
      console.warn('Theme transition unavailable; applying theme directly:', error.message);
    }
  }

  updateTheme();
}

syncThemeControl(initialTheme);
themeToggle?.addEventListener('change', () => {
  applyTheme(themeToggle.checked ? 'dark' : 'light');
});

const authView = $('#authView');
const appView = $('#appView');
const deviceGateView = $('#deviceGateView');
const loginForm = $('#loginForm');
const registerForm = $('#registerForm');
const contactDialog = $('#contactDialog');
const e2eeUnlockDialog = $('#e2eeUnlockDialog');
const messageUnlockDialog = $('#messageUnlockDialog');
const keyDialog = $('#keyDialog');
const inspectorDialog = $('#inspectorDialog');
const navRail = $('#navRail');
const navItems = navRail.querySelector('.nav-items');
const navActivePill = navRail.querySelector('.nav-active-pill');

function updateNavActivePill() {
  const active = navRail.querySelector('.nav-item[data-view].is-active');
  if (!active || !navActivePill) return;

  if (window.innerWidth <= 700) {
    navActivePill.style.width = `${active.offsetWidth}px`;
    navActivePill.style.height = `${active.offsetHeight}px`;
    navActivePill.style.transform = `translateX(${active.offsetLeft}px)`;
  } else {
    navActivePill.style.width = '';
    navActivePill.style.height = `${active.offsetHeight}px`;
    navActivePill.style.transform = `translateY(${active.offsetTop}px)`;
  }
}

function setAppView(view) {
  const allowedViews = ['contacts', 'security', 'settings'];
  if (!allowedViews.includes(view)) return;

  appView.dataset.view = view;
  // Returning to Contacts always restores the expanded directory stage.
  appView.classList.remove('has-chat');

  navRail.querySelectorAll('.nav-item[data-view]').forEach((button) => {
    const active = button.dataset.view === view;
    button.classList.toggle('is-active', active);
    if (active) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  });

  window.requestAnimationFrame(updateNavActivePill);
}

navRail.querySelectorAll('.nav-item[data-view]').forEach((button) => {
  button.addEventListener('click', () => setAppView(button.dataset.view));
});
window.addEventListener('resize', updateNavActivePill);
window.requestAnimationFrame(updateNavActivePill);

function setAuthMode(mode) {
  const isRegister = mode === 'register';
  loginForm.hidden = isRegister;
  registerForm.hidden = !isRegister;
  $('#showLoginBtn').classList.toggle('is-active', !isRegister);
  $('#showRegisterBtn').classList.toggle('is-active', isRegister);
  $('#showLoginBtn').setAttribute('aria-selected', String(!isRegister));
  $('#showRegisterBtn').setAttribute('aria-selected', String(isRegister));
  $('#authTitle').textContent = isRegister ? 'Create your SYNTRIX identity' : 'Sign in to your space';
  $('#authSubtitle').textContent = isRegister
    ? 'Choose a handle your friends can use to find you.'
    : 'Continue where your conversations left off.';
}

$('#showLoginBtn').addEventListener('click', () => setAuthMode('login'));
$('#showRegisterBtn').addEventListener('click', () => setAuthMode('register'));

function friendlyError(error, fallback = 'Something went wrong. Please try again.') {
  const message = String(error?.message ?? '');
  if (/invalid login credentials/i.test(message)) return 'Email atau password tidak cocok.';
  if (/email not confirmed/i.test(message)) return 'Email belum dikonfirmasi. Periksa kotak masuk email kamu.';
  if (/user already registered/i.test(message)) return 'Email ini sudah terdaftar. Silakan masuk.';
  if (/duplicate key|unique constraint|profiles_handle_key/i.test(message)) return 'Handle tersebut sudah digunakan. Pilih handle lain.';
  if (/rate[ _]?limit/i.test(message)) return 'Terlalu banyak percobaan. Coba lagi nanti.';
  if (/database error saving new user/i.test(message)) return 'Pendaftaran gagal. Coba handle lain.';
  if (/failed to fetch|networkerror|load failed/i.test(message)) return 'Tidak dapat terhubung ke server. Periksa internet dan konfigurasi Supabase.';
  if (/row-level security|permission denied/i.test(message)) return 'Akses database ditolak. Periksa migration dan kebijakan RLS Supabase.';
  if (/device_not_trusted/i.test(message)) return 'Perangkat ini belum dikonfirmasi sebagai milikmu, jadi belum bisa mengelola perangkat lain.';
  if (/device_not_approved/i.test(message)) return 'Perangkat ini belum disetujui. Tunggu konfirmasi dari perangkat yang sudah dikenal.';
  if (/device_identity_mismatch/i.test(message)) return 'Identitas perangkat berubah. Keluar, lalu masuk kembali dari browser ini.';
  if (/session_revoked/i.test(message)) return 'Sesi ini sudah dikeluarkan dari perangkat lain.';
  if (/device_limit/i.test(message)) return 'Terlalu banyak perangkat tercatat di akun ini. Keluarkan perangkat yang tidak dipakai.';
  if (/cannot_reject_self/i.test(message)) return 'Perangkat yang sedang kamu pakai tidak bisa dikeluarkan dari sini. Gunakan tombol Keluar.';
  if (/e2ee_required/i.test(message)) return 'Pesan harus dienkripsi. Aktifkan dan buka E2EE terlebih dahulu.';
  if (/e2ee_not_ready/i.test(message)) return 'Kontak ini belum mengaktifkan E2EE. Minta kontak mengaktifkannya sebelum mengirim pesan.';
  if (/e2ee_not_enabled/i.test(message)) return 'E2EE belum diaktifkan di akun ini.';
  if (/message_not_found/i.test(message)) return 'Pesan sudah dihapus dari percakapan.';
  console.warn('Unhandled error:', error);
  return fallback;
}

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#loginSubmit');
  setBusy(button, true, 'Signing in...');
  try {
    await signIn($('#loginEmail').value.trim(), $('#loginPassword').value);
    showToast('Berhasil masuk. Menyiapkan ruang chat...', 'success');
  } catch (error) {
    showToast(friendlyError(error, 'Login gagal.'), 'error');
  } finally {
    setBusy(button, false);
  }
});

registerForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#registerSubmit');
  const handle = $('#registerHandle').value.trim().toLowerCase();
  const displayName = $('#registerName').value.trim();
  const email = $('#registerEmail').value.trim();
  const password = $('#registerPassword').value;

  if (!/^[a-z0-9_]{3,24}$/.test(handle)) {
    showToast('Handle harus 3–24 karakter: huruf, angka, atau underscore.', 'error');
    return;
  }
  if (displayName.length < 1 || displayName.length > 60) {
    showToast('Nama tampilan harus berisi 1–60 karakter.', 'error');
    return;
  }

  setBusy(button, true, 'Creating account...');
  try {
    const data = await signUp({ email, password, handle, displayName });
    registerForm.reset();
    setAuthMode('login');
    showToast(data.session
      ? 'Akun berhasil dibuat.'
      : 'Akun dibuat. Periksa email untuk mengonfirmasi alamat email sebelum masuk.',
    'success');
  } catch (error) {
    showToast(friendlyError(error, 'Registrasi gagal.'), 'error');
  } finally {
    setBusy(button, false);
  }
});

function setConnection(status) {
  const dot = $('#connectionDot');
  const label = $('#connectionLabel');
  // Sidebar connection status is optional; the indicator is no longer rendered.
  if (!dot || !label) return;
  dot.classList.remove('connected', 'disconnected');
  if (status === 'SUBSCRIBED') {
    dot.classList.add('connected');
    label.textContent = 'Live connection';
  } else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT' || status === 'CLOSED') {
    dot.classList.add('disconnected');
    label.textContent = 'Realtime unavailable';
  } else {
    label.textContent = 'Connecting…';
  }
}

function partnerId(message, userId = state.user?.id) {
  return message.sender_id === userId ? message.receiver_id : message.sender_id;
}

function latestMessageFor(contactId) {
  for (let i = state.messages.length - 1; i >= 0; i -= 1) {
    const message = state.messages[i];
    if (
      (message.sender_id === state.user.id && message.receiver_id === contactId) ||
      (message.sender_id === contactId && message.receiver_id === state.user.id)
    ) return message;
  }
  return null;
}

function unreadCountFor(contactId) {
  return state.messages.filter((message) =>
    message.sender_id === contactId &&
    message.receiver_id === state.user.id &&
    !message.read_at
  ).length;
}

function normalizeContacts(profiles) {
  const seen = new Set();
  state.contacts = profiles
    .filter((profile) => profile && profile.id !== state.user.id && !seen.has(profile.id) && seen.add(profile.id))
    .map((profile) => ({
      id: profile.id, handle: profile.handle, display_name: profile.display_name,
      public_key: profile.public_key ?? null,
    }));
}

function avatarHueFor(identifier) {
  return [...String(identifier || '')]
    .reduce((sum, character) => sum + character.charCodeAt(0), 0) % 360;
}

function sortMessages() {
  state.messages.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
}

function renderAccount() {
  const name = state.profile?.display_name || 'SYNTRIX User';
  const handle = state.profile?.handle || 'user';
  $('#myName').textContent = name;
  $('#myHandle').textContent = `@${handle}`;
  $('#myAvatar').textContent = initials(name);
  $('#settingsName').textContent = name;
  $('#settingsHandle').textContent = `@${handle}`;
  const settingsAvatar = $('#settingsAvatar');
  settingsAvatar.textContent = initials(name);
  settingsAvatar.style.setProperty('--avatar-hue', avatarHueFor(state.user?.id || state.profile?.id || name));
}

function renderKeyStatus() {
  const status = $('#keyStatus');
  if (!status) return;
  if (!state.e2eeState?.enabled) {
    status.textContent = 'Belum aktif. Aktifkan E2EE untuk mulai mengirim pesan.';
  } else if (state.e2eeUnlocked) {
    status.textContent = 'Aktif dan terbuka di perangkat ini. Private key tetap terenkripsi di server.';
  } else {
    status.textContent = 'Aktif, tetapi terkunci di perangkat ini. Buka dengan passphrase E2EE.';
  }
}

function contactPreview(contactId) {
  const message = latestMessageFor(contactId);
  if (!message) return 'Start a conversation';
  const decoded = state.decodedMessages.get(message.id);
  if (decoded) return decoded;
  return `🔒 Encoded transmission · ${message.frame_count} frames`;
}

function createContactItem(contact) {
  const item = document.createElement('button');
  item.type = 'button';
  item.className = 'contact-item';
  item.dataset.contactId = String(contact.id);
  item.setAttribute('aria-label', `Open conversation with ${contact.display_name}`);
  item.innerHTML = `
    <span class="contact-avatar-wrap">
      <span class="avatar contact-avatar"></span>
      <i class="status-indicator"></i>
    </span>
    <span class="contact-detail">
      <span class="contact-name-row"><strong></strong></span>
      <span class="contact-status-line"></span>
      <span class="contact-preview"></span>
    </span>
  `;
  item.addEventListener('click', () => selectContact(item.dataset.contactId));
  return item;
}

function updateContactItem(item, contact) {
  const isOnline = state.onlineUsers.has(contact.id);
  const unread = unreadCountFor(contact.id);
  const lastMessage = latestMessageFor(contact.id);
  const lastTime = lastMessage ? formatTime(lastMessage.created_at) : '';

  item.classList.toggle('is-active', contact.id === state.activeContactId);
  item.setAttribute('aria-label', `Open conversation with ${contact.display_name}`);

  const avatar = item.querySelector('.contact-avatar');
  const avatarHue = avatarHueFor(contact.id);
  avatar.textContent = initials(contact.display_name);
  avatar.style.setProperty('--avatar-hue', avatarHue);

  item.querySelector('.status-indicator').classList.toggle('online', isOnline);
  item.querySelector('.contact-name-row strong').textContent = contact.display_name;

  const status = item.querySelector('.contact-status-line');
  status.textContent = isOnline ? 'Online' : 'Offline';
  status.classList.toggle('online', isOnline);
  item.querySelector('.contact-preview').textContent = contactPreview(contact.id);

  let time = item.querySelector('.contact-time');
  if (lastTime) {
    if (!time) {
      time = document.createElement('time');
      time.className = 'contact-time';
      item.append(time);
    }
    time.textContent = lastTime;
    time.dateTime = lastMessage.created_at;
  } else {
    time?.remove();
  }

  let badge = item.querySelector('.unread-count');
  if (unread > 0) {
    if (!badge) {
      badge = document.createElement('span');
      badge.className = 'unread-count';
      item.append(badge);
    }
    badge.textContent = unread > 99 ? '99+' : String(unread);
  } else {
    badge?.remove();
  }
}

function renderContacts() {
  const list = $('#contactList');
  const query = $('#contactSearch').value.trim().toLowerCase();
  const contacts = [...state.contacts].sort((a, b) => {
    const aMessage = latestMessageFor(a.id);
    const bMessage = latestMessageFor(b.id);
    return new Date(bMessage?.created_at || 0) - new Date(aMessage?.created_at || 0);
  });
  const filtered = contacts.filter((contact) =>
    contact.display_name.toLowerCase().includes(query) ||
    contact.handle.toLowerCase().includes(query)
  );

  if (filtered.length === 0) {
    const empty = list.querySelector('.list-empty') || document.createElement('div');
    empty.className = 'list-empty';
    empty.textContent = contacts.length
      ? 'No conversations match your search.'
      : 'Your conversations will appear here. Add a contact to begin.';
    for (const item of [...list.children]) {
      if (item !== empty) item.remove();
    }
    if (empty.parentElement !== list) list.append(empty);
    return;
  }

  list.querySelector('.list-empty')?.remove();
  const existing = new Map(
    [...list.querySelectorAll('.contact-item[data-contact-id]')]
      .map((item) => [item.dataset.contactId, item])
  );
  const retained = new Set();

  filtered.forEach((contact, index) => {
    const id = String(contact.id);
    const item = existing.get(id) || createContactItem(contact);
    updateContactItem(item, contact);
    retained.add(id);

    // Move only when the ordering actually changed. Unchanged rows keep their
    // DOM identity, focus state and in-flight CSS transitions.
    const currentAtIndex = list.children[index];
    if (currentAtIndex !== item) list.insertBefore(item, currentAtIndex || null);
  });

  for (const [id, item] of existing) {
    if (!retained.has(id)) item.remove();
  }
}

function currentConversationMessages() {
  if (!state.activeContactId) return [];
  return state.messages.filter((message) =>
    (message.sender_id === state.user.id && message.receiver_id === state.activeContactId) ||
    (message.sender_id === state.activeContactId && message.receiver_id === state.user.id)
  );
}

function renderMiniSignal(canvas, bits) {
  if (!canvas || !bits) return;
  const previewBits = bits.slice(0, 24 * 10);
  const levels = nrziEncode(previewBits);
  const bitWidth = 5;
  const height = 46;
  const width = Math.max(120, 12 + levels.length * bitWidth);
  const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
  canvas.width = Math.ceil(width * dpr);
  canvas.height = Math.ceil(height * dpr);
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);
  const yHigh = 12;
  const yLow = 34;

  ctx.strokeStyle = 'rgba(86,105,126,.16)';
  ctx.lineWidth = 1;
  for (let i = 0; i <= levels.length; i += 10) {
    const x = 6 + i * bitWidth;
    ctx.beginPath();
    ctx.moveTo(x, 3);
    ctx.lineTo(x, height - 3);
    ctx.stroke();
  }

  ctx.strokeStyle = '#477d83';
  ctx.lineWidth = 1.75;
  ctx.lineJoin = 'round';
  ctx.beginPath();
  let y = yHigh;
  let x = 6;
  ctx.moveTo(x, y);
  for (const level of levels) {
    const nextY = level === 1 ? yHigh : yLow;
    if (nextY !== y) {
      ctx.lineTo(x, nextY);
      y = nextY;
    }
    x += bitWidth;
    ctx.lineTo(x, y);
  }
  ctx.stroke();
}

function renderMessages({ scrollToBottom = false } = {}) {
  const container = $('#messages');
  const previousScrollTop = container.scrollTop;
  const wasNearBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 72;
  container.replaceChildren();
  const messages = currentConversationMessages();

  if (messages.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-messages';
    empty.innerHTML = '<strong>No transmissions yet</strong>Write the first encrypted message below. Only the two participants can decrypt it.';
    container.append(empty);
    return;
  }

  for (const message of messages) {
    const mine = message.sender_id === state.user.id;
    const isDecoded = state.decodedMessages.has(message.id);
    const decoded = state.decodedMessages.get(message.id);
    const bits = state.bitsByMessage.get(message.id);
    const displayMode = isDecoded ? (state.messageViewModes.get(message.id) || 'decoded') : 'signal';
    const showSignal = !isDecoded || displayMode === 'signal';
    const row = document.createElement('article');
    row.className = 'message-row' + (mine ? ' mine' : '');
    row.dataset.messageId = message.id;
    const timestamp = formatTime(message.created_at);
    const viewAction = isDecoded
      ? '<button class="inspect-button" type="button" data-action="toggle-view" data-message-id="' + message.id + '">' +
        (showSignal ? 'Tampilkan pesan' : 'Tampilkan sinyal') + '</button>'
      : '<button class="inspect-button" type="button" data-action="unlock-message" data-message-id="' + message.id + '">Masukkan kunci</button>';

    row.innerHTML =
      '<span class="message-author">' + (mine ? 'You' : escapeHTML(state.contacts.find((c) => c.id === message.sender_id)?.display_name || 'Contact')) + '</span>' +
      '<div class="message-bubble">' +
        (showSignal
          ? '<div class="wave-mini-wrap">' +
            (bits
              ? '<canvas class="wave-mini" aria-label="Encrypted NRZ-I signal"></canvas>'
              : '<span class="wave-mini-pending">Memuat sinyal terenkripsi…</span>') +
            '</div>'
          : '<div class="decode-result"><span class="decoded-text"></span></div>') +
        '<div class="message-actions">' + viewAction +
          '<button class="message-delete-button" type="button" data-action="delete" data-message-id="' + message.id + '" aria-label="Hapus pesan untuk kedua pihak">Hapus pesan</button>' +
        '</div>' +
      '</div>' +
      '<div class="message-bottom"><span>' + escapeHTML(timestamp) + '</span>' +
        (mine && message.read_at ? '<span class="message-read">· Read</span>' : '') +
      '</div>';

    if (showSignal && bits) {
      renderMiniSignal(row.querySelector('canvas'), bits);
    } else if (!showSignal) {
      row.querySelector('.decoded-text').textContent = decoded;
    }
    container.append(row);
  }
  if (scrollToBottom || wasNearBottom) {
    container.scrollTop = container.scrollHeight;
  } else {
    container.scrollTop = previousScrollTop;
  }
}

function updateConversationHeader() {
  const contact = state.contacts.find((item) => item.id === state.activeContactId);
  if (!contact) return;
  $('#chatAvatar').textContent = initials(contact.display_name);
  $('#chatName').textContent = contact.display_name;
  const online = state.onlineUsers.has(contact.id);
  $('#chatStatus').textContent = online ? 'Online' : 'Offline';
  $('#chatStatusDot').classList.toggle('online', online);
}

let contactSwitchInProgress = false;

function waitForDirectoryFade(element) {
  return new Promise((resolve) => {
    let completed = false;
    const finish = () => {
      if (completed) return;
      completed = true;
      element.removeEventListener('transitionend', onTransitionEnd);
      window.clearTimeout(fallback);
      resolve();
    };
    const onTransitionEnd = (event) => {
      if (event.target === element && event.propertyName === 'opacity') finish();
    };
    const fallback = window.setTimeout(finish, 190);
    element.addEventListener('transitionend', onTransitionEnd);
  });
}

async function beginContactSwitchFade() {
  const canFade = window.innerWidth > 700 &&
    appView.dataset.view === 'contacts' &&
    !appView.classList.contains('has-chat') &&
    !window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  if (!canFade) return false;
  if (contactSwitchInProgress) return null;

  const directoryInner = appView.querySelector('.directory-inner');
  if (!directoryInner) return false;

  contactSwitchInProgress = true;
  appView.classList.add('is-contact-switching');
  await waitForDirectoryFade(directoryInner);
  return true;
}

function endContactSwitchFade() {
  window.requestAnimationFrame(() => {
    window.requestAnimationFrame(() => {
      appView.classList.remove('is-contact-switching');
      contactSwitchInProgress = false;
    });
  });
}

async function selectContact(contactId) {
  const contact = state.contacts.find((item) => item.id === contactId);
  if (!contact || contactSwitchInProgress) return;

  const fadeStarted = await beginContactSwitchFade();
  if (fadeStarted === null) return;

  state.activeContactId = contactId;
  if (appView.dataset.view !== 'contacts') setAppView('contacts');
  appView.classList.add('has-chat');
  window.requestAnimationFrame(updateNavActivePill);
  $('#emptyState').hidden = true;
  $('#conversationView').hidden = false;
  $('#messageInput').focus();
  updateConversationHeader();
  renderContacts();
  renderMessages({ scrollToBottom: true });
  void loadConversationSignals(contactId);
  if (fadeStarted) endContactSwitchFade();

  const unseen = state.messages.some((message) =>
    message.sender_id === contactId &&
    message.receiver_id === state.user.id &&
    !message.read_at
  );
  if (unseen) {
    const now = new Date().toISOString();
    try {
      await markConversationRead(state.user.id, contactId);
      state.messages = state.messages.map((message) =>
        message.sender_id === contactId && message.receiver_id === state.user.id && !message.read_at
          ? { ...message, read_at: now } : message
      );
      renderMessages();
      renderContacts();
    } catch (error) {
      console.warn('Unable to mark messages read:', error.message);
    }
  }
  $('#sidebar').classList.remove('mobile-open');
}

async function ensureContactForUser(userId) {
  if (!userId || userId === state.user.id || state.contacts.some((item) => item.id === userId)) return;
  try {
    const profiles = await getProfilesByIds([userId]);
    const profile = profiles[0];
    if (!profile) return;
    await saveContact(state.user.id, userId);
    state.contacts.push(profile);
    renderContacts();
  } catch (error) {
    console.warn('Unable to add conversation contact:', error.message);
  }
}

function upsertMessage(message) {
  if (!message?.id) return false;
  const index = state.messages.findIndex((item) => item.id === message.id);
  if (index >= 0) {
    state.messages[index] = { ...state.messages[index], ...message };
    return false;
  }
  state.messages.push(message);
  sortMessages();
  return true;
}

async function loadConversationSignals(contactId = state.activeContactId) {
  if (!contactId || !state.user) return;
  const pending = state.messages.filter((message) => (
    (message.sender_id === state.user.id && message.receiver_id === contactId) ||
    (message.sender_id === contactId && message.receiver_id === state.user.id)
  ) && message.enc_version === 1 && !message.deleted_at && !state.bitsByMessage.has(message.id));

  if (pending.length === 0) return;
  try {
    // E2EE ciphertext is safe to display as a waveform before the user decrypts it.
    const payloads = await fetchMessagePayloads(pending.map((message) => message.id));
    for (const payload of payloads) {
      if (payload?.id && payload.payload_bits) state.bitsByMessage.set(payload.id, payload.payload_bits);
    }
    if (state.activeContactId === contactId) renderMessages();
  } catch (error) {
    console.warn('Unable to load encrypted signal payloads:', error.message);
  }
}

function openE2eeUnlockDialog() {
  if (!state.e2eeState?.enabled) {
    openDialog(keyDialog);
    return;
  }
  $('#e2eeUnlockForm').reset();
  openDialog(e2eeUnlockDialog);
  $('#e2eeUnlockPassphrase').focus();
}

async function handleMessageDelete(messageId) {
  if (!messageId || state.deletingMessageIds.has(messageId)) return;
  const exists = state.messages.some((message) => message.id === messageId);
  if (!exists) return;
  state.deletingMessageIds.add(messageId);

  const row = [...document.querySelectorAll('#messages .message-row')]
    .find((element) => element.dataset.messageId === messageId);
  if (row && !window.matchMedia('(prefers-reduced-motion: reduce)').matches && row.animate) {
    const height = row.getBoundingClientRect().height;
    const isMine = row.classList.contains('mine');
    row.style.transformOrigin = isMine ? 'right center' : 'left center';
    try {
      await row.animate([
        {
          height: height + 'px',
          marginTop: getComputedStyle(row).marginTop,
          marginBottom: getComputedStyle(row).marginBottom,
          transform: 'translateX(0) scaleX(1)',
          clipPath: 'inset(0 0 0 0 round 14px)',
        },
        {
          height: '0px',
          marginTop: '0px',
          marginBottom: '0px',
          transform: 'translateX(' + (isMine ? '28px' : '-28px') + ') scaleX(.04)',
          clipPath: 'inset(0 48% 0 48% round 14px)',
        },
      ], {
        duration: 280,
        easing: 'cubic-bezier(.22,1,.36,1)',
        fill: 'forwards',
      }).finished;
    } catch {
      // The element may be removed by a simultaneous workspace navigation.
    }
  }

  state.messages = state.messages.filter((message) => message.id !== messageId);
  state.decodedMessages.delete(messageId);
  state.bitsByMessage.delete(messageId);
  state.messageViewModes.delete(messageId);
  state.deletingMessageIds.delete(messageId);
  renderMessages();
  renderContacts();
}

async function handleIncomingMessage(rawMessage) {
  if (rawMessage.sender_id !== state.user.id && rawMessage.receiver_id !== state.user.id) return;
  // Realtime does not carry payload_bits or frame_count, so load the safe metadata row.
  let message = rawMessage;
  if (!message.frame_count) {
    try {
      message = await fetchMessageMeta(rawMessage.id);
    } catch (error) {
      console.warn('Unable to load incoming message:', error.message);
      return;
    }
    if (!message) return;
  }
  const inserted = upsertMessage(message);
  const otherId = partnerId(message);
  await ensureContactForUser(otherId);
  if (state.activeContactId === otherId) void loadConversationSignals(otherId);

  if (message.receiver_id === state.user.id && state.activeContactId === otherId) {
    try {
      await markConversationRead(state.user.id, otherId);
      state.messages = state.messages.map((item) =>
        item.sender_id === otherId && item.receiver_id === state.user.id && !item.read_at
          ? { ...item, read_at: new Date().toISOString() } : item
      );
    } catch (error) {
      console.warn('Unable to mark incoming message read:', error.message);
    }
  }

  renderContacts();
  if (state.activeContactId === otherId) renderMessages();
  else if (inserted && message.sender_id !== state.user.id) showToast('Pesan baru diterima.', 'info');
}

function handleMessageUpdate(message) {
  const index = state.messages.findIndex((item) => item.id === message.id);
  if (index >= 0) state.messages[index] = { ...state.messages[index], ...message };
  renderContacts();
  if (state.activeContactId) renderMessages();
}

async function loadWorkspace() {
  const userId = state.user.id;
  const [profile, contactIds, messages] = await Promise.all([
    getProfile(userId), listContactIds(userId), listRecentMessages(userId),
  ]);
  state.profile = profile;
  state.messages = messages;
  state.decodedMessages.clear();
  state.bitsByMessage.clear();
  state.messageViewModes.clear();

  const partnerIds = new Set(contactIds);
  for (const message of messages) partnerIds.add(partnerId(message, userId));
  partnerIds.delete(userId);

  const profiles = await getProfilesByIds([...partnerIds]);
  normalizeContacts(profiles);
  const knownContacts = new Set(contactIds);
  await Promise.all([...partnerIds].filter((id) => !knownContacts.has(id)).map((id) => saveContact(userId, id)));
  sortMessages();
  renderAccount();
  renderContacts();

  state.e2eeState = await getE2eeState();
  state.e2eeSession = null;
  state.e2eeUnlocked = false;
  if (!state.e2eeState.enabled) {
    $('#keyForm').dataset.mode = 'enable';
    $('#oldKeyField').hidden = !state.e2eeState.has_legacy_key;
    $('#oldKeyLabel').textContent = 'Kunci pembuka lama';
    $('#keyDialogTitle').textContent = 'Aktifkan E2EE';
    $('#keyLabel').textContent = 'Passphrase E2EE baru';
    openDialog(keyDialog);
  } else {
    // Restore the already-unlocked CryptoKey from this browser's local vault.
    // The cache is tied to the account and its current public identity key.
    try {
      state.e2eeSession = await getE2eeVault(userId, state.e2eeState.public_key);
      if (state.e2eeSession) {
        state.e2eeSession.wrappedKeyB64 = state.e2eeState.wrapped_private_key;
      }
    } catch (error) {
      console.warn('Unable to restore local E2EE key:', error.message);
    }
    state.e2eeUnlocked = Boolean(state.e2eeSession?.privateKey);
    // Do not ask for the key just to enter the chat. Reading a message has its
    // own per-message prompt; sending asks for the key only when necessary.
  }
  renderKeyStatus();

  state.disconnectRealtime?.();
  state.disconnectRealtime = connectRealtime({
    userId,
    onMessage: handleIncomingMessage,
    onMessageUpdate: handleMessageUpdate,
    onMessageDelete: handleMessageDelete,
    onPresence: (entries) => {
      state.onlineUsers = new Set(entries.map((entry) => entry.userId).filter(Boolean));
      renderContacts();
      updateConversationHeader();
    },
    onStatus: (status) => {
      setConnection(status);
      // After a dropped connection, check right away: a "Bukan aku" may have been missed.
      if (status === 'SUBSCRIBED' && state.deviceRowId) deviceTick();
    },
    onDevice: handleDeviceEvent,
  });
}

const relativeTimeFormat = new Intl.RelativeTimeFormat('id-ID', { numeric: 'auto' });

function formatRelative(date) {
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  for (const [unit, size] of [['day', 86400], ['hour', 3600], ['minute', 60]]) {
    if (Math.abs(seconds) >= size) return relativeTimeFormat.format(Math.round(seconds / size), unit);
  }
  return 'baru saja';
}

function formatDeviceTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  const absolute = date.toLocaleString('id-ID', {
    day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
  });
  return `${absolute} (${formatRelative(date)})`;
}

// Approximate place derived from the connection's IP address by the server.
function formatDevicePlace(device) {
  let country = '';
  if (device.country) {
    try {
      country = new Intl.DisplayNames(['id'], { type: 'region' }).of(device.country) || device.country;
    } catch {
      country = device.country;
    }
  }
  const parts = [device.city, device.region, country].filter(Boolean);
  const unique = parts.filter((part, index) => parts.indexOf(part) === index);
  return unique.length ? `${unique.join(', ')} (perkiraan)` : 'Lokasi tidak diketahui';
}

const DEVICE_TYPE_LABELS = { desktop: 'Komputer / laptop', mobile: 'Ponsel', tablet: 'Tablet' };
const DEVICE_ONLINE_WINDOW_MS = 90_000;
let deviceRefreshTimer = null;

function formatLastActive(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  if (Date.now() - date.getTime() < DEVICE_ONLINE_WINDOW_MS) return 'Sedang aktif sekarang';
  return formatDeviceTime(value);
}

function deviceFact(label, value, { mono = false } = {}) {
  if (!value) return '';
  return `<div><dt>${escapeHTML(label)}</dt><dd${mono ? ' class="mono"' : ''}>${escapeHTML(value)}</dd></div>`;
}

// One readable card per device. Location and IP only exist in the data when the
// viewer is a trusted device; the server leaves them out otherwise.
function renderDeviceCard(device, { canManage }) {
  const pending = device.status === 'pending';
  const badges = [];
  if (device.is_current) badges.push('<span class="device-badge is-current">Perangkat ini</span>');
  badges.push(pending
    ? '<span class="device-badge is-pending">Belum dikonfirmasi</span>'
    : '<span class="device-badge is-trusted">Dikenal</span>');

  const loginValue = device.session_started_at || device.first_seen_at;
  const loginDate = new Date(loginValue);
  const when = Number.isNaN(loginDate.getTime()) ? '' : formatRelative(loginDate);
  const hasPlace = Boolean(device.city || device.region || device.country);
  const place = formatDevicePlace(device);
  const headline = [when && `Login ${when}`, canManage && hasPlace && place].filter(Boolean).join(' · ');

  const facts = [
    canManage && deviceFact('Lokasi', place),
    canManage && deviceFact('Alamat IP', device.ip_address || 'Tidak diketahui', { mono: true }),
    deviceFact('Login pada', formatDeviceTime(loginValue)),
    deviceFact('Terakhir aktif', formatLastActive(device.last_seen_at)),
    deviceFact('Jenis perangkat', DEVICE_TYPE_LABELS[device.device_type]),
    deviceFact('Browser', device.browser),
    deviceFact('Sistem operasi', device.os),
    deviceFact('Bahasa', device.language),
    deviceFact('Zona waktu', device.timezone),
    deviceFact('Pertama terlihat', formatDeviceTime(device.first_seen_at)),
  ].filter(Boolean).join('');

  const id = escapeHTML(device.id);
  let actions = '';
  if (canManage && !device.is_current) {
    actions = pending
      ? `<button class="button button-primary" type="button" data-device-action="ack" data-device-id="${id}">Ini aku</button>
         <button class="button button-danger" type="button" data-device-action="reject" data-device-id="${id}">Bukan aku</button>`
      : `<button class="button button-danger-quiet" type="button" data-device-action="remove" data-device-id="${id}">Keluarkan perangkat</button>`;
  }

  return `
    <li class="device-card${pending ? ' is-pending' : ''}">
      <div class="device-card-head"><strong>${escapeHTML(device.label)}</strong><span class="device-badges">${badges.join('')}</span></div>
      ${headline ? `<p class="device-headline">${escapeHTML(headline)}</p>` : ''}
      <dl class="device-facts">${facts}</dl>
      ${actions ? `<div class="device-actions">${actions}</div>` : ''}
    </li>`;
}

function renderDevices(devices) {
  const current = devices.find((device) => device.is_current);
  const trustedViewer = current?.status === 'trusted';
  // Only a trusted device is told about, and may decide on, newer devices.
  const pending = trustedViewer
    ? devices.filter((device) => !device.is_current && device.status === 'pending')
    : [];
  const others = devices.filter((device) => !pending.includes(device));
  const selfPending = Boolean(current) && !trustedViewer;

  const pendingIds = new Set(pending.map((device) => device.id));
  if (state.knownPendingIds) {
    const fresh = pending.filter((device) => !state.knownPendingIds.has(device.id));
    if (fresh.length) showToast(`Perangkat baru masuk: ${fresh[0].label}. Buka menu Keamanan untuk memeriksanya.`, 'error');
  }
  state.knownPendingIds = devices.length ? pendingIds : null;

  $('#deviceAlert').hidden = pending.length === 0;
  $('#deviceAlertTitle').textContent = pending.length === 1
    ? 'Ada 1 perangkat baru masuk ke akunmu'
    : `Ada ${pending.length} perangkat baru masuk ke akunmu`;
  $('#deviceAlertList').innerHTML = pending.map((device) => renderDeviceCard(device, { canManage: true })).join('');
  $('#deviceSelfNotice').hidden = !selfPending;
  $('#securityDot').hidden = pending.length === 0 && !selfPending;
  $('#deviceList').innerHTML = others.map((device) => renderDeviceCard(device, { canManage: trustedViewer })).join('');
  $('#deviceSummary').textContent = devices.length ? `${others.length} perangkat tercatat` : 'Memuat…';
}

async function refreshDevices() {
  if (!state.user) return [];
  try {
    const devices = await fetchDevices();
    if (state.user) renderDevices(devices);
    return devices;
  } catch (error) {
    if (isSessionRevoked(error)) await endRevokedSession();
    else console.error('Device list failed:', error);
    return [];
  }
}

// Every device of the account gets an event for each change. Bursts (for
// example several heartbeats) are folded into one refresh.
function scheduleDeviceRefresh(delay = 350) {
  window.clearTimeout(deviceRefreshTimer);
  deviceRefreshTimer = window.setTimeout(refreshDevices, delay);
}

// Realtime event for this account's devices. When it is this device's own row
// that was just revoked, leave immediately instead of waiting for the heartbeat.
function handleDeviceEvent({ row } = {}) {
  if (!row) return;
  if (row.id === state.deviceRowId && row.revoked_at) {
    endRevokedSession();
    return;
  }
  scheduleDeviceRefresh();
}

const DEVICE_HEARTBEAT_MS = 30_000;
let deviceHeartbeatTimer = null;
let deviceTickRunning = false;
let deviceRegistrationWarningShown = false;
let deviceStorageWarningShown = false;

function showDeviceApprovalGate(device = null) {
  authView.hidden = true;
  appView.hidden = true;
  deviceGateView.hidden = false;

  const title = $('#deviceGateTitle');
  const message = $('#deviceGateMessage');
  const note = $('#deviceGateNote');
  const recovery = $('#deviceGateRecovery');
  const status = $('#deviceGateStatus');
  const isPending = device?.status === 'pending';

  // Do not label a trusted browser as unapproved while the server is still
  // checking its session. The confirmation instructions appear only after
  // the database explicitly reports this session as pending.
  title.textContent = isPending ? 'Konfirmasi perangkat dulu' : 'Memeriksa perangkat…';
  note.hidden = !isPending;
  recovery.hidden = !isPending;

  if (isPending) {
    message.textContent = 'Login berhasil, tetapi perangkat ini belum disetujui. Data profil, kontak, pesan, dan private key tetap terkunci.';
    status.textContent = 'Status: menunggu persetujuan dari perangkat yang sudah dikenal.';
    return;
  }

  message.textContent = 'SYNTRIX sedang memeriksa identitas perangkat ini.';
  status.textContent = 'Memeriksa status perangkat…';
}

async function openApprovedWorkspace() {
  if (!state.user || state.workspaceLoaded || state.workspaceLoading) return;
  state.workspaceLoading = true;
  deviceGateView.hidden = true;
  appView.hidden = false;
  // The initial measurement runs while appView is hidden, so refresh the
  // active navigation shape as soon as the workspace has a real layout.
  window.requestAnimationFrame(updateNavActivePill);
  try {
    await loadWorkspace();
    state.workspaceLoaded = true;
  } catch (error) {
    showToast(friendlyError(error, 'Tidak dapat memuat workspace.'), 'error');
    console.error(error);
  } finally {
    state.workspaceLoading = false;
  }
}

function stopDeviceHeartbeat() {
  if (deviceHeartbeatTimer) window.clearInterval(deviceHeartbeatTimer);
  deviceHeartbeatTimer = null;
}

// This session was removed by "Bukan aku" on another device. Its access token
// may still be valid for a while, so leave the workspace right away.
async function endRevokedSession() {
  // After a normal sign-out state.user is already cleared; stay silent then.
  if (!state.user || state.endingSession) return;
  state.endingSession = true;
  stopDeviceHeartbeat();
  window.clearTimeout(deviceRefreshTimer);
  showToast('Sesi ini dikeluarkan dari perangkat lain. Silakan masuk lagi.', 'error');
  try {
    const { error } = await supabase.auth.signOut({ scope: 'local' });
    if (error) console.warn('Local sign-out failed:', error.message);
  } finally {
    state.endingSession = false;
  }
}

// Keeps last_seen_at and the location current, notices a revoked session, and
// re-reads alerts even if the realtime event for a new device was missed.
async function deviceTick({ reportFailure = false } = {}) {
  if (deviceTickRunning || !state.user) return false;
  deviceTickRunning = true;
  try {
    state.deviceRowId = await registerDevice();
    deviceRegistrationWarningShown = false;

    if (!hasPersistentDeviceId() && !deviceStorageWarningShown) {
      deviceStorageWarningShown = true;
      showToast(
        'Browser ini tidak menyimpan identitas perangkat. Login berikutnya mungkin terbaca sebagai perangkat baru.',
        'error'
      );
    } else if (hasPersistentDeviceId()) {
      deviceStorageWarningShown = false;
    }

    const devices = await refreshDevices();
    const currentDevice = devices.find((device) => device.is_current);
    if (!currentDevice) throw new Error('device_registration_missing');

    if (currentDevice.status === 'trusted') {
      await openApprovedWorkspace();
      return true;
    }

    showDeviceApprovalGate(currentDevice);
    return false;
  } catch (error) {
    if (isSessionRevoked(error)) {
      await endRevokedSession();
    } else {
      console.warn('Device heartbeat failed:', error.message);
      if (reportFailure && !deviceRegistrationWarningShown) {
        deviceRegistrationWarningShown = true;
        showToast(
          'Login berhasil, tetapi perangkat belum berhasil dicatat. Periksa koneksi lalu muat ulang halaman.',
          'error'
        );
      }
    }
    return false;
  } finally {
    deviceTickRunning = false;
  }
}

function startDeviceHeartbeat() {
  stopDeviceHeartbeat();
  deviceHeartbeatTimer = window.setInterval(() => {
    if (!document.hidden) deviceTick();
  }, DEVICE_HEARTBEAT_MS);
}

document.addEventListener('visibilitychange', () => {
  if (!document.hidden && deviceHeartbeatTimer) deviceTick();
});
// Coming back online is the moment a missed revocation is most likely.
window.addEventListener('online', () => {
  if (deviceHeartbeatTimer) deviceTick();
});

async function syncDevices() {
  const approved = await deviceTick({ reportFailure: true });
  // Pending devices still heartbeat so approval is noticed without reloading.
  if (state.user && !state.endingSession) startDeviceHeartbeat();
  return approved;
}

$('#deviceGateRetry').addEventListener('click', async () => {
  const button = $('#deviceGateRetry');
  button.disabled = true;
  button.textContent = 'Memeriksa…';
  await deviceTick({ reportFailure: true });
  button.disabled = false;
  button.textContent = 'Periksa lagi';
});

$('#deviceGateLogout').addEventListener('click', async () => {
  const button = $('#deviceGateLogout');
  button.disabled = true;
  const { error } = await supabase.auth.signOut({ scope: 'local' });
  if (error) {
    button.disabled = false;
    showToast(friendlyError(error, 'Gagal keluar dari akun.'), 'error');
  }
});

// "Ini aku", "Bukan aku" and "Keluarkan perangkat" act on exactly one device.
async function resolveDevice(button) {
  const { deviceAction, deviceId } = button.dataset;
  if (!deviceId) return;
  if (deviceAction === 'remove'
    && !window.confirm('Keluarkan perangkat ini dari akunmu? Sesinya akan langsung berakhir.')) return;

  const buttons = button.closest('.device-card')?.querySelectorAll('button') ?? [button];
  buttons.forEach((item) => { item.disabled = true; });
  try {
    if (deviceAction === 'ack') {
      const changed = await acknowledgeDevice(deviceId);
      showToast(changed ? 'Oke, perangkat itu ditandai sebagai kamu.' : 'Perangkat itu sudah diproses.', 'success');
    } else {
      const result = await rejectDevice(deviceId);
      showToast(result?.removed
        ? 'Perangkat itu langsung dikeluarkan. Sebaiknya ganti kunci pesan dan password.'
        : 'Perangkat itu sudah tidak ada.', 'success');
    }
  } catch (error) {
    showToast(friendlyError(error, 'Gagal memproses perangkat.'), 'error');
  } finally {
    // Always re-read the list so a card never stays stale after a partial failure.
    await refreshDevices();
  }
}

function isChatRoute() {
  return window.location.pathname.replace(/\/+$/, '') === '/chat';
}

async function enterApp(user) {
  if (!user || state.bootingUserId === user.id) return;
  if (state.user?.id === user.id && (!appView.hidden || !deviceGateView.hidden)) return;
  state.bootingUserId = user.id;
  state.user = user;
  state.workspaceLoaded = false;
  state.workspaceLoading = false;
  showDeviceApprovalGate();
  window.requestAnimationFrame(updateNavActivePill);
  $('#emptyState').hidden = false;
  $('#conversationView').hidden = true;
  $('#messages').replaceChildren();
  try {
    // The server decides whether this session is trusted. Pending sessions
    // stay on the approval screen and never load workspace data.
    await syncDevices();
  } catch (error) {
    showToast(friendlyError(error, 'Tidak dapat memeriksa perangkat.'), 'error');
    console.error(error);
  } finally {
    state.bootingUserId = null;
  }
}

async function leaveApp() {
  const signedOutUserId = state.user?.id;
  stopDeviceHeartbeat();
  window.clearTimeout(deviceRefreshTimer);
  state.deviceRowId = null;
  state.knownPendingIds = null;
  state.workspaceLoaded = false;
  state.workspaceLoading = false;
  deviceGateView.hidden = true;
  deviceRegistrationWarningShown = false;
  deviceStorageWarningShown = false;
  renderDevices([]);
  state.disconnectRealtime?.();
  state.disconnectRealtime = null;
  state.user = null;
  state.profile = null;
  state.contacts = [];
  state.messages = [];
  state.activeContactId = null;
  state.onlineUsers.clear();
  state.decodedMessages.clear();
  state.bitsByMessage.clear();
  state.messageViewModes.clear();
  state.e2eeState = null;
  state.e2eeSession = null;
  state.e2eeUnlocked = false;
  if (signedOutUserId) {
    try {
      await clearE2eeVault(signedOutUserId);
    } catch (error) {
      console.warn('Unable to clear local E2EE key:', error.message);
    }
  }
  state.deletingMessageIds.clear();
  appView.hidden = true;
  authView.hidden = false;
  loginForm.reset();
  registerForm.reset();
  setAuthMode('login');
  setConnection('CLOSED');
}

supabase.auth.onAuthStateChange((event, session) => {
  if (event === 'SIGNED_OUT') {
    leaveApp();
    if (isChatRoute()) window.history.replaceState({}, '', '/');
    return;
  }

  if (!session?.user) return;

  // A fresh login is an explicit request to enter the workspace.
  if (event === 'SIGNED_IN') {
    window.history.replaceState({}, '', '/chat');
    window.setTimeout(() => enterApp(session.user), 0);
    return;
  }

  // Restoring or refreshing a saved session must never hijack the public homepage.
  if (event === 'INITIAL_SESSION' && isChatRoute()) {
    window.setTimeout(() => enterApp(session.user), 0);
    return;
  }

  // Keep an already-open workspace alive when Supabase refreshes its session.
  if (['TOKEN_REFRESHED', 'USER_UPDATED'].includes(event) && state.user?.id === session.user.id) {
    window.setTimeout(() => enterApp(session.user), 0);
  }
});

async function initialize() {
  try {
    const { data, error } = await supabase.auth.getSession();
    if (error) throw error;

    // The homepage is the default route, even when a valid session exists.
    // The workspace is restored only when the user opens /chat explicitly.
    if (data.session?.user && isChatRoute()) {
      await enterApp(data.session.user);
    }
  } catch (error) {
    showToast(friendlyError(error, 'Gagal memeriksa sesi login.'), 'error');
  }
}

window.addEventListener('popstate', async () => {
  if (isChatRoute()) {
    if (state.user) {
      await enterApp(state.user);
      return;
    }
    const { data, error } = await supabase.auth.getSession();
    if (error) {
      showToast(friendlyError(error, 'Gagal memeriksa sesi login.'), 'error');
      return;
    }
    if (data.session?.user) await enterApp(data.session.user);
    return;
  }

  if (!appView.hidden) {
    appView.hidden = true;
    authView.hidden = false;
  }
});

$('#addContactBtn').addEventListener('click', () => {
  $('#contactForm').reset();
  openDialog(contactDialog);
  $('#contactHandle').focus();
});
$('#emptyAddContactBtn').addEventListener('click', () => $('#addContactBtn').click());

$('#contactForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#contactSubmit');
  const handle = $('#contactHandle').value.trim().replace(/^@/, '').toLowerCase();
  if (!/^[a-z0-9_]{3,24}$/.test(handle)) {
    showToast('Format handle tidak valid.', 'error');
    return;
  }

  setBusy(button, true, 'Looking up...');
  try {
    const profile = await findProfileByHandle(handle);
    if (!profile) {
      showToast(`Handle @${handle} tidak ditemukan.`, 'error');
      return;
    }
    if (profile.id === state.user.id) {
      showToast('Kamu tidak bisa menambahkan akun sendiri.', 'error');
      return;
    }
    await saveContact(state.user.id, profile.id);
    if (!state.contacts.some((item) => item.id === profile.id)) state.contacts.push(profile);
    renderContacts();
    closeDialog(contactDialog);
    await selectContact(profile.id);
    showToast(`@${handle} ditambahkan ke kontak.`, 'success');
  } catch (error) {
    showToast(friendlyError(error, 'Tidak bisa menambahkan kontak.'), 'error');
  } finally {
    setBusy(button, false);
  }
});

$('#contactSearch').addEventListener('input', renderContacts);
$('#messageInput').addEventListener('input', (event) => {
  $('#messageCounter').textContent = `${event.target.value.length} / ${MAX_MESSAGE_LENGTH}`;
});

$('#messageForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (state.sending) return;
  if (!state.activeContactId) {
    showToast('Pilih kontak terlebih dahulu.', 'error');
    return;
  }
  if (!state.e2eeUnlocked || !state.e2eeSession?.privateKey) {
    openE2eeUnlockDialog();
    showToast('Buka E2EE di perangkat ini sebelum mengirim pesan.', 'info');
    return;
  }
  const contact = state.contacts.find((item) => item.id === state.activeContactId);
  if (!contact?.public_key) {
    showToast('Kontak ini belum mengaktifkan E2EE. Pengiriman pesan belum diizinkan.', 'error');
    return;
  }
  const plaintext = $('#messageInput').value.trim();
  if (!plaintext) return;

  state.sending = true;
  const button = $('#sendButton');
  button.disabled = true;
  try {
    const encrypted = await encryptE2eePayload({
      plaintext,
      privateKey: state.e2eeSession.privateKey,
      ownPublicKeyB64: state.e2eeSession.publicKeyB64,
      recipientPublicKeyB64: contact.public_key,
      senderId: state.user.id,
      receiverId: contact.id,
    });
    const message = await insertMessage(state.user.id, contact.id, encrypted.payloadBits);
    upsertMessage(message);
    state.bitsByMessage.set(message.id, encrypted.payloadBits);
    // Outgoing messages stay locked too; the sender must enter the E2EE key
    // for this individual message when they want to read it.
    $('#messageInput').value = '';
    $('#messageCounter').textContent = '0 / ' + MAX_MESSAGE_LENGTH;
    renderMessages();
    renderContacts();
  } catch (error) {
    showToast(friendlyError(error, 'Pesan gagal dienkripsi atau dikirim.'), 'error');
  } finally {
    state.sending = false;
    button.disabled = false;
    $('#messageInput').focus();
  }
});

$('#e2eeUnlockForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!state.e2eeState?.enabled) return;
  const button = $('#e2eeUnlockSubmit');
  setBusy(button, true, 'Membuka private key...');
  try {
    state.e2eeSession = await unlockE2ee(
      $('#e2eeUnlockPassphrase').value,
      state.e2eeState,
    );
    state.e2eeUnlocked = true;
    try {
      await saveE2eeVault(state.user.id, state.e2eeSession);
    } catch (error) {
      console.warn('Private key unlocked, but local persistence failed:', error.message);
      showToast('E2EE terbuka, tetapi browser tidak bisa menyimpan sesi kunci lokal.', 'info');
    }
    closeDialog(e2eeUnlockDialog);
    $('#e2eeUnlockForm').reset();
    renderKeyStatus();
    renderMessages();
    renderContacts();
    showToast('E2EE berhasil dibuka di perangkat ini.', 'success');
  } catch (error) {
    showToast(friendlyError(error, 'Gagal membuka E2EE.'), 'error');
  } finally {
    setBusy(button, false);
  }
});

$('#messageUnlockForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = $('#messageUnlockForm');
  const messageId = form.dataset.messageId;
  const message = state.messages.find((item) => item.id === messageId);
  if (!message || message.deleted_at) {
    showToast('Pesan sudah tidak tersedia.', 'error');
    closeDialog(messageUnlockDialog);
    return;
  }

  const passphrase = $('#messageUnlockPassphrase').value;
  const button = $('#messageUnlockSubmit');
  setBusy(button, true, 'Membuka pesan...');
  try {
    // The passphrase only unwraps this account's private key in this browser.
    // It is deliberately not cached or sent to Supabase.
    const messageSession = await unlockE2ee(passphrase);
    let payloadBits = state.bitsByMessage.get(message.id);
    if (!payloadBits) {
      const payloads = await fetchMessagePayloads([message.id]);
      payloadBits = payloads.find((item) => item.id === message.id)?.payload_bits;
    }
    if (!payloadBits) throw new Error('Payload sinyal pesan tidak ditemukan.');

    const peer = state.contacts.find((contact) => contact.id === partnerId(message));
    if (!peer?.public_key) throw new Error('Public key kontak tidak tersedia.');
    const plaintext = await decryptE2eePayload({
      payloadBits,
      privateKey: messageSession.privateKey,
      ownPublicKeyB64: messageSession.publicKeyB64,
      peerPublicKeyB64: peer.public_key,
      userId: state.user.id,
      message,
    });

    state.bitsByMessage.set(message.id, payloadBits);
    state.decodedMessages.set(message.id, plaintext);
    state.messageViewModes.set(message.id, 'decoded');
    closeDialog(messageUnlockDialog);
    form.reset();
    form.dataset.messageId = '';
    renderMessages();
    renderContacts();
    showToast('Pesan berhasil dibuka.', 'success');
  } catch (error) {
    showToast(friendlyError(error, 'Kunci E2EE salah atau pesan tidak dapat dibuka.'), 'error');
  } finally {
    setBusy(button, false);
  }
});

$('#keyForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const passphrase = $('#newUnlockKey').value;
  const confirmation = $('#confirmUnlockKey').value;
  const mode = $('#keyForm').dataset.mode || 'enable';
  if (passphrase !== confirmation) {
    showToast('Konfirmasi passphrase tidak cocok.', 'error');
    return;
  }
  if (passphrase.length < 10 || new TextEncoder().encode(passphrase).length > 256) {
    showToast('Passphrase E2EE minimal 10 karakter dan maksimal 256 byte.', 'error');
    return;
  }
  if (mode === 'enable' && state.e2eeState?.has_legacy_key && !$('#oldUnlockKey').value) {
    showToast('Masukkan kunci pembuka lama untuk memverifikasi akun.', 'error');
    return;
  }
  if (mode === 'change' && !$('#oldUnlockKey').value) {
    showToast('Masukkan passphrase E2EE saat ini.', 'error');
    return;
  }

  const button = $('#keySubmit');
  setBusy(button, true, mode === 'enable' ? 'Mengaktifkan E2EE...' : 'Mengganti passphrase...');
  try {
    if (mode === 'enable') {
      state.e2eeSession = await enableE2ee(
        state.e2eeState?.has_legacy_key ? $('#oldUnlockKey').value : null,
        passphrase,
      );
    } else {
      state.e2eeSession = await changeE2eePassphrase(
        state.e2eeSession,
        $('#oldUnlockKey').value,
        passphrase,
        state.e2eeState,
      );
    }
    state.e2eeState = await getE2eeState();
    state.e2eeUnlocked = true;
    try {
      await saveE2eeVault(state.user.id, state.e2eeSession);
    } catch (error) {
      console.warn('Private key activated, but local persistence failed:', error.message);
      showToast('E2EE aktif, tetapi browser tidak bisa menyimpan sesi kunci lokal.', 'info');
    }
    $('#oldKeyField').hidden = true;
    $('#keyForm').reset();
    $('#keyForm').dataset.mode = 'enable';
    closeDialog(keyDialog);
    renderKeyStatus();
    renderMessages();
    renderContacts();
    showToast(mode === 'enable' ? 'E2EE berhasil diaktifkan.' : 'Passphrase E2EE berhasil diganti.', 'success');
  } catch (error) {
    showToast(friendlyError(error, 'Pengaturan E2EE gagal disimpan.'), 'error');
  } finally {
    setBusy(button, false);
  }
});

$('#changeKeyBtn').addEventListener('click', () => {
  if (!state.e2eeState?.enabled) {
    $('#keyForm').dataset.mode = 'enable';
    $('#oldKeyField').hidden = !state.e2eeState?.has_legacy_key;
    $('#oldKeyLabel').textContent = 'Kunci pembuka lama';
    $('#keyDialogTitle').textContent = 'Aktifkan E2EE';
    $('#keyLabel').textContent = 'Passphrase E2EE baru';
    $('#keyForm').reset();
    openDialog(keyDialog);
    return;
  }
  if (!state.e2eeUnlocked || !state.e2eeSession?.privateKey) {
    openE2eeUnlockDialog();
    showToast('Buka E2EE terlebih dahulu sebelum mengganti passphrase.', 'info');
    return;
  }
  $('#keyForm').reset();
  $('#keyForm').dataset.mode = 'change';
  $('#oldKeyField').hidden = false;
  $('#oldKeyLabel').textContent = 'Passphrase E2EE saat ini';
  $('#keyDialogTitle').textContent = 'Ganti passphrase E2EE';
  $('#keyLabel').textContent = 'Passphrase E2EE baru';
  openDialog(keyDialog);
});
$('#logoutBtn').addEventListener('click', async () => {
  const button = $('#logoutBtn');
  button.disabled = true;
  try {
    // Clear the local private-key cache before navigation can interrupt cleanup.
    if (state.user?.id) await clearE2eeVault(state.user.id);
    await signOut();
    // Always leave the /chat route after the local session is cleared.
    window.location.replace('/');
  } catch (error) {
    showToast(friendlyError(error, 'Gagal keluar.'), 'error');
  } finally {
    button.disabled = false;
  }
});

document.querySelectorAll('[data-close]').forEach((button) => {
  button.addEventListener('click', () => closeDialog(document.getElementById(button.dataset.close)));
});

for (const dialog of [contactDialog, e2eeUnlockDialog, messageUnlockDialog, keyDialog, inspectorDialog]) {
  dialog.addEventListener('click', (event) => {
    if (event.target === dialog) closeDialog(dialog);
  });
}

function drawSignal(canvas, bits, maxFrames = 120) {
  if (!canvas || !bits) return;
  const previewBits = bits.slice(0, maxFrames * 10);
  const levels = nrziEncode(previewBits);
  const bitWidth = 8;
  const width = 24 + levels.length * bitWidth;
  const height = 150;
  const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
  canvas.width = Math.ceil(width * dpr);
  canvas.height = Math.ceil(height * dpr);
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);
  const yHigh = 42;
  const yLow = 104;
  ctx.font = '9px DM Mono, monospace';
  ctx.fillStyle = '#56657a';
  ctx.fillText('HIGH', 2, yHigh - 9);
  ctx.fillText('LOW', 2, yLow - 9);

  ctx.strokeStyle = 'rgba(89,108,132,.16)';
  ctx.lineWidth = 1;
  ctx.setLineDash([3, 5]);
  for (const y of [yHigh, yLow]) {
    ctx.beginPath();
    ctx.moveTo(22, y);
    ctx.lineTo(width - 2, y);
    ctx.stroke();
  }
  ctx.setLineDash([]);

  for (let i = 0; i <= levels.length; i += 10) {
    const x = 22 + i * bitWidth;
    ctx.strokeStyle = 'rgba(89,108,132,.2)';
    ctx.beginPath();
    ctx.moveTo(x, 20);
    ctx.lineTo(x, 126);
    ctx.stroke();
    if (i < levels.length) {
      ctx.fillStyle = '#617087';
      ctx.fillText(String(i / 10 + 1), x + 2, 140);
    }
  }

  ctx.strokeStyle = '#477d83';
  ctx.lineWidth = 2;
  ctx.lineJoin = 'round';
  ctx.beginPath();
  let levelY = yHigh;
  let x = 22;
  ctx.moveTo(x, levelY);
  for (const level of levels) {
    const nextY = level === 1 ? yHigh : yLow;
    if (nextY !== levelY) {
      ctx.lineTo(x, nextY);
      levelY = nextY;
    }
    x += bitWidth;
    ctx.lineTo(x, levelY);
  }
  ctx.stroke();
}

function openInspector(storedMessage) {
  const payload = state.bitsByMessage.get(storedMessage.id);
  if (!payload) {
    showToast('Buka kunci pesan terlebih dahulu.', 'error');
    return;
  }
  const issue = validateBitStream(payload);
  if (issue) {
    showToast(`Frame tidak valid: ${issue}`, 'error');
    return;
  }

  const frames = summarizeFrames(payload);
  const decodedText = state.decodedMessages.get(storedMessage.id) ?? decodeBitStream(payload);
  const levels = nrziEncode(payload);
  const content = $('#inspectorContent');
  const visibleFrames = frames.slice(0, 120);
  const truncated = frames.length > visibleFrames.length;
  const hexBytes = visibleFrames.map((frame) => frame.code.toString(16).padStart(2, '0').toUpperCase()).join(' ');
  const asciiBits = visibleFrames.map((frame) => frame.data).join(' ');
  const framedBits = visibleFrames.map((frame) => frame.bits).join(' ');
  const levelPreview = levels.slice(0, 240).map((level) => level === 1 ? 'H' : 'L').join(' ');

  content.innerHTML = `
    <div class="inspector-summary">
      <div class="metric-card"><span>Characters</span><strong>${frames.length}</strong></div>
      <div class="metric-card"><span>Payload bits</span><strong>${payload.length}</strong></div>
      <div class="metric-card"><span>Hex bytes</span><strong>${frames.length}</strong></div>
      <div class="metric-card"><span>Frame size</span><strong>10 bit</strong></div>
    </div>
    <section class="inspector-section">
      <h3>Decoded message</h3>
      <div class="inspector-decoded-message">${escapeHTML(decodedText)}</div>
    </section>
    <section class="inspector-section">
      <h3>Transmission format</h3>
      <p>Each printable ASCII character uses one 10-bit frame: start bit <strong>0</strong>, seven data bits, one even-parity bit, then stop bit <strong>1</strong>. NRZ-I changes the signal level for bit 1 and keeps the previous level for bit 0.</p>
      <p class="inspector-frame-format">FRAME = START · DATA[7] · PARITY · STOP</p>
    </section>
    <section class="inspector-section">
      <h3>NRZ-I waveform</h3>
      <div class="signal-scroll"><canvas id="inspectorSignal" class="signal-large"></canvas></div>
      <p class="inspector-wave-note">${truncated ? 'Waveform preview shows the first 120 frames to keep the browser responsive.' : 'Complete waveform for this message.'} The initial signal level is HIGH.</p>
    </section>
    <section class="inspector-section">
      <h3>Hexadecimal bytes</h3>
      <p class="inspector-code-block">${hexBytes}${truncated ? ' …' : ''}</p>
      <p class="inspector-wave-note">${truncated ? 'Showing the first 120 characters; the complete list is available in the frame table.' : 'One hexadecimal byte for each printable ASCII character.'}</p>
    </section>
    <section class="inspector-section">
      <h3>ASCII binary · 7 bit per character</h3>
      <p class="inspector-code-block">${asciiBits}${truncated ? ' …' : ''}</p>
    </section>
    <section class="inspector-section">
      <h3>Framed binary · 10 bit per character</h3>
      <p class="inspector-code-block">${framedBits}${truncated ? ' …' : ''}</p>
      <p class="inspector-wave-note">Each frame = start bit + 7 data bits + even parity + stop bit.</p>
    </section>
    <section class="inspector-section">
      <h3>NRZ-I signal levels · HIGH / LOW</h3>
      <p class="inspector-code-block">${levelPreview}${levels.length > 240 ? ' …' : ''}</p>
      <p class="inspector-wave-note">H = HIGH and L = LOW. A transmitted 1 changes the level; a 0 keeps it.</p>
    </section>
    <section class="inspector-section">
      <h3>Frame breakdown</h3>
      <div class="inspector-table-wrap">
        <table class="inspector-table">
          <thead><tr><th>#</th><th>ASCII</th><th>Decimal</th><th>Hex</th><th>Data (7)</th><th>Parity</th><th>Frame (10)</th></tr></thead>
          <tbody>${frames.map((frame) => {
            const hex = frame.code.toString(16).padStart(2, '0').toUpperCase();
            const character = frame.character === ' ' ? 'SPACE' : frame.character;
            return `<tr><td>${frame.index}</td><td>${escapeHTML(character)}</td><td>${frame.code}</td><td>${hex}</td><td>${frame.data}</td><td>${frame.parity}</td><td>${frame.bits}</td></tr>`;
          }).join('')}</tbody>
        </table>
      </div>
    </section>
    <section class="inspector-section">
      <h3>Validation result</h3>
      <p class="inspector-validation">✓ Start bits, stop bits, frame length, and even parity are valid. ${levels.length} signal levels generated.</p>
    </section>
  `;
  openDialog(inspectorDialog);
  drawSignal($('#inspectorSignal'), payload);
}

$('#messages').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-action]');
  if (!button) return;
  const message = state.messages.find((item) => item.id === button.dataset.messageId);
  if (!message) return;
  if (button.dataset.action === 'unlock-message') {
    const form = $('#messageUnlockForm');
    form.reset();
    form.dataset.messageId = message.id;
    openDialog(messageUnlockDialog);
    $('#messageUnlockPassphrase').focus();
    return;
  }
  if (button.dataset.action === 'delete') {
    if (!window.confirm('Hapus pesan ini untuk kedua pihak? Pesan akan dihapus permanen dari percakapan.')) return;
    button.disabled = true;
    try {
      const removed = await deleteMessageForEveryone(message.id);
      await handleMessageDelete(message.id);
      showToast(removed ? 'Pesan dihapus untuk kedua pihak.' : 'Pesan sudah tidak tersedia.', 'success');
    } catch (error) {
      button.disabled = false;
      showToast(friendlyError(error, 'Pesan gagal dihapus.'), 'error');
    }
    return;
  }
  if (button.dataset.action === 'toggle-view') {
    if (!state.bitsByMessage.has(message.id) || !state.decodedMessages.has(message.id)) return;
    const currentMode = state.messageViewModes.get(message.id) || 'decoded';
    state.messageViewModes.set(message.id, currentMode === 'signal' ? 'decoded' : 'signal');
    renderMessages();
    return;
  }
  if (button.dataset.action === 'inspect') openInspector(message);
});

$('#mobileSidebarOpen').addEventListener('click', () => {
  setAppView('contacts');
});
$('#mobileSidebarClose')?.addEventListener('click', () => {
  setAppView('contacts');
});

document.addEventListener('keydown', (event) => {
  if (event.key === '/' && !event.ctrlKey && !event.metaKey && !event.altKey) {
    const tag = document.activeElement?.tagName;
    if (!['INPUT', 'TEXTAREA'].includes(tag) && !event.target.isContentEditable && !appView.hidden) {
      event.preventDefault();
      $('#contactSearch').focus();
    }
  }
  if (event.key === 'Escape') {
    $('#sidebar').classList.remove('mobile-open');
    if (!document.querySelector('dialog[open]')) appView.classList.remove('has-chat');
  }
});

$('#securityView')?.addEventListener('click', (event) => {
  const button = event.target.closest('[data-device-action]');
  if (button) resolveDevice(button);
});

initialize();