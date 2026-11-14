import { supabase } from './core/supabase.js';
import {
  decodeBitStream, nrziEncode, summarizeFrames, textToBitStream,
  validateBitStream, MAX_MESSAGE_LENGTH,
} from './core/encoding.js';
import {
  $, escapeHTML, formatTime, initials, openDialog, closeDialog, setBusy, showToast,
} from './core/dom.js';
import {
  getProfile, requestPasswordReset, signIn, signOut, signUp, updatePassword,
} from './services/auth.service.js';
import {
  deleteMessage, fetchMessageMeta, findProfileByHandle, getProfilesByIds, insertMessage,
  listContactIds, listRecentMessages, markConversationRead, saveContact,
} from './services/chat.service.js';
import {
  fetchKeyBundle, replaceWrappedKey, resetKeyBundle, saveKeyBundle,
} from './services/keys.service.js';
import {
  WrongUnlockKeyError, assertUnlockKey, decryptMessage, encryptMessage, generateIdentity,
  rewrapKeyBundle, unlockPrivateKey,
} from './core/e2ee.js';
import { connectRealtime } from './services/realtime.service.js';
import {
  acknowledgeDevice, fetchDevices, isSessionRevoked, registerDevice, rejectDevice,
} from './services/device.service.js';

// Read synchronously: Supabase clears the URL hash after it reads the emailed reset link.
const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ''));
const recoveryLink = hashParams.get('type') === 'recovery';
const linkError = hashParams.get('error_description');

const state = {
  recovering: recoveryLink, privateKey: null, keyBundle: null, keyExists: false, keyMode: 'create',
  failedMessages: new Set(), vanishing: new Set(),
  user: null, profile: null, contacts: [], messages: [], activeContactId: null,
  onlineUsers: new Set(), disconnectRealtime: null, decodedMessages: new Map(), bitsByMessage: new Map(),
  messageViewModes: new Map(), unlockTarget: null, bootingUserId: null, sending: false, keyReady: false,
  deviceRowId: null, knownPendingIds: null, endingSession: false,
};

// A safe sample waveform is shown while the real payload is protected by the key.
// The real NRZ-I waveform is rendered only after the payload has been authorized.
const LOCKED_SIGNAL_SAMPLE = textToBitStream('NRZI SAMPLE');

function createLockedSignalPreview(frameCount) {
  const previewFrames = Math.min(Math.max(Number(frameCount) || 1, 1), 24);
  const previewLength = previewFrames * 10;
  return LOCKED_SIGNAL_SAMPLE
    .repeat(Math.ceil(previewLength / LOCKED_SIGNAL_SAMPLE.length))
    .slice(0, previewLength);
}

const THEME_STORAGE_KEY = 'syntrix-theme';
const themeToggle = $('#themeToggle');
const themeModeLabel = $('#themeModeLabel');
const themeRoot = document.documentElement;

function syncThemeControl(theme) {
  if (themeToggle) themeToggle.checked = theme === 'dark';
  if (themeModeLabel) themeModeLabel.textContent = theme === 'dark' ? 'Dark' : 'Light';
}

function applyTheme(theme, trigger = themeToggle) {
  const nextTheme = theme === 'dark' ? 'dark' : 'light';
  const currentTheme = themeRoot.dataset.theme === 'dark' ? 'dark' : 'light';
  if (nextTheme === currentTheme) {
    syncThemeControl(currentTheme);
    return;
  }

  const triggerRect = trigger?.getBoundingClientRect?.();
  if (triggerRect) {
    themeRoot.style.setProperty('--theme-origin-x', `${triggerRect.left + triggerRect.width / 2}px`);
    themeRoot.style.setProperty('--theme-origin-y', `${triggerRect.top + triggerRect.height / 2}px`);
  }

  const updateTheme = () => {
    themeRoot.dataset.theme = nextTheme;
    syncThemeControl(nextTheme);
    try {
      localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
    } catch (error) {
      console.warn('Unable to persist theme preference:', error.message);
    }
  };

  const canAnimate = typeof document.startViewTransition === 'function'
    && !window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  if (canAnimate) {
    // Restore the old switch position for the outgoing snapshot; update it with the new theme.
    if (themeToggle) themeToggle.checked = currentTheme === 'dark';
    const transition = document.startViewTransition(updateTheme);
    transition.finished.then(
      () => {
        themeRoot.style.removeProperty('--theme-origin-x');
        themeRoot.style.removeProperty('--theme-origin-y');
      },
      () => {
        themeRoot.style.removeProperty('--theme-origin-x');
        themeRoot.style.removeProperty('--theme-origin-y');
      }
    );
  } else {
    updateTheme();
    themeRoot.style.removeProperty('--theme-origin-x');
    themeRoot.style.removeProperty('--theme-origin-y');
  }
}

syncThemeControl(themeRoot.dataset.theme === 'dark' ? 'dark' : 'light');
themeToggle?.addEventListener('change', () => {
  const switchTrack = themeToggle.parentElement?.querySelector('.theme-switch-track') || themeToggle;
  applyTheme(themeToggle.checked ? 'dark' : 'light', switchTrack);
});

const authView = $('#authView');
const appView = $('#appView');
const loginForm = $('#loginForm');
const registerForm = $('#registerForm');
const contactDialog = $('#contactDialog');
const unlockDialog = $('#unlockDialog');
const keyDialog = $('#keyDialog');
const forgotForm = $('#forgotForm');
const resetView = $('#resetView');
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
  const isForgot = mode === 'forgot';
  const isLogin = !isRegister && !isForgot;
  loginForm.hidden = !isLogin;
  registerForm.hidden = !isRegister;
  forgotForm.hidden = !isForgot;
  $('#showLoginBtn').classList.toggle('is-active', isLogin);
  $('#showRegisterBtn').classList.toggle('is-active', isRegister);
  $('#showLoginBtn').setAttribute('aria-selected', String(isLogin));
  $('#showRegisterBtn').setAttribute('aria-selected', String(isRegister));
  $('#authTitle').textContent = isRegister
    ? 'Create your SYNTRIX identity'
    : isForgot ? 'Reset your password' : 'Sign in to your space';
  $('#authSubtitle').textContent = isRegister
    ? 'Choose a handle your friends can use to find you.'
    : isForgot
      ? 'Masukkan email akunmu. Kami kirim link untuk membuat password baru.'
      : 'Continue where your conversations left off.';
}

$('#showLoginBtn').addEventListener('click', () => setAuthMode('login'));
$('#showRegisterBtn').addEventListener('click', () => setAuthMode('register'));

function friendlyError(error, fallback = 'Something went wrong. Please try again.') {
  const message = String(error?.message ?? '');
  if (error instanceof WrongUnlockKeyError) return error.message;
  if (/^(Kunci|Jumlah iterasi|Data kunci|Format data|Enkripsi membutuhkan)/.test(message)) return message;
  if (/keys_exist/i.test(message)) return 'Kunci pembuka sudah dibuat di perangkat lain. Muat ulang halaman.';
  if (/new password should be different/i.test(message)) return 'Password baru harus berbeda dari password lama.';
  if (/password.*(at least|too short|weak)/i.test(message)) return 'Password terlalu lemah. Gunakan minimal 8 karakter.';
  if (/auth session missing|invalid.*(token|jwt)|otp.*expired/i.test(message)) return 'Link reset tidak valid atau sudah kedaluwarsa. Minta link baru lewat "Lupa password?".';
  if (/invalid login credentials/i.test(message)) return 'Email atau password tidak cocok.';
  if (/email not confirmed/i.test(message)) return 'Email belum dikonfirmasi. Periksa kotak masuk email kamu.';
  if (/user already registered/i.test(message)) return 'Email ini sudah terdaftar. Silakan masuk.';
  if (/duplicate key|unique constraint|profiles_handle_key/i.test(message)) return 'Handle tersebut sudah digunakan. Pilih handle lain.';
  if (/rate[ _]?limit/i.test(message)) return 'Terlalu banyak percobaan. Coba lagi nanti.';
  if (/database error saving new user/i.test(message)) return 'Pendaftaran gagal. Coba handle lain.';
  if (/failed to fetch|networkerror|load failed/i.test(message)) return 'Tidak dapat terhubung ke server. Periksa internet dan konfigurasi Supabase.';
  if (/row-level security|permission denied/i.test(message)) return 'Akses database ditolak. Periksa migration dan kebijakan RLS Supabase.';
  if (/device_not_trusted/i.test(message)) return 'Perangkat ini belum dikonfirmasi sebagai milikmu, jadi belum bisa mengelola perangkat lain.';
  if (/session_revoked/i.test(message)) return 'Sesi ini sudah dikeluarkan dari perangkat lain.';
  if (/device_limit/i.test(message)) return 'Terlalu banyak perangkat tercatat di akun ini. Keluarkan perangkat yang tidak dipakai.';
  if (/cannot_reject_self/i.test(message)) return 'Perangkat yang sedang kamu pakai tidak bisa dikeluarkan dari sini. Gunakan tombol Keluar.';
  console.warn('Unhandled error:', error);
  return fallback;
}

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#loginSubmit');
  setBusy(button, true, 'Signing in...');
  try {
    state.recovering = false;
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

$('#forgotLink').addEventListener('click', () => {
  $('#forgotEmail').value = $('#loginEmail').value.trim();
  setAuthMode('forgot');
  $('#forgotEmail').focus();
});
$('#forgotBackBtn').addEventListener('click', () => setAuthMode('login'));

forgotForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#forgotSubmit');
  setBusy(button, true, 'Mengirim...');
  try {
    await requestPasswordReset($('#forgotEmail').value.trim());
    // Same message whether or not the address exists, so emails cannot be probed.
    showToast('Jika email terdaftar, link reset password sudah dikirim. Periksa kotak masuk dan folder spam.', 'success');
    setAuthMode('login');
  } catch (error) {
    showToast(friendlyError(error, 'Gagal mengirim email reset.'), 'error');
  } finally {
    setBusy(button, false);
  }
});

// The emailed link opens the app with a short-lived recovery session. Show a dedicated
// "change password" page instead of entering the workspace.
function showResetView() {
  authView.hidden = true;
  appView.hidden = true;
  resetView.hidden = false;
  $('#resetNewPassword').focus();
}

function hideResetView() {
  resetView.hidden = true;
  $('#resetPasswordForm').reset();
  authView.hidden = false;
  setAuthMode('login');
}

async function cancelRecovery() {
  state.recovering = false;
  hideResetView();
  try {
    await supabase.auth.signOut({ scope: 'local' });
  } catch (error) {
    console.warn('Recovery sign-out failed:', error.message);
  }
  window.history.replaceState({}, '', '/');
}

$('#resetPasswordForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const password = $('#resetNewPassword').value;
  if (password.length < 8) {
    showToast('Password minimal 8 karakter.', 'error');
    return;
  }
  if (password !== $('#resetConfirmPassword').value) {
    showToast('Konfirmasi password tidak cocok.', 'error');
    return;
  }
  const button = $('#resetPasswordSubmit');
  setBusy(button, true, 'Menyimpan...');
  try {
    await updatePassword(password);
    state.recovering = false;
    hideResetView();
    window.history.replaceState({}, '', '/');
    showToast('Password berhasil diganti. Silakan masuk dengan password baru.', 'success');
    // Sign out everywhere so a session opened with the old password cannot stay alive.
    await signOut();
  } catch (error) {
    showToast(friendlyError(error, 'Gagal mengganti password.'), 'error');
  } finally {
    setBusy(button, false);
  }
});
$('#resetCancelBtn').addEventListener('click', cancelRecovery);

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
  $('#settingsAvatar').textContent = initials(name);
}

function renderKeyStatus() {
  const status = $('#keyStatus');
  if (!status) return;
  if (!state.keyExists) status.textContent = 'Belum dibuat. Buat kunci agar pesan bisa dikirim dan dibuka.';
  else if (state.keyReady) status.textContent = 'Aktif dan terbuka. Pesanmu dienkripsi end-to-end.';
  else status.textContent = 'Terkunci. Masukkan kunci untuk membuka pesan.';
}

function contactPreview(contactId) {
  const message = latestMessageFor(contactId);
  if (!message) return 'Start a conversation';
  const decoded = state.decodedMessages.get(message.id);
  if (decoded) return decoded;
  if (state.failedMessages.has(message.id)) return '⚠ Pesan tidak dapat dibuka';
  return `🔒 Pesan terenkripsi · ${message.frame_count} frames`;
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
  $('#contactCount').textContent = String(contacts.length);
  list.replaceChildren();

  if (filtered.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'list-empty';
    empty.textContent = contacts.length
      ? 'No conversations match your search.'
      : 'Your conversations will appear here. Add a contact to begin.';
    list.append(empty);
    return;
  }

  for (const contact of filtered) {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = `contact-item${contact.id === state.activeContactId ? ' is-active' : ''}`;
    const isOnline = state.onlineUsers.has(contact.id);
    const unread = unreadCountFor(contact.id);
    const lastMessage = latestMessageFor(contact.id);
    const lastTime = lastMessage ? formatTime(lastMessage.created_at) : '';
    const avatarHue = [...String(contact.id)].reduce((sum, character) => sum + character.charCodeAt(0), 0) % 360;
    item.setAttribute('aria-label', `Open conversation with ${contact.display_name}`);
    item.innerHTML = `
      <span class="contact-avatar-wrap">
        <span class="avatar contact-avatar" style="--avatar-hue: ${avatarHue}">${escapeHTML(initials(contact.display_name))}</span>
        <i class="status-indicator ${isOnline ? 'online' : ''}"></i>
      </span>
      <span class="contact-detail">
        <span class="contact-name-row">
          <strong>${escapeHTML(contact.display_name)}</strong>
          <span class="contact-handle">@${escapeHTML(contact.handle)}</span>
        </span>
        <span class="contact-status-line ${isOnline ? 'online' : ''}">${isOnline ? 'Online' : 'Offline'}</span>
        <span class="contact-preview">${escapeHTML(contactPreview(contact.id))}</span>
      </span>
      <span class="active-cutout active-cutout-top" aria-hidden="true"></span>
      <span class="active-cutout active-cutout-bottom" aria-hidden="true"></span>
      ${lastTime ? `<time class="contact-time">${escapeHTML(lastTime)}</time>` : ''}
      ${unread ? `<span class="unread-count">${unread > 99 ? '99+' : unread}</span>` : ''}
    `;
    item.addEventListener('click', () => selectContact(contact.id));
    list.append(item);
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
    empty.innerHTML = '<strong>No transmissions yet</strong>Write the first message below. It is encrypted in your browser, then framed and encoded before it is stored.';
    container.append(empty);
    return;
  }

  for (const message of messages) {
    const mine = message.sender_id === state.user.id;
    const isUnlocked = state.decodedMessages.has(message.id);
    const decoded = state.decodedMessages.get(message.id);
    const frameCount = message.frame_count;
    const failed = state.failedMessages.has(message.id);
    const displayMode = isUnlocked ? (state.messageViewModes.get(message.id) || 'decoded') : 'signal';
    const showSignal = !failed && (!isUnlocked || displayMode === 'signal');
    const row = document.createElement('article');
    row.className = `message-row${mine ? ' mine' : ''}`;
    row.dataset.messageId = message.id;
    const timestamp = formatTime(message.created_at);
    let action = '';
    if (isUnlocked) {
      action = `<button class="inspect-button" type="button" data-action="toggle-view" data-message-id="${message.id}">${showSignal ? 'Tampilkan pesan' : 'Tampilkan sinyal NRZ-I'}</button>`;
    } else if (!failed) {
      action = `<button class="inspect-button" type="button" data-action="unlock" data-message-id="${message.id}">${state.keyExists ? 'Masukkan kunci' : 'Buat kunci'}</button>`;
    }
    const deleteButton = `<button class="inspect-button message-delete" type="button" data-action="delete" data-message-id="${message.id}" aria-label="Hapus pesan">Hapus</button>`;

    row.innerHTML = `
      <span class="message-author">${mine ? 'You' : escapeHTML(state.contacts.find((c) => c.id === message.sender_id)?.display_name || 'Contact')}</span>
      <div class="message-bubble">
        ${showSignal
          ? '<div class="wave-mini-wrap"><canvas class="wave-mini" aria-label="NRZ-I waveform"></canvas></div>'
          : '<div class="decode-result"><span class="decoded-text"></span></div>'}
        <div class="message-actions">${action}${deleteButton}</div>
      </div>
      <div class="message-bottom"><span>${escapeHTML(timestamp)}</span>${mine && message.read_at ? '<span class="message-read">· Read</span>' : ''}</div>
    `;

    if (showSignal) {
      // The stored bits are ciphertext, so showing the real waveform leaks nothing.
      renderMiniSignal(row.querySelector('canvas'), message.payload_bits || createLockedSignalPreview(frameCount));
    } else {
      const textNode = row.querySelector('.decoded-text');
      if (failed) {
        textNode.textContent = 'Pesan tidak dapat dibuka dengan kuncimu.';
        textNode.classList.add('is-failed');
      } else {
        textNode.textContent = decoded;
      }
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
  $('#chatName').textContent = `${contact.display_name} · @${contact.handle}`;
  const online = state.onlineUsers.has(contact.id);
  $('#chatStatus').textContent = online ? 'Online' : 'Offline';
  $('#chatStatusDot').classList.toggle('online', online);
}

async function selectContact(contactId) {
  const contact = state.contacts.find((item) => item.id === contactId);
  if (!contact) return;

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

async function handleIncomingMessage(rawMessage) {
  if (rawMessage.sender_id !== state.user.id && rawMessage.receiver_id !== state.user.id) return;
  // Realtime does not carry payload_bits or frame_count, so load the full (ciphertext) row.
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
  await decryptMessageRow(state.messages.find((item) => item.id === message.id) ?? message);

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

// ---- End-to-end encryption helpers -------------------------------------------

function bundleOf(identity) {
  return {
    publicKey: identity.publicKey,
    wrappedPrivateKey: identity.wrappedPrivateKey,
    kdfSalt: identity.kdfSalt,
    kdfIterations: identity.kdfIterations,
  };
}

// A contact may have reset their keys since this browser loaded their profile.
async function refreshContactKey(contactId) {
  const contact = state.contacts.find((item) => item.id === contactId);
  if (!contact) return null;
  try {
    const [profile] = await getProfilesByIds([contactId]);
    if (profile?.public_key) contact.public_key = profile.public_key;
  } catch (error) {
    console.warn('Unable to refresh contact key:', error.message);
  }
  return contact;
}

async function decryptMessageRow(message, canRetry = true) {
  if (!state.privateKey || !message) return;
  const peerId = partnerId(message);
  try {
    const peer = state.contacts.find((item) => item.id === peerId);
    if (!peer?.public_key) throw new Error('Kunci publik kontak tidak tersedia.');
    const payload = decodeBitStream(message.payload_bits);
    const text = await decryptMessage({
      payload,
      privateKey: state.privateKey,
      peerPublicKey: peer.public_key,
      senderId: message.sender_id,
      receiverId: message.receiver_id,
    });
    state.decodedMessages.set(message.id, text);
    state.bitsByMessage.set(message.id, message.payload_bits);
    state.failedMessages.delete(message.id);
  } catch (error) {
    if (canRetry) {
      await refreshContactKey(peerId);
      await decryptMessageRow(message, false);
      return;
    }
    state.failedMessages.add(message.id);
    console.warn('Unable to decrypt message:', error.message);
  }
}

async function decryptAll() {
  await Promise.all(state.messages.map((message) => decryptMessageRow(message, false)));
}

// ---- Deleting messages --------------------------------------------------------

function forgetMessage(id) {
  state.messages = state.messages.filter((message) => message.id !== id);
  state.decodedMessages.delete(id);
  state.bitsByMessage.delete(id);
  state.messageViewModes.delete(id);
  state.failedMessages.delete(id);
}

// The bubble shrinks into its own corner while the row collapses, so the messages
// below slide up into the gap. No fade: the message is simply sucked away.
function animateRemoveMessage(id) {
  const container = $('#messages');
  const row = [...container.children].find((element) => element.dataset?.messageId === id);
  if (!row || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return Promise.resolve();
  const gap = Number.parseFloat(window.getComputedStyle(container).rowGap) || 0;
  row.style.height = `${row.offsetHeight}px`;
  row.style.setProperty('--collapse-gap', `-${gap}px`);
  void row.offsetHeight;
  row.classList.add('is-deleting');
  return new Promise((resolve) => window.setTimeout(resolve, 380));
}

async function vanishMessage(id) {
  if (state.vanishing.has(id)) return;
  state.vanishing.add(id);
  try {
    await animateRemoveMessage(id);
  } finally {
    forgetMessage(id);
    state.vanishing.delete(id);
    renderMessages();
    renderContacts();
  }
}

// Realtime DELETE events only carry the id. Unknown ids belong to other people's chats.
function handleMessageDelete(row) {
  const id = row?.id;
  if (!id || !state.messages.some((message) => message.id === id)) return;
  vanishMessage(id);
}

async function removeMessage(message) {
  if (state.vanishing.has(message.id)) return;
  if (!window.confirm('Hapus pesan ini untuk kamu dan lawan bicaramu? Pesan hilang permanen dan tidak bisa dikembalikan.')) return;
  try {
    const removed = await deleteMessage(message.id);
    if (!removed) showToast('Pesan itu sudah tidak ada.', 'info');
    await vanishMessage(message.id);
  } catch (error) {
    showToast(friendlyError(error, 'Gagal menghapus pesan.'), 'error');
  }
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
  state.failedMessages.clear();
  state.privateKey = null;
  state.keyReady = false;

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

  const keyBundle = await fetchKeyBundle();
  state.keyBundle = keyBundle;
  state.keyExists = Boolean(keyBundle);
  renderKeyStatus();
  renderMessages();
  // First use: create the key. Otherwise unlock the stored one for this session.
  openSessionUnlock();

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
  if (!state.user) return;
  try {
    const devices = await fetchDevices();
    if (state.user) renderDevices(devices);
  } catch (error) {
    if (isSessionRevoked(error)) await endRevokedSession();
    else console.error('Device list failed:', error);
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
async function deviceTick() {
  if (deviceTickRunning || !state.user) return;
  deviceTickRunning = true;
  try {
    state.deviceRowId = await registerDevice();
    await refreshDevices();
  } catch (error) {
    if (isSessionRevoked(error)) await endRevokedSession();
    else console.warn('Device heartbeat failed:', error.message);
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
  await deviceTick();
  if (state.user && !state.endingSession) startDeviceHeartbeat();
}

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
  if (state.user?.id === user.id && !appView.hidden) return;
  state.bootingUserId = user.id;
  state.user = user;
  authView.hidden = true;
  appView.hidden = false;
  window.requestAnimationFrame(updateNavActivePill);
  $('#emptyState').hidden = false;
  $('#conversationView').hidden = true;
  $('#messages').replaceChildren();
  try {
    await loadWorkspace();
    await syncDevices();
  } catch (error) {
    showToast(friendlyError(error, 'Tidak dapat memuat workspace.'), 'error');
    console.error(error);
  } finally {
    state.bootingUserId = null;
  }
}

async function leaveApp() {
  stopDeviceHeartbeat();
  window.clearTimeout(deviceRefreshTimer);
  state.deviceRowId = null;
  state.knownPendingIds = null;
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
  state.failedMessages.clear();
  state.privateKey = null;
  state.keyBundle = null;
  state.keyExists = false;
  state.keyReady = false;
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

  // The emailed reset link creates a session, but it may only be used to set a new password.
  if (event === 'PASSWORD_RECOVERY') {
    state.recovering = true;
    showResetView();
    return;
  }
  if (state.recovering) return;

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
  // Show the page right away; do not wait for Supabase to report the recovery session.
  if (recoveryLink) showResetView();
  if (linkError) {
    showToast('Link reset password tidak valid atau sudah kedaluwarsa. Minta link baru lewat "Lupa password?".', 'error');
    window.history.replaceState({}, '', '/');
  }
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
$('#drawerAddContactBtn').addEventListener('click', () => $('#addContactBtn').click());

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
  const text = $('#messageInput').value.trim();
  if (!text) return;
  try {
    textToBitStream(text);
  } catch (error) {
    showToast(error.message, 'error');
    return;
  }

  state.sending = true;
  const button = $('#sendButton');
  button.disabled = true;
  try {
    if (!state.privateKey) {
      showToast('Buka kunci pembuka dulu agar pesan bisa dienkripsi.', 'error');
      openSessionUnlock();
      return;
    }
    // Always use the contact's newest public key; they may have reset theirs.
    const contact = await refreshContactKey(state.activeContactId);
    if (!contact?.public_key) {
      showToast(`${contact?.display_name ?? 'Kontak ini'} belum mengaktifkan enkripsi. Minta dia masuk dan membuat kunci pembuka dulu.`, 'error');
      return;
    }
    const payload = await encryptMessage({
      text,
      privateKey: state.privateKey,
      peerPublicKey: contact.public_key,
      senderId: state.user.id,
      receiverId: contact.id,
    });
    const message = await insertMessage(state.user.id, contact.id, payload);
    upsertMessage(message);
    state.decodedMessages.set(message.id, text);
    state.bitsByMessage.set(message.id, message.payload_bits);
    $('#messageInput').value = '';
    $('#messageCounter').textContent = `0 / ${MAX_MESSAGE_LENGTH}`;
    renderMessages();
    renderContacts();
  } catch (error) {
    showToast(friendlyError(error, 'Pesan gagal dikirim.'), 'error');
  } finally {
    state.sending = false;
    button.disabled = false;
    $('#messageInput').focus();
  }
});

// ---- Unlock key dialogs -------------------------------------------------------

const KEY_MODES = {
  create: {
    title: 'Buat kunci pembuka',
    desc: 'Kunci ini mengunci pesanmu dengan enkripsi end-to-end. Server tidak pernah menerimanya, jadi kalau kamu lupa, pesan lama tidak bisa dipulihkan. Pakai frasa yang panjang tapi mudah kamu ingat.',
    old: false,
    submit: 'Simpan kunci',
  },
  change: {
    title: 'Ganti kunci pembuka',
    desc: 'Pesanmu tetap bisa dibuka. Yang diganti hanya kunci yang melindungi kunci pribadimu.',
    old: true,
    submit: 'Ganti kunci',
  },
  reset: {
    title: 'Atur ulang kunci',
    desc: 'Karena kunci lama tidak diketahui, pasangan kunci baru dibuat. SEMUA pesanmu (terkirim dan diterima) dihapus permanen dan tidak bisa dipulihkan.',
    old: false,
    submit: 'Hapus pesan & atur ulang',
  },
};

function openKeyDialog(mode) {
  const config = KEY_MODES[mode];
  state.keyMode = mode;
  $('#keyForm').reset();
  $('#keyDialogTitle').textContent = config.title;
  $('#keyDialogDesc').textContent = config.desc;
  $('#oldKeyField').hidden = !config.old;
  $('#oldUnlockKey').required = config.old;
  $('#keySubmit').textContent = config.submit;
  keyDialog.classList.toggle('is-danger', mode === 'reset');
  openDialog(keyDialog);
}

function openSessionUnlock() {
  if (!state.keyExists) {
    openKeyDialog('create');
    return;
  }
  $('#unlockForm').reset();
  openDialog(unlockDialog);
  $('#unlockKeyInput').focus();
}

async function adoptKeyBundle(bundle, privateKey) {
  state.keyBundle = bundle;
  state.keyExists = true;
  state.privateKey = privateKey;
  state.keyReady = true;
  state.failedMessages.clear();
  await decryptAll();
  renderKeyStatus();
  renderMessages();
  renderContacts();
}

$('#unlockForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#unlockSubmit');
  setBusy(button, true, 'Membuka...');
  try {
    const privateKey = await unlockPrivateKey(state.keyBundle, $('#unlockKeyInput').value);
    closeDialog(unlockDialog);
    $('#unlockKeyInput').value = '';
    await adoptKeyBundle(state.keyBundle, privateKey);
    showToast('Pesan berhasil dibuka.', 'success');
  } catch (error) {
    showToast(friendlyError(error, 'Gagal membuka pesan.'), 'error');
  } finally {
    setBusy(button, false);
  }
});

$('#forgotKeyBtn').addEventListener('click', () => {
  closeDialog(unlockDialog);
  openKeyDialog('reset');
});

$('#keyForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const mode = state.keyMode;
  const key = $('#newUnlockKey').value;
  if (key !== $('#confirmUnlockKey').value) {
    showToast('Konfirmasi kunci tidak cocok.', 'error');
    return;
  }
  try {
    assertUnlockKey(key);
  } catch (error) {
    showToast(error.message, 'error');
    return;
  }
  if (mode === 'reset'
    && !window.confirm('Semua pesan yang kamu kirim dan terima akan dihapus permanen, juga di sisi lawan bicara. Lanjutkan?')) return;

  const button = $('#keySubmit');
  setBusy(button, true, 'Menyimpan...');
  try {
    if (mode === 'create') {
      const identity = await generateIdentity(key);
      await saveKeyBundle(identity);
      await adoptKeyBundle(bundleOf(identity), identity.privateKey);
    } else if (mode === 'change') {
      const current = await fetchKeyBundle();
      if (!current) throw new Error('Kunci belum dibuat.');
      const next = await rewrapKeyBundle(current, $('#oldUnlockKey').value, key);
      const saved = await replaceWrappedKey(current.wrappedPrivateKey, next);
      if (!saved) {
        state.keyBundle = await fetchKeyBundle();
        showToast('Kunci berubah dari perangkat lain. Coba lagi.', 'error');
        return;
      }
      const bundle = { ...current, ...next };
      await adoptKeyBundle(bundle, await unlockPrivateKey(bundle, key));
    } else {
      const identity = await generateIdentity(key);
      await resetKeyBundle(identity);
      state.messages = [];
      state.decodedMessages.clear();
      state.bitsByMessage.clear();
      state.messageViewModes.clear();
      await adoptKeyBundle(bundleOf(identity), identity.privateKey);
    }
    $('#keyForm').reset();
    closeDialog(keyDialog);
    showToast(mode === 'reset' ? 'Kunci baru dibuat. Pesan lama dihapus.' : 'Kunci pembuka berhasil disimpan.', 'success');
  } catch (error) {
    showToast(friendlyError(error, 'Gagal menyimpan kunci.'), 'error');
  } finally {
    setBusy(button, false);
  }
});

$('#changeKeyBtn').addEventListener('click', () => {
  openKeyDialog(state.keyExists ? 'change' : 'create');
});
$('#logoutBtn').addEventListener('click', async () => {
  const button = $('#logoutBtn');
  button.disabled = true;
  try {
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

for (const dialog of [contactDialog, unlockDialog, keyDialog, inspectorDialog]) {
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

$('#messages').addEventListener('click', (event) => {
  const button = event.target.closest('[data-action]');
  if (!button) return;
  const message = state.messages.find((item) => item.id === button.dataset.messageId);
  if (!message) return;
  if (button.dataset.action === 'delete') {
    removeMessage(message);
    return;
  }
  if (button.dataset.action === 'unlock') {
    openSessionUnlock();
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