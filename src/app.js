import { supabase } from './core/supabase.js';
import {
  decodeBitStream, nrziEncode, summarizeFrames, textToBitStream,
  validateBitStream, MAX_MESSAGE_LENGTH,
} from './core/encoding.js';
import {
  $, escapeHTML, formatTime, initials, openDialog, closeDialog, setBusy, showToast,
} from './core/dom.js';
import {
  changeUnlockKey, getProfile, hasUnlockKey, setUnlockKey, signIn, signOut, signUp,
} from './services/auth.service.js';
import {
  fetchMessageBits, fetchMessageMeta, findProfileByHandle, getProfilesByIds, insertMessage,
  listContactIds, listRecentMessages, markConversationRead, saveContact,
} from './services/chat.service.js';
import { connectRealtime } from './services/realtime.service.js';

const state = {
  user: null, profile: null, contacts: [], messages: [], activeContactId: null,
  onlineUsers: new Set(), disconnectRealtime: null, decodedMessages: new Map(), bitsByMessage: new Map(),
  unlockTarget: null, bootingUserId: null, sending: false, keyReady: false,
};

const authView = $('#authView');
const appView = $('#appView');
const loginForm = $('#loginForm');
const registerForm = $('#registerForm');
const contactDialog = $('#contactDialog');
const unlockDialog = $('#unlockDialog');
const keyDialog = $('#keyDialog');
const inspectorDialog = $('#inspectorDialog');
const accountDialog = $('#accountDialog');

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

function contactPreview(contactId) {
  const message = latestMessageFor(contactId);
  if (!message) return 'Start a conversation';
  const decoded = state.decodedMessages.get(message.id);
  if (decoded) return decoded;
  return `🔒 Encoded transmission · ${message.frame_count} frames`;
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
    item.innerHTML = `
      <span class="contact-avatar-wrap">
        <span class="avatar contact-avatar">${escapeHTML(initials(contact.display_name))}</span>
        <i class="status-indicator ${isOnline ? 'online' : ''}"></i>
      </span>
      <span class="contact-detail">
        <span class="contact-name-row"><strong>${escapeHTML(contact.display_name)}</strong></span>
        <span class="contact-preview">${escapeHTML(contactPreview(contact.id))}</span>
      </span>
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
  const previewBits = bits.slice(0, 100 * 10);
  const levels = nrziEncode(previewBits);
  const bitWidth = 4;
  const height = 36;
  const width = Math.max(120, 12 + levels.length * bitWidth);
  const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
  canvas.width = Math.ceil(width * dpr);
  canvas.height = Math.ceil(height * dpr);
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);
  const yHigh = 10;
  const yLow = 26;

  ctx.strokeStyle = 'rgba(184,210,212,.12)';
  ctx.lineWidth = 1;
  for (let i = 0; i <= levels.length; i += 10) {
    const x = 6 + i * bitWidth;
    ctx.beginPath();
    ctx.moveTo(x, 3);
    ctx.lineTo(x, height - 3);
    ctx.stroke();
  }

  ctx.strokeStyle = '#83b9b3';
  ctx.lineWidth = 1.5;
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
    empty.innerHTML = '<strong>No transmissions yet</strong>Write the first message below. It will be framed and encoded before it is stored.';
    container.append(empty);
    return;
  }

  for (const message of messages) {
    const mine = message.sender_id === state.user.id;
    const decoded = state.decodedMessages.get(message.id);
    const frameCount = message.frame_count;
    const bits = state.bitsByMessage.get(message.id);
    const row = document.createElement('article');
    row.className = `message-row${mine ? ' mine' : ''}`;
    const timestamp = formatTime(message.created_at);
    const action = decoded
      ? `<button class="inspect-button" type="button" data-action="inspect" data-message-id="${message.id}">⌁ Transmission inspector</button>`
      : `<button class="inspect-button" type="button" data-action="unlock" data-message-id="${message.id}">⌑ Unlock message</button>`;

    row.innerHTML = `
      <span class="message-author">${mine ? 'You' : escapeHTML(state.contacts.find((c) => c.id === message.sender_id)?.display_name || 'Contact')}</span>
      <div class="message-bubble">
        <div class="message-lockline"><span class="message-lockicon">⌑</span><span>Encoded message</span></div>
        <div class="message-stats">${frameCount} FRAMES · ${frameCount * 10} BITS</div>
        ${bits ? '<div class="wave-mini-wrap"><canvas class="wave-mini" aria-label="NRZ-I waveform preview"></canvas></div>' : ''}
        ${decoded ? '<div class="decode-result"><div class="decode-result-label">DECODED TEXT</div><span class="decoded-text"></span></div>' : ''}
        <div class="message-actions">${action}</div>
      </div>
      <div class="message-bottom"><span>${escapeHTML(timestamp)}</span>${mine && message.read_at ? '<span class="message-read">· Read</span>' : ''}</div>
    `;

    renderMiniSignal(row.querySelector('canvas'), bits);
    if (decoded) row.querySelector('.decoded-text').textContent = decoded;
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
  state.activeContactId = contactId;
  const contact = state.contacts.find((item) => item.id === contactId);
  if (!contact) return;
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

  const keyExists = await hasUnlockKey();
  state.keyReady = keyExists;
  if (!keyExists) {
    $('#oldKeyField').hidden = true;
    $('#keyDialogTitle').textContent = 'Create your unlock key';
    $('#keyLabel').textContent = 'New unlock key';
    openDialog(keyDialog);
  }

  state.disconnectRealtime?.();
  state.disconnectRealtime = connectRealtime({
    userId,
    onMessage: handleIncomingMessage,
    onMessageUpdate: handleMessageUpdate,
    onPresence: (entries) => {
      state.onlineUsers = new Set(entries.map((entry) => entry.userId).filter(Boolean));
      renderContacts();
      updateConversationHeader();
    },
    onStatus: setConnection,
  });
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
  $('#emptyState').hidden = false;
  $('#conversationView').hidden = true;
  $('#messages').replaceChildren();
  try {
    await loadWorkspace();
  } catch (error) {
    showToast(friendlyError(error, 'Tidak dapat memuat workspace.'), 'error');
    console.error(error);
  } finally {
    state.bootingUserId = null;
  }
}

async function leaveApp() {
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
    const message = await insertMessage(state.user.id, state.activeContactId, text);
    upsertMessage(message);
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

function openUnlockDialog(message) {
  if (!state.keyReady) {
    openDialog(keyDialog);
    return;
  }
  state.unlockTarget = message;
  $('#unlockForm').reset();
  $('#unlockedMessage').hidden = true;
  $('#unlockedMessage').replaceChildren();
  $('#unlockSubmit').hidden = false;
  openDialog(unlockDialog);
  $('#unlockKeyInput').focus();
}

$('#unlockForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!state.unlockTarget) return;
  const button = $('#unlockSubmit');
  setBusy(button, true, 'Checking key...');
  try {
    const bits = await fetchMessageBits(state.unlockTarget.id, $('#unlockKeyInput').value);
    if (!bits) {
      showToast('Kunci salah atau sedang dikunci sementara karena terlalu banyak percobaan.', 'error');
      return;
    }
    const messageText = decodeBitStream(bits);
    state.bitsByMessage.set(state.unlockTarget.id, bits);
    state.decodedMessages.set(state.unlockTarget.id, messageText);
    const output = $('#unlockedMessage');
    output.hidden = false;
    output.innerHTML = '<div class="decode-result-label">DECODED TEXT</div><div class="decode-result"></div>';
    output.querySelector('.decode-result').textContent = messageText;
    $('#unlockSubmit').hidden = true;
    renderMessages();
    showToast('Pesan berhasil dibuka.', 'success');
  } catch (error) {
    showToast(friendlyError(error, 'Gagal membuka pesan.'), 'error');
  } finally {
    setBusy(button, false);
  }
});

$('#keyForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const key = $('#newUnlockKey').value;
  if (state.keyReady && !$('#oldUnlockKey').value) {
    showToast('Masukkan kunci lama terlebih dahulu.', 'error');
    return;
  }
  const confirmation = $('#confirmUnlockKey').value;
  if (key !== confirmation) {
    showToast('Konfirmasi kunci tidak cocok.', 'error');
    return;
  }
  if (key.length < 6 || new TextEncoder().encode(key).length > 72) {
    showToast('Kunci minimal 6 karakter dan maksimal 72 byte.', 'error');
    return;
  }

  const button = $('#keySubmit');
  setBusy(button, true, 'Saving key...');
  try {
    if (state.keyReady) {
      const changed = await changeUnlockKey($('#oldUnlockKey').value, key);
      if (!changed) {
        showToast('Kunci lama salah atau sedang dikunci sementara.', 'error');
        return;
      }
    } else {
      await setUnlockKey(key);
    }
    state.keyReady = true;
    $('#oldKeyField').hidden = true;
    $('#keyForm').reset();
    closeDialog(keyDialog);
    showToast('Kunci pembuka berhasil disimpan.', 'success');
  } catch (error) {
    showToast(friendlyError(error, 'Gagal menyimpan kunci.'), 'error');
  } finally {
    setBusy(button, false);
  }
});

$('#accountMenuBtn').addEventListener('click', () => openDialog(accountDialog));
$('#changeKeyBtn').addEventListener('click', () => {
  closeDialog(accountDialog);
  $('#keyForm').reset();
  $('#oldKeyField').hidden = false;
  $('#keyDialogTitle').textContent = 'Change your unlock key';
  $('#keyLabel').textContent = 'New unlock key';
  openDialog(keyDialog);
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

for (const dialog of [contactDialog, unlockDialog, keyDialog, inspectorDialog, accountDialog]) {
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
  ctx.fillStyle = '#718795';
  ctx.fillText('HIGH', 2, yHigh - 9);
  ctx.fillText('LOW', 2, yLow - 9);

  ctx.strokeStyle = 'rgba(173,203,208,.12)';
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
    ctx.strokeStyle = 'rgba(173,203,208,.18)';
    ctx.beginPath();
    ctx.moveTo(x, 20);
    ctx.lineTo(x, 126);
    ctx.stroke();
    if (i < levels.length) {
      ctx.fillStyle = '#748895';
      ctx.fillText(String(i / 10 + 1), x + 2, 140);
    }
  }

  ctx.strokeStyle = '#91c6bd';
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
  const message = { ...storedMessage, payload_bits: payload };
  const issue = validateBitStream(message.payload_bits);
  if (issue) {
    showToast(`Frame tidak valid: ${issue}`, 'error');
    return;
  }
  const frames = summarizeFrames(message.payload_bits);
  const levels = nrziEncode(message.payload_bits);
  const content = $('#inspectorContent');
  const firstBits = message.payload_bits.slice(0, 200);
  const truncated = frames.length > 120;

  content.innerHTML = `
    <div class="inspector-summary">
      <div class="metric-card"><span>Characters</span><strong>${frames.length}</strong></div>
      <div class="metric-card"><span>Total bits</span><strong>${message.payload_bits.length}</strong></div>
      <div class="metric-card"><span>Frame size</span><strong>10 bit</strong></div>
      <div class="metric-card"><span>Line code</span><strong>NRZ-I</strong></div>
    </div>
    <section class="inspector-section">
      <h3>Transmission format</h3>
      <p>Each character is framed as <strong>0</strong> start bit + <strong>7</strong> ASCII data bits + <strong>1</strong> even-parity bit + <strong>1</strong> stop bit. NRZ-I toggles the signal level when the encoded bit is 1; a 0 keeps the previous level.</p>
      <p style="margin-top:7px;color:#a5c8c2;font-family:var(--mono)">FRAME = START · DATA[7] · PARITY · STOP</p>
    </section>
    <section class="inspector-section">
      <h3>NRZ-I waveform</h3>
      <div class="signal-scroll"><canvas id="inspectorSignal" class="signal-large"></canvas></div>
      <p style="margin-top:8px">${truncated ? 'Waveform preview shows the first 120 frames to keep the browser responsive.' : 'Complete waveform for this message.'} The level begins at HIGH.</p>
    </section>
    <section class="inspector-section">
      <h3>Binary payload</h3>
      <p style="font-family:var(--mono);overflow-wrap:anywhere;color:#a8c2c1">${escapeHTML(firstBits)}${message.payload_bits.length > firstBits.length ? ' …' : ''}</p>
    </section>
    <section class="inspector-section">
      <h3>Frame breakdown</h3>
      <div class="inspector-table-wrap">
        <table class="inspector-table">
          <thead><tr><th>#</th><th>ASCII</th><th>Code</th><th>Data (7)</th><th>Parity</th><th>Frame (10)</th></tr></thead>
          <tbody>${frames.map((frame) => `<tr><td>${frame.index}</td><td>${escapeHTML(frame.character)}</td><td>${frame.code}</td><td>${frame.data}</td><td>${frame.parity}</td><td>${frame.bits}</td></tr>`).join('')}</tbody>
        </table>
      </div>
    </section>
    <section class="inspector-section">
      <h3>Validation result</h3>
      <p style="color:var(--green)">✓ Start bits, stop bits, frame length, and even parity are valid. ${levels.length} signal levels generated.</p>
    </section>
  `;
  openDialog(inspectorDialog);
  drawSignal($('#inspectorSignal'), message.payload_bits);
}

$('#messages').addEventListener('click', (event) => {
  const button = event.target.closest('[data-action]');
  if (!button) return;
  const message = state.messages.find((item) => item.id === button.dataset.messageId);
  if (!message) return;
  if (button.dataset.action === 'unlock') openUnlockDialog(message);
  if (button.dataset.action === 'inspect') openInspector(message);
});

$('#mobileSidebarOpen').addEventListener('click', () => $('#sidebar').classList.add('mobile-open'));
$('#mobileSidebarClose').addEventListener('click', () => $('#sidebar').classList.remove('mobile-open'));

document.addEventListener('keydown', (event) => {
  if (event.key === '/' && !event.ctrlKey && !event.metaKey && !event.altKey) {
    const tag = document.activeElement?.tagName;
    if (!['INPUT', 'TEXTAREA'].includes(tag) && !event.target.isContentEditable && !appView.hidden) {
      event.preventDefault();
      $('#contactSearch').focus();
    }
  }
  if (event.key === 'Escape') $('#sidebar').classList.remove('mobile-open');
});

initialize();