import { promoteToastLayer } from './toast.js';

export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

export function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

export function initials(name = '') {
  const clean = String(name).trim();
  return clean ? Array.from(clean)[0].toUpperCase() : '?';
}

export function formatTime(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return new Intl.DateTimeFormat(document.documentElement.lang === 'id' ? 'id-ID' : 'en-US', { hour: '2-digit', minute: '2-digit' }).format(date);
}

export function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return new Intl.DateTimeFormat(document.documentElement.lang === 'id' ? 'id-ID' : 'en-US', {
    day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit',
  }).format(date);
}

export function setBusy(button, busy, busyLabel = 'Memproses...') {
  if (!button) return;
  if (busy) {
    button.dataset.originalLabel = button.innerHTML;
    button.disabled = true;
    button.innerHTML = `<span class="button-spinner" aria-hidden="true"></span>${escapeHTML(busyLabel)}`;
  } else {
    button.disabled = false;
    if (button.dataset.originalLabel) button.innerHTML = button.dataset.originalLabel;
    delete button.dataset.originalLabel;
  }
}

export function openDialog(dialog) {
  if (!dialog) return;
  if (typeof dialog.showModal === 'function' && !dialog.open) {
    dialog.showModal();
    promoteToastLayer();
  }
}

export function closeDialog(dialog) {
  if (!dialog) return;
  if (dialog.open && typeof dialog.close === 'function') dialog.close();
}
