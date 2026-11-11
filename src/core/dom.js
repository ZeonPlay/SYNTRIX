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
  return new Intl.DateTimeFormat('id-ID', { hour: '2-digit', minute: '2-digit' }).format(date);
}

export function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return new Intl.DateTimeFormat('id-ID', {
    day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit',
  }).format(date);
}

export function showToast(message, type = 'info') {
  const region = $('#toastRegion');
  if (!region) return;
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
  toast.textContent = message;
  region.append(toast);
  requestAnimationFrame(() => toast.classList.add('toast-visible'));
  window.setTimeout(() => {
    toast.classList.remove('toast-visible');
    window.setTimeout(() => toast.remove(), 220);
  }, 3600);
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
  if (typeof dialog.showModal === 'function' && !dialog.open) dialog.showModal();
}

export function closeDialog(dialog) {
  if (!dialog) return;
  if (dialog.open && typeof dialog.close === 'function') dialog.close();
}
