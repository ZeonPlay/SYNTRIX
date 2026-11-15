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

function dismissToast(toast) {
  if (!toast || toast.dataset.leaving === 'true') return;

  toast.dataset.leaving = 'true';
  window.clearTimeout(toast.dismissTimer);
  toast.classList.remove('is-visible');

  window.setTimeout(() => {
    toast.remove();

    const region = $('#syntrixToastRegion');
    const layer = $('#syntrixToastLayer');
    if (region && !region.children.length && layer) {
      if (typeof layer.hidePopover === 'function' && layer.matches(':popover-open')) {
        layer.hidePopover();
      }
    }
  }, 260);
}

export function showToast(message, type = 'info') {
  const layer = $('#syntrixToastLayer');
  const region = $('#syntrixToastRegion');
  if (!layer || !region) return;

  // Keep one persistent popover open while notifications are visible.
  // Unlike toggling a dialog for every toast, this does not reset the animation.
  if (typeof layer.showPopover === 'function' && !layer.matches(':popover-open')) {
    layer.showPopover();
  }

  const toast = document.createElement('article');
  const safeType = ['success', 'error', 'info'].includes(type) ? type : 'info';
  toast.className = `syntrix-toast syntrix-toast--${safeType}`;
  toast.setAttribute('role', safeType === 'error' ? 'alert' : 'status');

  const icon = document.createElement('span');
  icon.className = 'syntrix-toast__icon';
  icon.setAttribute('aria-hidden', 'true');
  icon.textContent = safeType === 'success' ? '✓' : safeType === 'error' ? '!' : 'i';

  const text = document.createElement('span');
  text.className = 'syntrix-toast__message';
  text.textContent = String(message ?? '');

  const close = document.createElement('button');
  close.className = 'syntrix-toast__close';
  close.type = 'button';
  close.setAttribute('aria-label', 'Tutup notifikasi');
  close.textContent = '×';
  close.addEventListener('click', () => dismissToast(toast));

  toast.append(icon, text, close);
  region.append(toast);

  requestAnimationFrame(() => {
    if (toast.isConnected && toast.dataset.leaving !== 'true') {
      toast.classList.add('is-visible');
    }
  });

  toast.dismissTimer = window.setTimeout(() => dismissToast(toast), 4200);
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

    // Dialogs enter the top layer after the toast popover. Promote the
    // existing popover once, without rebuilding or restarting toast cards.
    const toastLayer = $('#syntrixToastLayer');
    if (toastLayer?.matches(':popover-open') && typeof toastLayer.hidePopover === 'function') {
      toastLayer.hidePopover();
      toastLayer.showPopover();
    }
  }
}

export function closeDialog(dialog) {
  if (!dialog) return;
  if (dialog.open && typeof dialog.close === 'function') dialog.close();
}
