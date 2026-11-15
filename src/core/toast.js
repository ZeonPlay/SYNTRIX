const TOAST_DURATION = 4200;
const TOAST_EXIT_DURATION = 260;

function getToastElements() {
  return {
    layer: document.getElementById('syntrixToastLayer'),
    region: document.getElementById('syntrixToastRegion'),
  };
}

function hideToastLayerIfEmpty(region, layer) {
  if (region.children.length > 0) return;

  if (typeof layer.hidePopover === 'function' && layer.matches(':popover-open')) {
    layer.hidePopover();
  }
}

function dismissToast(toast) {
  if (!toast || toast.dataset.leaving === 'true') return;

  toast.dataset.leaving = 'true';
  window.clearTimeout(toast.dismissTimer);
  toast.classList.remove('is-visible');

  window.setTimeout(() => {
    toast.remove();

    const { layer, region } = getToastElements();
    if (layer && region) hideToastLayerIfEmpty(region, layer);
  }, TOAST_EXIT_DURATION);
}

/**
 * Keep the toast popover above dialogs opened after a notification.
 * It is only promoted when a native modal actually opens, never per toast.
 */
export function promoteToastLayer() {
  const { layer, region } = getToastElements();
  if (!layer || !region?.children.length) return;
  if (typeof layer.hidePopover !== 'function' || !layer.matches(':popover-open')) return;

  // These calls happen in the same task. No card is recreated and no toast
  // animation is restarted while the popover moves to the top of the top layer.
  layer.hidePopover();
  layer.showPopover();
}

export function showToast(message, type = 'info') {
  const { layer, region } = getToastElements();
  if (!layer || !region) return;

  // Open the host only when the first notification arrives. Keep it open while
  // cards are present so later notifications do not cause a dialog/popover blink.
  if (typeof layer.showPopover === 'function' && !layer.matches(':popover-open')) {
    layer.showPopover();
  }

  const safeType = ['success', 'error', 'info'].includes(type) ? type : 'info';
  const toast = document.createElement('article');
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

  // Force the hidden starting state to be painted before starting the slide-in.
  void toast.offsetWidth;
  requestAnimationFrame(() => {
    if (toast.isConnected && toast.dataset.leaving !== 'true') {
      toast.classList.add('is-visible');
    }
  });

  toast.dismissTimer = window.setTimeout(() => dismissToast(toast), TOAST_DURATION);
}
