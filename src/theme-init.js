// Runs before first paint to avoid a theme flash. It lives in its own file because
// the Content-Security-Policy does not allow inline scripts.
(() => {
  const root = document.documentElement;
  let theme = 'light';
  try {
    theme = localStorage.getItem('syntrix-theme') === 'dark' ? 'dark' : 'light';
  } catch (_) { /* storage may be unavailable */ }
  root.dataset.theme = theme;
  root.style.colorScheme = theme;
})();
