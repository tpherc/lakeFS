(() => {
    let darkMode = false;
    try {
        darkMode = window.localStorage.getItem('darkMode') === 'true';
    } catch {
        // Storage may be unavailable; keep the default light theme.
    }
    document.documentElement.dataset.bsTheme = darkMode ? 'dark' : 'light';
})();
