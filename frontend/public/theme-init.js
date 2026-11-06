try {
  var t = localStorage.getItem('pcapvis.theme');
  if (t === 'dark' || t === 'light') document.documentElement.dataset.theme = t;
} catch (e) { /* storage unavailable: keep light default */ }
