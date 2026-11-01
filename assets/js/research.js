(() => {
  const index = document.querySelector('[data-research-index]');
  if (!index) return;
  const search = index.querySelector('[data-search]');
  const buttons = [...index.querySelectorAll('[data-filter]')];
  const entries = [...index.querySelectorAll('[data-entry]')];
  const empty = index.querySelector('[data-empty]');
  let category = 'all';
  const filter = () => {
    const query = search.value.trim().toLowerCase();
    let shown = 0;
    for (const entry of entries) {
      const matches = (category === 'all' || entry.dataset.category === category) && (!query || entry.textContent.toLowerCase().includes(query));
      entry.hidden = !matches;
      if (matches) shown++;
    }
    empty.hidden = shown > 0;
  };
  search.addEventListener('input', filter);
  for (const button of buttons) button.addEventListener('click', () => {
    category = button.dataset.filter;
    buttons.forEach(item => item.setAttribute('aria-pressed', String(item === button)));
    filter();
  });
})();
