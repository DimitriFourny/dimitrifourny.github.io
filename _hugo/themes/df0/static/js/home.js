(() => {
  const site = document.getElementById('df-homepage');
  if (!site) return;
  const hero = site.querySelector('.df-hero');
  const preference = window.matchMedia('(prefers-reduced-motion: reduce)');
  const duration = 900;
  const running = new Set();
  let lightFrame = 0;
  let revealObserver = null;
  function enabled() { return !preference.matches && typeof hero.animate === 'function'; }
  function stop() {
    running.forEach(animation => animation.cancel());
    running.clear();
    cancelAnimationFrame(lightFrame);
    lightFrame = 0;
  }
  function animate(element, frames, options) {
    if (!enabled()) return;
    const animation = element.animate(frames, { easing: 'cubic-bezier(.16,1,.3,1)', fill: 'backwards', ...options });
    running.add(animation);
    animation.finished.then(() => running.delete(animation)).catch(() => running.delete(animation));
  }
  function entrance(element, delay = 0, distance = 22) {
    animate(element, [{ opacity: .08, transform: 'translateY(' + distance + 'px)' }, { opacity: 1, transform: 'translateY(0)' }], { duration, delay });
  }
  function intro() {
    if (!enabled()) return;
    animate(site.querySelector('.df-ambient-glow'), [
      { opacity: 0, transform: 'scale(.82) translateY(24px)' }, { opacity: .8, transform: 'scale(1) translateY(0)' }
    ], { duration: duration + 700 });
    animate(site.querySelector('.df-horizon'), [
      { opacity: 0, transform: 'perspective(260px) rotateX(50deg) translateY(30px)' }, { opacity: .6, transform: 'perspective(260px) rotateX(50deg) translateY(0)' }
    ], { duration: duration + 500, delay: 140 });
    animate(site.querySelector('.df-horizon-light'), [
      { opacity: 0, transform: 'scaleX(.15)' }, { opacity: .8, transform: 'scaleX(1)' }
    ], { duration: duration + 500, delay: 180 });
    [...site.querySelectorAll('[data-intro]')].forEach((element, i) => entrance(element, i * 85, i === 1 ? 28 : 18));
    entrance(site.querySelector('.df-terminal'), 180, 24);
    const command = site.querySelector('.df-terminal-typed');
    const outputDelay = duration + 650;
    animate(command, [{ clipPath: 'inset(0 100% 0 0)' }, { clipPath: 'inset(0 0% 0 0)' }], {
      duration: duration + 200, delay: 350, easing: 'steps(' + command.textContent.length + ', end)'
    });
    [...site.querySelectorAll('.df-terminal-output > span')].forEach((line, i) => animate(line, [
      { opacity: 0, transform: 'translateY(5px)' }, { opacity: 1, transform: 'translateY(0)' }
    ], { duration: 320, delay: outputDelay + i * 65 }));
    animate(site.querySelector('.df-terminal-ready'), [{ opacity: 0 }, { opacity: 1 }], { duration: 200, delay: outputDelay + 680 });
  }
  function renderPreference() {
    site.dataset.motion = enabled() ? 'on' : 'off';
    if (!enabled()) {
      stop();
      site.style.setProperty('--df-light-x', '80%');
      site.style.setProperty('--df-light-y', '48%');
    }
  }
  renderPreference();
  intro();
  if ('IntersectionObserver' in window) {
    revealObserver = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (!entry.isIntersecting) return;
        const panelIndex = [...site.querySelectorAll('.df-focus-panel')].indexOf(entry.target);
        entrance(entry.target, panelIndex < 0 ? 0 : panelIndex * 100, 20);
        revealObserver.unobserve(entry.target);
      });
    }, { threshold: .12 });
    site.querySelectorAll('.df-focus-panel,.df-writing').forEach(element => revealObserver.observe(element));
  }
  hero.addEventListener('pointermove', event => {
    if (!enabled() || event.pointerType !== 'mouse' || lightFrame) return;
    const bounds = hero.getBoundingClientRect();
    const x = 65 + (event.clientX - bounds.left) / bounds.width * 20;
    const y = 35 + (event.clientY - bounds.top) / bounds.height * 20;
    lightFrame = requestAnimationFrame(() => {
      site.style.setProperty('--df-light-x', x.toFixed(1) + '%');
      site.style.setProperty('--df-light-y', y.toFixed(1) + '%');
      lightFrame = 0;
    });
  });
  hero.addEventListener('pointerleave', () => {
    cancelAnimationFrame(lightFrame);
    lightFrame = 0;
    site.style.setProperty('--df-light-x', '80%');
    site.style.setProperty('--df-light-y', '48%');
  });
  preference.addEventListener('change', renderPreference);
  window.addEventListener('pagehide', () => {
    stop();
    revealObserver?.disconnect();
    preference.removeEventListener('change', renderPreference);
  }, { once: true });
})();
