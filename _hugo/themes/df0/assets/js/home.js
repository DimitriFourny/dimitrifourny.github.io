import { createAttractor } from './attractor.js';

(() => {
  'use strict';

  const canvas = document.getElementById('df-flow-canvas');
  if (!canvas) return;
  const context = canvas.getContext('2d', { alpha: false });
  if (!context) return;
  const figure = canvas.closest('.df-flow');
  const toggle = figure.querySelector('.df-motion-toggle');
  const hint = figure.querySelector('.df-pointer-hint');
  const preference = window.matchMedia('(prefers-reduced-motion: reduce)');
  const pointer = window.matchMedia('(pointer: coarse)');
  const engine = createAttractor(context, {
    coarse: pointer.matches,
    colors: ['#68462f', '#b97849', '#e7a578', '#d4c6b2'],
    paper: '#111210'
  });
  let frame = 0;
  let lastTime = 0;
  let visible = true;
  let paused = false;
  let pixels = 0;
  let tapRemaining = 0;
  let touch = null;

  function running() {
    return !paused && !preference.matches && visible && !document.hidden;
  }

  function clearInteraction() {
    tapRemaining = 0;
    touch = null;
    engine.clearPointer();
  }

  function updateHint() {
    hint.textContent = pointer.matches
      ? ' · Tap to tilt'
      : ' · Move your cursor to tilt';
  }

  function tick(time) {
    frame = 0;
    if (!running()) return;
    const elapsed = time - lastTime;
    if (elapsed >= 1000 / 30) {
      const dt = lastTime ? Math.min(elapsed / 1000, 0.05) : 1 / 30;
      if (tapRemaining > 0) {
        tapRemaining -= dt;
        if (tapRemaining <= 0) clearInteraction();
      }
      engine.step(dt);
      lastTime = time;
    }
    frame = requestAnimationFrame(tick);
  }

  function sync() {
    cancelAnimationFrame(frame);
    frame = 0;
    clearInteraction();
    if (preference.matches) engine.finishIntro();
    toggle.hidden = preference.matches;
    figure.toggleAttribute('data-running', running());
    toggle.setAttribute('aria-pressed', String(paused));
    toggle.setAttribute('aria-label', paused ? 'Resume artwork animation' : 'Pause artwork animation');
    toggle.innerHTML = paused ? 'Resume <span aria-hidden="true">▷</span>' : 'Pause <span aria-hidden="true">Ⅱ</span>';
    if (running()) {
      lastTime = 0;
      frame = requestAnimationFrame(tick);
    }
  }

  function resize() {
    const size = canvas.getBoundingClientRect().width;
    const nextPixels = Math.min(1100, Math.round(size * Math.min(window.devicePixelRatio || 1, 1.5)));
    if (!nextPixels || nextPixels === pixels) return;
    pixels = nextPixels;
    canvas.width = canvas.height = pixels;
    engine.resize(pixels);
    figure.dataset.rendered = '';
  }

  function interact(event) {
    const bounds = canvas.getBoundingClientRect();
    if (!bounds.width || !bounds.height) return;
    engine.setPointer(
      Math.max(0, Math.min(1, (event.clientX - bounds.left) / bounds.width)),
      Math.max(0, Math.min(1, (event.clientY - bounds.top) / bounds.height))
    );
  }

  // A short tap tilts the artwork; a swipe retains native page scrolling.
  // No pointer capture, preventDefault, or touch-action override is needed.
  canvas.addEventListener('pointerdown', event => {
    if (event.pointerType === 'mouse' || !event.isPrimary || !running()) return;
    touch = { id: event.pointerId, x: event.clientX, y: event.clientY, time: event.timeStamp };
  });
  canvas.addEventListener('pointermove', event => {
    if (event.pointerType === 'mouse') {
      if (!running()) return;
      tapRemaining = 0;
      interact(event);
    } else if (touch && touch.id === event.pointerId
      && Math.hypot(event.clientX - touch.x, event.clientY - touch.y) > 10) {
      touch = null;
    }
  });
  canvas.addEventListener('pointerup', event => {
    if (!touch || touch.id !== event.pointerId) return;
    if (running() && event.timeStamp - touch.time < 600
      && Math.hypot(event.clientX - touch.x, event.clientY - touch.y) <= 10) {
      interact(event);
      tapRemaining = 4;
    }
    touch = null;
  });
  canvas.addEventListener('pointercancel', () => { touch = null; });
  canvas.addEventListener('pointerleave', event => {
    if (event.pointerType === 'mouse') clearInteraction();
  });
  toggle.addEventListener('click', () => { paused = !paused; sync(); });
  preference.addEventListener('change', sync);
  pointer.addEventListener('change', updateHint);
  document.addEventListener('visibilitychange', sync);
  window.addEventListener('pagehide', () => { cancelAnimationFrame(frame); frame = 0; });
  window.addEventListener('pageshow', sync);
  updateHint();
  resize();
  sync();
  const visibility = new IntersectionObserver(entries => {
    visible = entries[0].isIntersecting;
    sync();
  });
  visibility.observe(canvas);
  const sizing = new ResizeObserver(() => resize());
  sizing.observe(canvas);
})();
