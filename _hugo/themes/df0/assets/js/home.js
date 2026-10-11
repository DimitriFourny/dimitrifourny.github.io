(() => {
  'use strict';

  const canvas = document.getElementById('df-flow-canvas');
  if (!canvas) return;
  const context = canvas.getContext('2d', { alpha: false });
  if (!context) return;
  const figure = canvas.closest('.df-flow');
  const toggle = figure.querySelector('.df-motion-toggle');
  const preference = window.matchMedia('(prefers-reduced-motion: reduce)');
  const coarse = window.matchMedia('(pointer: coarse)').matches;
  const colors = ['#68462f', '#b97849', '#e7a578', '#d4c6b2'];
  const paper = '#111210';

  // A small incompressible velocity grid; the canvas only draws tracer paths.
  // Semi-Lagrangian advection, viscosity, and a pressure projection keep the
  // experiment bounded without a GPU dependency or a high-resolution dye grid.
  const n = coarse ? 72 : 96;
  const cells = n * n;
  let u = new Float32Array(cells);
  let v = new Float32Array(cells);
  let nextU = new Float32Array(cells);
  let nextV = new Float32Array(cells);
  const diffusedU = new Float32Array(cells);
  const diffusedV = new Float32Array(cells);
  const pressure = new Float32Array(cells);
  const divergence = new Float32Array(cells);
  const solid = new Uint8Array(cells);
  const obstacleRadius = n * 0.032;
  const obstacleRadiusSquared = obstacleRadius * obstacleRadius;
  const baseU = new Float32Array(cells);
  const baseV = new Float32Array(cells);
  const stream = new Float32Array(cells);
  const count = coarse ? 1800 : 3600;
  const x = new Float32Array(count);
  const y = new Float32Array(count);
  const age = new Float32Array(count);
  const cos = Math.cos(-0.58);
  const sin = Math.sin(-0.58);
  let seed = 431;
  let frame = 0;
  let lastTime = 0;
  let visible = true;
  let paused = false;
  let width = 0;
  let pointerX = -1;
  let pointerY = -1;
  let obstacleDirty = false;

  function random() {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed / 4294967296;
  }

  function spawn(i) {
    const angle = random() * Math.PI * 2;
    const radius = 0.18 + random() * 0.16 + 0.025 * Math.sin(angle * 3);
    const px = Math.cos(angle) * radius;
    const py = Math.sin(angle) * radius * 0.72;
    x[i] = (0.5 + px * cos - py * sin) * n;
    y[i] = (0.5 + px * sin + py * cos) * n;
    age[i] = 160 + random() * 320;
  }

  // Taking the curl of a stream function gives a divergence-free starting field.
  // The smaller, opposing vortex breaks the symmetry of the main circulation.
  for (let j = 0; j < n; j++) {
    for (let i = 0; i < n; i++) {
      const px = i / n - 0.5;
      const py = j / n - 0.5;
      const rx = px * cos + py * sin;
      const ry = -px * sin + py * cos;
      const satellite = (px - 0.17) ** 2 + (py + 0.12) ** 2;
      stream[i + j * n] = n * (0.15 * Math.exp(-rx * rx / 0.105 - ry * ry / 0.054)
        - 0.052 * Math.exp(-satellite / 0.008));
    }
  }
  for (let j = 1; j < n - 1; j++) {
    for (let i = 1; i < n - 1; i++) {
      const k = i + j * n;
      u[k] = baseU[k] = (stream[k + n] - stream[k - n]) * 0.5;
      v[k] = baseV[k] = (stream[k - 1] - stream[k + 1]) * 0.5;
    }
  }
  for (let i = 0; i < count; i++) spawn(i);

  function sample(field, px, py) {
    px = Math.max(0.5, Math.min(n - 1.5, px));
    py = Math.max(0.5, Math.min(n - 1.5, py));
    const left = Math.floor(px);
    const top = Math.floor(py);
    const k = left + top * n;
    const sx = px - left;
    const sy = py - top;
    return (field[k] * (1 - sx) + field[k + 1] * sx) * (1 - sy)
      + (field[k + n] * (1 - sx) + field[k + n + 1] * sx) * sy;
  }

  function updateObstacle() {
    solid.fill(0);
    if (pointerX >= 0) {
      for (let j = 1; j < n - 1; j++) {
        for (let i = 1; i < n - 1; i++) {
          const dx = i - pointerX;
          const dy = j - pointerY;
          solid[i + j * n] = dx * dx + dy * dy < obstacleRadiusSquared ? 1 : 0;
        }
      }
    }
    obstacleDirty = false;
  }

  function solve() {
    if (obstacleDirty) updateObstacle();
    for (let j = 1; j < n - 1; j++) {
      for (let i = 1; i < n - 1; i++) {
        const k = i + j * n;
        if (solid[k]) {
          u[k] = v[k] = 0;
          continue;
        }
        // A gentle, steady force sustains the circulation against viscosity.
        u[k] += (baseU[k] - u[k]) * 0.025;
        v[k] += (baseV[k] - v[k]) * 0.025;
      }
    }

    diffusedU.set(u);
    diffusedV.set(v);
    const viscosity = 0.035;
    const divisor = 1 + 4 * viscosity;
    for (let iteration = 0; iteration < 4; iteration++) {
      for (let j = 1; j < n - 1; j++) {
        for (let i = 1; i < n - 1; i++) {
          const k = i + j * n;
          if (solid[k]) continue;
          diffusedU[k] = (u[k] + viscosity * (diffusedU[k - 1] + diffusedU[k + 1] + diffusedU[k - n] + diffusedU[k + n])) / divisor;
          diffusedV[k] = (v[k] + viscosity * (diffusedV[k - 1] + diffusedV[k + 1] + diffusedV[k - n] + diffusedV[k + n])) / divisor;
        }
      }
    }
    for (let j = 1; j < n - 1; j++) {
      for (let i = 1; i < n - 1; i++) {
        const k = i + j * n;
        if (solid[k]) {
          nextU[k] = nextV[k] = 0;
          continue;
        }
        const px = i - diffusedU[k];
        const py = j - diffusedV[k];
        nextU[k] = sample(diffusedU, px, py);
        nextV[k] = sample(diffusedV, px, py);
      }
    }
    // No-through-flow boundaries. Pressure uses a zero-normal-gradient edge.
    for (let i = 0; i < n; i++) {
      nextU[i] = nextU[i + (n - 1) * n] = 0;
      nextV[i] = nextV[i + (n - 1) * n] = 0;
      nextU[i * n] = nextU[i * n + n - 1] = 0;
      nextV[i * n] = nextV[i * n + n - 1] = 0;
    }
    pressure.fill(0);
    for (let j = 1; j < n - 1; j++) {
      for (let i = 1; i < n - 1; i++) {
        const k = i + j * n;
        if (solid[k]) continue;
        divergence[k] = -0.5 * (nextU[k + 1] - nextU[k - 1] + nextV[k + n] - nextV[k - n]);
      }
    }
    for (let iteration = 0; iteration < 12; iteration++) {
      for (let j = 1; j < n - 1; j++) {
        for (let i = 1; i < n - 1; i++) {
          const k = i + j * n;
          if (solid[k]) continue;
          // A solid neighbour has zero normal pressure gradient. Excluding it
          // from the stencil prevents pressure from leaking through the body.
          const neighbours = 4 - solid[k - 1] - solid[k + 1] - solid[k - n] - solid[k + n];
          pressure[k] = neighbours ? (divergence[k]
            + (solid[k - 1] ? 0 : pressure[k - 1]) + (solid[k + 1] ? 0 : pressure[k + 1])
            + (solid[k - n] ? 0 : pressure[k - n]) + (solid[k + n] ? 0 : pressure[k + n])) / neighbours : 0;
        }
      }
      for (let i = 1; i < n - 1; i++) {
        pressure[i] = pressure[i + n];
        pressure[i + (n - 1) * n] = pressure[i + (n - 2) * n];
        pressure[i * n] = pressure[i * n + 1];
        pressure[i * n + n - 1] = pressure[i * n + n - 2];
      }
    }
    for (let j = 1; j < n - 1; j++) {
      for (let i = 1; i < n - 1; i++) {
        const k = i + j * n;
        if (solid[k]) continue;
        nextU[k] -= ((solid[k + 1] ? pressure[k] : pressure[k + 1])
          - (solid[k - 1] ? pressure[k] : pressure[k - 1])) * 0.5;
        nextV[k] -= ((solid[k + n] ? pressure[k] : pressure[k + n])
          - (solid[k - n] ? pressure[k] : pressure[k - n])) * 0.5;
        if (pointerX >= 0) {
          const dx = i - pointerX;
          const dy = j - pointerY;
          const distanceSquared = dx * dx + dy * dy;
          const collar = obstacleRadius + 1.5;
          if (distanceSquared < collar * collar) {
            // Resolve the curved, free-slip surface within the square grid:
            // remove normal velocity at the wall, retaining tangential flow.
            const weight = Math.min(1, (collar * collar - distanceSquared)
              / (collar * collar - obstacleRadiusSquared));
            const normal = (nextU[k] * dx + nextV[k] * dy) / distanceSquared;
            nextU[k] -= dx * normal * weight;
            nextV[k] -= dy * normal * weight;
          }
        }
      }
    }
    let swap = u; u = nextU; nextU = swap;
    swap = v; v = nextV; nextV = swap;
  }

  function draw() {
    context.fillStyle = 'rgba(17, 18, 16, 0.055)';
    context.fillRect(0, 0, n, n);
    context.lineWidth = 0.065;
    for (let color = 0; color < colors.length; color++) {
      context.beginPath();
      context.strokeStyle = colors[color];
      for (let i = color; i < count; i += colors.length) {
        const oldX = x[i];
        const oldY = y[i];
        if (pointerX >= 0) {
          const dx = oldX - pointerX;
          const dy = oldY - pointerY;
          const clearance = obstacleRadius + 0.6;
          const distance = Math.hypot(dx, dy);
          if (distance < obstacleRadius) {
            // A moving obstacle can cover existing tracers. Relocate these
            // without drawing a streak across the solid interior.
            const angle = Math.atan2(dy, dx);
            x[i] = pointerX + Math.cos(angle) * clearance;
            y[i] = pointerY + Math.sin(angle) * clearance;
            continue;
          }
        }
        // Midpoint integration makes tracer arcs smooth on the coarse grid.
        const midX = oldX + sample(u, oldX, oldY) * 0.5;
        const midY = oldY + sample(v, oldX, oldY) * 0.5;
        x[i] += sample(u, midX, midY);
        y[i] += sample(v, midX, midY);
        if (pointerX >= 0) {
          const dx = x[i] - pointerX;
          const dy = y[i] - pointerY;
          const clearance = obstacleRadius + 0.6;
          const distance = Math.hypot(dx, dy);
          if (distance < clearance) {
            const scale = clearance / Math.max(distance, 0.001);
            x[i] = pointerX + dx * scale;
            y[i] = pointerY + dy * scale;
          }
        }
        if (--age[i] <= 0 || x[i] < 2 || x[i] > n - 3 || y[i] < 2 || y[i] > n - 3) {
          spawn(i);
          continue;
        }
        context.moveTo(oldX, oldY);
        context.lineTo(x[i], y[i]);
      }
      context.stroke();
    }
    if (pointerX >= 0) {
      // The body also occludes old trails when the cursor moves over them.
      context.fillStyle = paper;
      context.beginPath();
      context.arc(pointerX, pointerY, obstacleRadius, 0, Math.PI * 2);
      context.fill();
    }
  }

  function resize() {
    const size = Math.round(canvas.getBoundingClientRect().width);
    if (!size || size === width) return;
    width = size;
    const pixels = Math.min(1100, Math.round(size * Math.min(window.devicePixelRatio || 1, 1.5)));
    canvas.width = canvas.height = pixels;
    context.setTransform(pixels / n, 0, 0, pixels / n, 0, 0);
    context.fillStyle = paper;
    context.fillRect(0, 0, n, n);
    // Compose a complete first frame, including when motion is disabled.
    for (let i = 0; i < 65; i++) draw();
    figure.dataset.rendered = '';
  }

  function running() {
    return !paused && !preference.matches && visible && !document.hidden;
  }

  function tick(time) {
    frame = 0;
    if (!running()) return;
    if (time - lastTime >= 1000 / 30) {
      solve();
      draw();
      lastTime = time;
    }
    frame = requestAnimationFrame(tick);
  }

  function sync() {
    cancelAnimationFrame(frame);
    frame = 0;
    solid.fill(0);
    obstacleDirty = false;
    pointerX = pointerY = -1;
    toggle.hidden = preference.matches;
    figure.toggleAttribute('data-running', running());
    toggle.setAttribute('aria-pressed', String(paused));
    toggle.setAttribute('aria-label', paused ? 'Resume flow animation' : 'Pause flow animation');
    toggle.innerHTML = paused ? 'Resume <span aria-hidden="true">▷</span>' : 'Pause <span aria-hidden="true">Ⅱ</span>';
    if (running()) {
      lastTime = 0;
      frame = requestAnimationFrame(tick);
    }
  }

  canvas.addEventListener('pointermove', event => {
    // Touch scrolling is never captured by the illustration.
    if (event.pointerType !== 'mouse' || !running()) return;
    const bounds = canvas.getBoundingClientRect();
    const px = (event.clientX - bounds.left) / bounds.width * n;
    const py = (event.clientY - bounds.top) / bounds.height * n;
    obstacleDirty = true;
    pointerX = px;
    pointerY = py;
  });
  canvas.addEventListener('pointerleave', () => {
    pointerX = pointerY = -1;
    obstacleDirty = true;
  });
  toggle.addEventListener('click', () => { paused = !paused; sync(); });
  preference.addEventListener('change', sync);
  document.addEventListener('visibilitychange', sync);
  window.addEventListener('pagehide', () => { cancelAnimationFrame(frame); frame = 0; });
  window.addEventListener('pageshow', sync);
  const visibility = new IntersectionObserver(entries => {
    visible = entries[0].isIntersecting;
    sync();
  });
  visibility.observe(canvas);
  const sizing = new ResizeObserver(resize);
  sizing.observe(canvas);
  resize();
  sync();
})();
