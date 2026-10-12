// The orbit is integrated once; animation moves the camera, not the solution.
export function createAttractor(context, { coarse, colors, paper }) {
  const count = coarse ? 10000 : 14000;
  const points = new Float32Array(count * 3);
  const projectedX = new Float32Array(count);
  const projectedY = new Float32Array(count);
  const depth = new Float32Array(count);
  const accents = new Uint8Array(count - 1);
  const bins = 14;
  const heads = new Int32Array(bins * 2);
  const next = new Int32Array(count - 1);
  const accentNext = new Int32Array(count - 1);
  const tau = Math.PI * 2;
  const introDuration = 3;
  let introTime = 0;
  let pixels = 0;
  let yawPhase = 0;
  let pitchPhase = 0;
  let rollPhase = 0;
  let targetYaw = 0;
  let targetPitch = 0;
  let pointerYaw = 0;
  let pointerPitch = 0;

  // Classical Lorenz parameters, with a small fixed RK4 step. Throw away the
  // approach to the attractor before recording a single continuous copper wire.
  const sigma = 10;
  const rho = 28;
  const beta = 8 / 3;
  const h = 0.0068;
  let x = 0.4;
  let y = 0.8;
  let z = 21;
  let minX = Infinity;
  let minY = Infinity;
  let minZ = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  let maxZ = -Infinity;
  const transient = 2500;
  for (let i = -transient; i < count; i++) {
    const ax = sigma * (y - x);
    const ay = x * (rho - z) - y;
    const az = x * y - beta * z;
    const bx = x + ax * h * 0.5;
    const by = y + ay * h * 0.5;
    const bz = z + az * h * 0.5;
    const dx = sigma * (by - bx);
    const dy = bx * (rho - bz) - by;
    const dz = bx * by - beta * bz;
    const cx = x + dx * h * 0.5;
    const cy = y + dy * h * 0.5;
    const cz = z + dz * h * 0.5;
    const ex = sigma * (cy - cx);
    const ey = cx * (rho - cz) - cy;
    const ez = cx * cy - beta * cz;
    const fx = x + ex * h;
    const fy = y + ey * h;
    const fz = z + ez * h;
    const gx = sigma * (fy - fx);
    const gy = fx * (rho - fz) - fy;
    const gz = fx * fy - beta * fz;
    x += h / 6 * (ax + 2 * dx + 2 * ex + gx);
    y += h / 6 * (ay + 2 * dy + 2 * ey + gy);
    z += h / 6 * (az + 2 * dz + 2 * ez + gz);
    if (i < 0) continue;
    const k = i * 3;
    points[k] = x;
    points[k + 1] = z;
    points[k + 2] = -y;
    minX = Math.min(minX, x);
    maxX = Math.max(maxX, x);
    minY = Math.min(minY, z);
    maxY = Math.max(maxY, z);
    minZ = Math.min(minZ, -y);
    maxZ = Math.max(maxZ, -y);
  }

  // One isotropic normalization preserves the actual 3D orbit. A bounding
  // sphere guarantees breathing room at every camera angle, including tilt.
  const centerX = (minX + maxX) * 0.5;
  const centerY = (minY + maxY) * 0.5;
  const centerZ = (minZ + maxZ) * 0.5;
  let radius = 0;
  for (let i = 0; i < count; i++) {
    const k = i * 3;
    points[k] -= centerX;
    points[k + 1] -= centerY;
    points[k + 2] -= centerZ;
    radius = Math.max(radius, Math.hypot(points[k], points[k + 1], points[k + 2]));
  }
  for (let i = 0; i < points.length; i++) points[i] /= radius;
  for (let i = 0; i < accents.length; i++) {
    // Small, separated lengths of the wire catch the light, never a glittering
    // point cloud or a uniformly bright outline around both wings.
    accents[i] = i % 1327 < 115 ? 1 : 0;
  }

  // Prepare all paint strings once; the drawing loop only changes references.
  const palette = colors.map(color => {
    const value = Number.parseInt(color.slice(1), 16);
    return [value >>> 16, (value >>> 8) & 255, value & 255];
  });
  const strokes = new Array(bins);
  const opacity = new Float32Array(bins);
  for (let i = 0; i < bins; i++) {
    const light = i / (bins - 1);
    const blend = light < 0.6 ? light / 0.6 : (light - 0.6) / 0.4;
    const from = palette[light < 0.6 ? 0 : 1];
    const to = palette[light < 0.6 ? 1 : 2];
    const red = Math.round(from[0] + (to[0] - from[0]) * blend);
    const green = Math.round(from[1] + (to[1] - from[1]) * blend);
    const blue = Math.round(from[2] + (to[2] - from[2]) * blend);
    strokes[i] = `rgb(${red}, ${green}, ${blue})`;
    opacity[i] = 0.24 + light * 0.4;
  }

  function drawBucket(head, links) {
    context.beginPath();
    let previous = -2;
    for (let i = head; i !== -1; i = links[i]) {
      // Lists run backwards through the orbit. Join adjacent segments into
      // antialiased curves rather than overlapping thousands of line caps.
      if (i !== previous - 1) context.moveTo(projectedX[i + 1], projectedY[i + 1]);
      context.lineTo(projectedX[i], projectedY[i]);
      previous = i;
    }
    context.stroke();
  }

  function draw() {
    if (!pixels) return;
    context.setTransform(1, 0, 0, 1, 0, 0);
    context.globalAlpha = 1;
    context.globalCompositeOperation = 'source-over';
    context.fillStyle = paper;
    context.fillRect(0, 0, pixels, pixels);
    const segmentCount = Math.floor((count - 1) * Math.min(1, introTime / introDuration));
    if (!segmentCount) return;

    const yaw = -0.52 + yawPhase + pointerYaw;
    const pitch = 0.16 + Math.sin(pitchPhase) * 0.12 + pointerPitch;
    const roll = -0.2 + Math.sin(rollPhase) * 0.07;
    const sy = Math.sin(yaw);
    const cy = Math.cos(yaw);
    const sp = Math.sin(pitch);
    const cp = Math.cos(pitch);
    const sr = Math.sin(roll);
    const cr = Math.cos(roll);
    const scale = pixels * 0.46;
    const center = pixels * 0.5;
    heads.fill(-1);

    for (let i = 0; i <= segmentCount; i++) {
      const k = i * 3;
      const px = points[k];
      const py = points[k + 1];
      const pz = points[k + 2];
      const rx = cy * px + sy * pz;
      const rz = -sy * px + cy * pz;
      const ry = cp * py - sp * rz;
      const cameraZ = sp * py + cp * rz;
      const perspective = 4.8 / (4.8 - cameraZ);
      projectedX[i] = center + (cr * rx - sr * ry) * scale * perspective;
      projectedY[i] = center - (sr * rx + cr * ry) * scale * perspective;
      depth[i] = cameraZ;
    }
    for (let i = 0; i < segmentCount; i++) {
      const cameraZ = (depth[i] + depth[i + 1]) * 0.5;
      const bucket = Math.min(bins - 1, Math.max(0, Math.floor((cameraZ + 1) * 0.5 * bins)));
      next[i] = heads[bucket];
      heads[bucket] = i;
      if (accents[i] && bucket >= 9) {
        accentNext[i] = heads[bins + bucket];
        heads[bins + bucket] = i;
      }
    }

    const threadWidth = Math.max(0.5, pixels * (coarse ? 0.00095 : 0.0008));
    context.lineCap = 'round';
    context.lineJoin = 'round';
    for (let bucket = 0; bucket < bins; bucket++) {
      context.lineWidth = threadWidth;
      context.strokeStyle = strokes[bucket];
      context.globalAlpha = opacity[bucket];
      if (heads[bucket] !== -1) drawBucket(heads[bucket], next);
      if (heads[bins + bucket] !== -1) {
        context.lineWidth = threadWidth * 1.12;
        context.strokeStyle = colors[3];
        context.globalAlpha = 0.4 + (bucket - 9) * 0.045;
        drawBucket(heads[bins + bucket], accentNext);
      }
    }
    context.globalAlpha = 1;
  }

  return {
    resize(size) {
      pixels = Math.max(0, size);
      draw();
    },
    finishIntro() {
      introTime = introDuration;
      draw();
    },
    step(dt) {
      if (Number.isFinite(dt) && dt > 0) {
        // Reveal the continuous orbit at a fixed angle before moving the camera.
        // Only consume the remainder of a boundary-crossing step for rotation.
        const revealDt = Math.min(dt, introDuration - introTime);
        introTime += revealDt;
        const rotationDt = dt - revealDt;
        // Bounded phases keep indefinitely running tabs numerically well
        // behaved. One turn takes roughly 45 seconds after the entrance.
        yawPhase = (yawPhase + rotationDt * 0.14) % tau;
        pitchPhase = (pitchPhase + rotationDt * 0.013) % tau;
        rollPhase = (rollPhase + rotationDt * 0.009) % tau;
        const ease = -Math.expm1(-rotationDt * 3.2);
        pointerYaw += (targetYaw - pointerYaw) * ease;
        pointerPitch += (targetPitch - pointerPitch) * ease;
      }
      draw();
    },
    setPointer(x, y) {
      if (!Number.isFinite(x) || !Number.isFinite(y)) return;
      targetYaw = (Math.max(0, Math.min(1, x)) - 0.5) * 0.44;
      targetPitch = (Math.max(0, Math.min(1, y)) - 0.5) * 0.32;
    },
    clearPointer() {
      targetYaw = 0;
      targetPitch = 0;
    },
  };
}
