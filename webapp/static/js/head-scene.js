// 3D head used by the live scan page: a scanned human head rendered as fingerprint-style ridges with a neural
// node mesh on a light platform, driven by what the scan is actually doing (activity pulses, red alerts on a
// finding, slow-down while paused).
//
// Ported to plain JavaScript from the CyberGuard AI site's HeadScene component. The head geometry is
// "Infinite" by Lee Perry-Smith (Infinite Realities / triplegangers.com), licensed CC BY 3.0 - see
// /static/models/head-license.txt. Only its geometry is used; the surface look is a custom shader, so the
// original skin textures are never loaded.
import * as THREE from "three";
import { GLTFLoader } from "three/addons/loaders/GLTFLoader.js";

const MODEL_URL = "/static/models/head.glb";

const RIDGE_VERT = /* glsl */ `
  varying vec3 vPos;
  varying vec3 vNormal;
  varying vec3 vView;
  void main() {
    vPos = position;
    vec4 mv = modelViewMatrix * vec4(position, 1.0);
    vNormal = normalize(normalMatrix * normal);
    vView = normalize(-mv.xyz);
    gl_Position = projectionMatrix * mv;
  }
`;

// Ridges are iso-lines of a scalar field on the surface (distance from a whorl core on the temple, warped by 3D
// noise), so they wrap around ear, cheek, nose and brow like a fingerprint wraps a fingertip. fwidth() keeps the
// stroke width constant in screen space.
const RIDGE_FRAG = /* glsl */ `
  precision highp float;
  uniform float uScan;
  uniform float uFreq;
  uniform float uAlert;
  uniform float uActivity;
  varying vec3 vPos;
  varying vec3 vNormal;
  varying vec3 vView;

  float hash(vec3 p) {
    p = fract(p * 0.3183099 + 0.1);
    p *= 17.0;
    return fract(p.x * p.y * p.z * (p.x + p.y + p.z));
  }
  float noise(vec3 x) {
    vec3 i = floor(x);
    vec3 f = fract(x);
    f = f * f * (3.0 - 2.0 * f);
    return mix(
      mix(mix(hash(i + vec3(0,0,0)), hash(i + vec3(1,0,0)), f.x),
          mix(hash(i + vec3(0,1,0)), hash(i + vec3(1,1,0)), f.x), f.y),
      mix(mix(hash(i + vec3(0,0,1)), hash(i + vec3(1,0,1)), f.x),
          mix(hash(i + vec3(0,1,1)), hash(i + vec3(1,1,1)), f.x), f.y),
      f.z);
  }

  void main() {
    vec3 p = vPos;
    vec3 core = vec3(-0.78, 0.30, 0.02);
    float s = length((p - core) * vec3(1.0, 1.12, 1.0)) * uFreq + noise(p * 2.3) * 1.7 + noise(p * 6.0) * 0.35;

    float w = fwidth(s) * 1.4;
    float d = abs(fract(s) - 0.5) * 2.0;
    float line = 1.0 - smoothstep(0.2 - w, 0.2 + w, d);

    vec3 n = normalize(vNormal);
    vec3 v = normalize(vView);
    float facing = max(dot(n, v), 0.0);
    float rim = pow(1.0 - facing, 2.2);
    float diffuse = max(dot(n, normalize(vec3(-0.4, 0.6, 0.7))), 0.0);

    float band = exp(-pow((p.y - uScan) * 6.5, 2.0));

    float intensity = line * (0.42 + rim * 1.1 + diffuse * 0.35) + line * band * 1.6;
    intensity *= 1.0 + uActivity * 0.45 + uAlert * 0.7;
    float fill = rim * 0.09 + band * 0.05 + uAlert * rim * 0.12;

    vec3 cold = vec3(0.12, 0.5, 1.0);
    vec3 hot = vec3(0.55, 0.96, 1.0);
    vec3 col = mix(cold, hot, clamp(rim * 1.2 + band * 0.9 + diffuse * 0.25, 0.0, 1.0));
    col = mix(col, vec3(1.0, 0.3, 0.33), clamp(uAlert, 0.0, 1.0) * 0.7);

    float fadeBottom = smoothstep(-1.0, -0.4, p.y);
    float a = (intensity + fill) * fadeBottom;
    gl_FragColor = vec4(col, clamp(a, 0.0, 1.0));
  }
`;

const POINT_VERT = /* glsl */ `
  uniform float uTime;
  uniform float uScale;
  uniform float uActivity;
  attribute float aPhase;
  attribute float aSize;
  varying float vPulse;
  void main() {
    vPulse = 0.55 + 0.45 * sin(uTime * 2.2 + aPhase);
    vec4 mv = modelViewMatrix * vec4(position, 1.0);
    gl_PointSize = aSize * uScale / -mv.z * (0.8 + 0.4 * vPulse + uActivity * 0.5);
    gl_Position = projectionMatrix * mv;
  }
`;

const POINT_FRAG = /* glsl */ `
  precision highp float;
  uniform float uAlert;
  varying float vPulse;
  void main() {
    float d = length(gl_PointCoord - 0.5);
    float glow = smoothstep(0.5, 0.0, d);
    float core = smoothstep(0.14, 0.0, d);
    vec3 col = mix(vec3(0.35, 0.8, 1.0), vec3(1.0), core);
    col = mix(col, vec3(1.0, 0.35, 0.38), clamp(uAlert, 0.0, 1.0) * 0.8);
    gl_FragColor = vec4(col, glow * glow * vPulse + core);
  }
`;

const COLUMN_VERT = /* glsl */ `
  varying vec2 vUv;
  varying vec3 vPos;
  void main() {
    vUv = uv;
    vPos = position;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

const COLUMN_FRAG = /* glsl */ `
  precision highp float;
  uniform float uTime;
  uniform float uAlert;
  varying vec2 vUv;
  varying vec3 vPos;
  void main() {
    float ang = atan(vPos.z, vPos.x);
    float stripe = smoothstep(0.55, 0.95, sin(ang * 64.0 + uTime * 0.35) * 0.5 + 0.5);
    float flicker = 0.75 + 0.25 * sin(uTime * 3.0 + ang * 9.0);
    float a = (1.0 - vUv.y) * 0.55 * stripe * flicker;
    vec3 col = mix(vec3(0.45, 0.85, 1.0), vec3(1.0, 0.4, 0.4), clamp(uAlert, 0.0, 1.0) * 0.8);
    gl_FragColor = vec4(col, a);
  }
`;

/**
 * Mounts the head into `canvas` (which `wrap` sizes) and returns a controller:
 *   pulse(amount)  - scan activity (a payload was sent): brightens the mesh briefly
 *   alert()        - a finding was confirmed: the whole head flashes red
 *   setPaused(b)   - slows everything down while the scan is paused
 *   dispose()
 * `onFail` is called once if WebGL or the model is unavailable, so the page can show its fallback.
 */
export function createHeadScene(wrap, canvas, { onFail = () => {} } = {}) {
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const lowPower = window.matchMedia("(max-width: 768px)").matches || (navigator.hardwareConcurrency ?? 8) <= 4;

  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: !lowPower, powerPreference: "high-performance" });
  } catch (e) {
    onFail();
    return { pulse() {}, alert() {}, setPaused() {}, dispose() {} };
  }
  const pixelRatio = Math.min(window.devicePixelRatio || 1, lowPower ? 1.5 : 2);
  renderer.setPixelRatio(pixelRatio);
  renderer.setClearColor(0x000000, 0);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(28, 1, 0.1, 50);
  camera.position.set(0, 0.12, 6.4);
  camera.lookAt(0, -0.08, 0);

  const headGroup = new THREE.Group();
  const platformGroup = new THREE.Group();
  scene.add(headGroup, platformGroup);

  const disposables = [];
  const track = (o) => { disposables.push(o); return o; };

  const state = { activity: 0, alert: 0, speed: 1, paused: false };
  const ridgeUniforms = { uScan: { value: -2 }, uFreq: { value: lowPower ? 12 : 18 },
                          uAlert: { value: 0 }, uActivity: { value: 0 } };
  const pointUniforms = { uTime: { value: 0 }, uScale: { value: 1 }, uAlert: { value: 0 }, uActivity: { value: 0 } };
  const columnUniforms = { uTime: { value: 0 }, uAlert: { value: 0 } };
  const dashedRings = [];

  // Platform: concentric rings, a rotating dashed ring, soft ground glow and a striped light column.
  const PLATFORM_Y = -1.32;
  [
    { r: 1.3, op: 0.85, w: 0.022 },
    { r: 1.08, op: 0.5, w: 0.012 },
    { r: 0.84, op: 0.4, w: 0.01 },
    { r: 0.6, op: 0.3, w: 0.01 },
  ].forEach(({ r, op, w }) => {
    const geo = track(new THREE.RingGeometry(r - w, r, 160));
    const mat = track(new THREE.MeshBasicMaterial({ color: 0x8fd0ff, transparent: true, opacity: op,
      blending: THREE.AdditiveBlending, depthWrite: false, side: THREE.DoubleSide }));
    const ring = new THREE.Mesh(geo, mat);
    ring.rotation.x = -Math.PI / 2;
    ring.position.y = PLATFORM_Y;
    platformGroup.add(ring);
  });
  const dashPts = [];
  for (let i = 0; i <= 160; i++) {
    const a = (i / 160) * Math.PI * 2;
    dashPts.push(new THREE.Vector3(Math.cos(a) * 1.18, 0, Math.sin(a) * 1.18));
  }
  const dashGeo = track(new THREE.BufferGeometry().setFromPoints(dashPts));
  const dashMat = track(new THREE.LineDashedMaterial({ color: 0xbfe6ff, dashSize: 0.07, gapSize: 0.09,
    transparent: true, opacity: 0.8, blending: THREE.AdditiveBlending }));
  const dashed = new THREE.Line(dashGeo, dashMat);
  dashed.computeLineDistances();
  dashed.position.y = PLATFORM_Y + 0.004;
  dashedRings.push(dashed);
  platformGroup.add(dashed);

  const glowGeo = track(new THREE.CircleGeometry(1.6, 64));
  const glowMat = track(new THREE.ShaderMaterial({
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    vertexShader: "varying vec2 vUv; void main(){ vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position,1.0); }",
    fragmentShader: "varying vec2 vUv; void main(){ float d = length(vUv - 0.5) * 2.0; float a = pow(1.0 - clamp(d,0.0,1.0), 2.4) * 0.5; gl_FragColor = vec4(0.25,0.6,1.0,a); }",
  }));
  const glow = new THREE.Mesh(glowGeo, glowMat);
  glow.rotation.x = -Math.PI / 2;
  glow.position.y = PLATFORM_Y - 0.01;
  platformGroup.add(glow);

  const colGeo = track(new THREE.CylinderGeometry(0.74, 1.0, 0.95, 96, 1, true));
  const colMat = track(new THREE.ShaderMaterial({ uniforms: columnUniforms, vertexShader: COLUMN_VERT,
    fragmentShader: COLUMN_FRAG, transparent: true, depthWrite: false, side: THREE.DoubleSide,
    blending: THREE.AdditiveBlending }));
  const column = new THREE.Mesh(colGeo, colMat);
  column.position.y = PLATFORM_Y + 0.475;
  platformGroup.add(column);

  let disposed = false;
  new GLTFLoader().load(
    MODEL_URL,
    (gltf) => {
      if (disposed) return;
      let src = null;
      gltf.scene.traverse((o) => { if (!src && o.isMesh) src = o; });
      if (!src) { onFail(); return; }
      const geometry = src.geometry.clone();
      geometry.computeBoundingBox();
      const box = geometry.boundingBox;
      const center = box.getCenter(new THREE.Vector3());
      const GROW = 1.25;
      const scale = (2 / (box.max.y - box.min.y)) * GROW;
      geometry.translate(-center.x, -center.y, -center.z);
      geometry.scale(scale, scale, scale);
      geometry.translate(0, 0.4 * (GROW - 1), 0);
      geometry.computeVertexNormals();
      track(geometry);

      // Depth-only copy: hides the far side of the head so ridges on the back don't show through the front.
      const occMat = track(new THREE.MeshBasicMaterial({ colorWrite: false, polygonOffset: true,
        polygonOffsetFactor: 1, polygonOffsetUnits: 1 }));
      const occluder = new THREE.Mesh(geometry, occMat);
      occluder.renderOrder = -1;
      headGroup.add(occluder);

      const ridgeMat = track(new THREE.ShaderMaterial({ uniforms: ridgeUniforms, vertexShader: RIDGE_VERT,
        fragmentShader: RIDGE_FRAG, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending }));
      headGroup.add(new THREE.Mesh(geometry, ridgeMat));

      // Neural nodes sampled from the surface, plus links between near ones.
      const posAttr = geometry.getAttribute("position");
      const nrmAttr = geometry.getAttribute("normal");
      let seed = 4242;
      const rnd = () => { seed = (seed * 16807) % 2147483647; return seed / 2147483647; };
      const count = lowPower ? 70 : 130;
      const nodePos = [];
      let guard = 0;
      while (nodePos.length < count && guard++ < 6000) {
        const i = Math.floor(rnd() * posAttr.count);
        const p = new THREE.Vector3(posAttr.getX(i), posAttr.getY(i), posAttr.getZ(i));
        if (p.y < -0.55) continue;
        const n = new THREE.Vector3(nrmAttr.getX(i), nrmAttr.getY(i), nrmAttr.getZ(i));
        p.addScaledVector(n, 0.012);
        if (nodePos.some((q) => q.distanceToSquared(p) < 0.1 * 0.1)) continue;
        nodePos.push(p);
      }
      const pPos = new Float32Array(nodePos.length * 3);
      const pPhase = new Float32Array(nodePos.length);
      const pSize = new Float32Array(nodePos.length);
      nodePos.forEach((p, i) => {
        pPos.set([p.x, p.y, p.z], i * 3);
        pPhase[i] = rnd() * Math.PI * 2;
        pSize[i] = 1.2 + rnd() * 2.2;
      });
      const pGeo = track(new THREE.BufferGeometry());
      pGeo.setAttribute("position", new THREE.BufferAttribute(pPos, 3));
      pGeo.setAttribute("aPhase", new THREE.BufferAttribute(pPhase, 1));
      pGeo.setAttribute("aSize", new THREE.BufferAttribute(pSize, 1));
      const pMat = track(new THREE.ShaderMaterial({ uniforms: pointUniforms, vertexShader: POINT_VERT,
        fragmentShader: POINT_FRAG, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending }));
      headGroup.add(new THREE.Points(pGeo, pMat));

      const linePts = [];
      const degree = new Array(nodePos.length).fill(0);
      for (let a = 0; a < nodePos.length; a++) {
        for (let b = a + 1; b < nodePos.length; b++) {
          if (degree[a] >= 3 || degree[b] >= 3) continue;
          if (nodePos[a].distanceTo(nodePos[b]) < 0.3) {
            linePts.push(nodePos[a].x, nodePos[a].y, nodePos[a].z, nodePos[b].x, nodePos[b].y, nodePos[b].z);
            degree[a]++; degree[b]++;
          }
        }
      }
      const lGeo = track(new THREE.BufferGeometry());
      lGeo.setAttribute("position", new THREE.BufferAttribute(new Float32Array(linePts), 3));
      const lMat = track(new THREE.LineBasicMaterial({ color: 0x9fdcff, transparent: true, opacity: 0.28,
        blending: THREE.AdditiveBlending, depthWrite: false }));
      headGroup.add(new THREE.LineSegments(lGeo, lMat));
    },
    undefined,
    () => { if (!disposed) onFail(); },
  );

  const pointer = { x: 0, y: 0, tx: 0, ty: 0 };
  const resize = () => {
    const w = wrap.clientWidth;
    const h = wrap.clientHeight;
    if (w === 0 || h === 0) return;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    pointUniforms.uScale.value = (h * pixelRatio * 0.5) / Math.tan((camera.fov * Math.PI) / 360) * 0.0105;
  };
  resize();
  const ro = new ResizeObserver(resize);
  ro.observe(wrap);

  const onMove = (e) => {
    const rect = wrap.getBoundingClientRect();
    pointer.tx = ((e.clientX - rect.left) / rect.width - 0.5) * 2;
    pointer.ty = ((e.clientY - rect.top) / rect.height - 0.5) * 2;
  };
  const onLeave = () => { pointer.tx = 0; pointer.ty = 0; };
  window.addEventListener("pointermove", onMove);
  wrap.addEventListener("pointerleave", onLeave);

  let tabHidden = false;
  const onVis = () => { tabHidden = document.hidden; };
  document.addEventListener("visibilitychange", onVis);

  let raf = 0;
  let lastTime = 0;
  let clock = 0;
  let scanPhase = 0;
  const BASE_YAW = 0.85;
  const frame = (time) => {
    raf = requestAnimationFrame(frame);
    if (tabHidden) return;
    if (lowPower && time - lastTime < 32) return;
    const dt = Math.min(0.1, lastTime ? (time - lastTime) / 1000 : 0.016);
    lastTime = time;

    state.speed += ((state.paused ? 0.12 : 1) - state.speed) * 0.08;
    state.activity *= 0.94;
    state.alert *= 0.94;
    clock += dt * (reduceMotion ? 0 : state.speed);
    scanPhase += dt * (reduceMotion ? 0 : state.speed) * 0.55 * (1 + state.activity * 1.6);

    pointer.x += (pointer.tx - pointer.x) * 0.06;
    pointer.y += (pointer.ty - pointer.y) * 0.06;
    headGroup.rotation.y = BASE_YAW + pointer.x * 0.38 + (reduceMotion ? 0 : Math.sin(clock * 0.35) * 0.1);
    headGroup.rotation.x = -0.04 + pointer.y * 0.12;
    headGroup.position.y = reduceMotion ? 0 : Math.sin(clock * 0.8) * 0.015;

    ridgeUniforms.uScan.value = reduceMotion ? -2 : (scanPhase % 3.2) - 1.3;
    ridgeUniforms.uAlert.value = state.alert;
    ridgeUniforms.uActivity.value = state.activity;
    pointUniforms.uTime.value = clock;
    pointUniforms.uAlert.value = state.alert;
    pointUniforms.uActivity.value = state.activity;
    columnUniforms.uTime.value = clock;
    columnUniforms.uAlert.value = state.alert;
    dashedRings.forEach((r) => (r.rotation.y = -clock * 0.25));

    renderer.render(scene, camera);
  };
  raf = requestAnimationFrame(frame);

  return {
    pulse(amount = 0.6) { state.activity = Math.min(1, state.activity + amount); },
    alert() { state.alert = 1; state.activity = 1; },
    setPaused(paused) { state.paused = !!paused; },
    dispose() {
      disposed = true;
      cancelAnimationFrame(raf);
      ro.disconnect();
      window.removeEventListener("pointermove", onMove);
      wrap.removeEventListener("pointerleave", onLeave);
      document.removeEventListener("visibilitychange", onVis);
      disposables.forEach((d) => d.dispose());
      renderer.dispose();
    },
  };
}
