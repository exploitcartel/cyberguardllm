// Target AI bust used by live scans and login. Ten original procedural robot variants share the same network,
// interaction and scan-event controller. The optional legacy asset is rendered as fingerprint-style ridges
// with a neural node mesh, enclosed in a rotating geodesic network globe whose nodes are linked by data arcs with
// packets travelling along them. It is driven by what the scan is actually doing (activity pulses, a red flash on a
// finding, slow-down while paused) and it follows the page theme: additive glow on dark, solid deep blues on light.
//
// Ported to plain JavaScript from the CyberGuard AI site's HeadScene component. The head geometry is
// "Infinite" by Lee Perry-Smith (Infinite Realities / triplegangers.com), licensed CC BY 3.0 - see
// /static/models/head-license.txt. Only its geometry is used; the surface look is a custom shader, so the
// original skin textures are never loaded.
import * as THREE from "three";
import { buildRobotAvatar, ROBOT_VARIANTS } from "/static/js/robot-avatars.js?v=3";
import { GLTFLoader } from "three/addons/loaders/GLTFLoader.js";

const MODEL_URL = "/static/models/head.glb";

// Radius of the network globe around the head, and the vertical centre of both.
const CAGE_RADIUS = 1.72;
const CENTER_Y = 0.05;

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
  uniform float uLight;
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

    // dark theme: bright cyan glow (additive); light theme: deep blues (normal blending)
    vec3 cold = mix(vec3(0.12, 0.5, 1.0), vec3(0.07, 0.22, 0.70), uLight);
    vec3 hot = mix(vec3(0.55, 0.96, 1.0), vec3(0.15, 0.42, 0.92), uLight);
    vec3 col = mix(cold, hot, clamp(rim * 1.2 + band * 0.9 + diffuse * 0.25, 0.0, 1.0));
    vec3 red = mix(vec3(1.0, 0.3, 0.33), vec3(0.85, 0.10, 0.16), uLight);
    col = mix(col, red, clamp(uAlert, 0.0, 1.0) * 0.7);

    float fadeBottom = smoothstep(-1.0, -0.4, p.y);
    float a = (intensity + fill * (1.0 - uLight * 0.6)) * fadeBottom;
    gl_FragColor = vec4(col, clamp(a, 0.0, 1.0) * mix(1.0, 0.92, uLight));
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
  uniform float uLight;
  varying float vPulse;
  void main() {
    float d = length(gl_PointCoord - 0.5);
    float glow = smoothstep(0.5, 0.0, d);
    float core = smoothstep(0.14, 0.0, d);
    vec3 halo = mix(vec3(0.35, 0.8, 1.0), vec3(0.15, 0.40, 0.95), uLight);
    vec3 center = mix(vec3(1.0), vec3(0.04, 0.16, 0.55), uLight);
    vec3 col = mix(halo, center, core);
    vec3 red = mix(vec3(1.0, 0.35, 0.38), vec3(0.86, 0.12, 0.18), uLight);
    col = mix(col, red, clamp(uAlert, 0.0, 1.0) * 0.8);
    gl_FragColor = vec4(col, glow * glow * vPulse + core);
  }
`;

/**
 * Mounts the head into `canvas` (which `wrap` sizes) and returns a controller:
 *   pulse(amount)  - scan activity (a payload was sent): brightens the mesh and speeds up the data packets
 *   alert()        - a finding was confirmed: the head and the globe flash red once
 *   (drag the head with the mouse or a finger to turn it; it keeps its momentum; double-click resets the view)
 *   alertPulses(n) - the same flash n times in a row (the scan found something: pulse red 3 times)
 *   setReserve(px) - horizontal room (total, both sides) the page needs for tickets; the globe shrinks to fit
 *                    in what is left instead of running under them
 *   getShield()    - {cx, cy, r}: the globe's circle in CSS pixels inside `wrap`, so the page can draw tickets
 *                    outside it and connect them to its edge with a thin line
 *   setPaused(b)   - slows everything down while the scan is paused
 *   dispose()
 * `theme` is "dark" (default) or "light". `onFail` is called once if WebGL or the model is unavailable.
 */
export function createHeadScene(wrap, canvas, { onFail = () => {}, theme = "dark", variant = "legacy" } = {}) {
  let light = theme === "light";
  let BLEND = light ? THREE.NormalBlending : THREE.AdditiveBlending;
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const lowPower = window.matchMedia("(max-width: 768px)").matches || (navigator.hardwareConcurrency ?? 8) <= 4;

  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: !lowPower, powerPreference: "high-performance" });
  } catch (e) {
    onFail();
    return { pulse() {}, alert() {}, alertPulses() {}, setPaused() {}, setVariant() {}, dispose() {},
             setReserve() {},
             getShield: () => ({ cx: wrap.clientWidth / 2, cy: wrap.clientHeight / 2,
                                 r: Math.min(wrap.clientWidth, wrap.clientHeight) * 0.38 }) };
  }
  const pixelRatio = Math.min(window.devicePixelRatio || 1, lowPower ? 1.5 : 2);
  renderer.setPixelRatio(pixelRatio);
  renderer.setClearColor(0x000000, 0);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(28, 1, 0.1, 50);

  const headGroup = new THREE.Group();
  const cageGroup = new THREE.Group();
  cageGroup.position.y = CENTER_Y;
  scene.add(cageGroup, headGroup);

  const disposables = [];
  const themeLines = [];
  const track = (o) => { disposables.push(o); return o; };

  const state = { activity: 0, alert: 0, speed: 1, paused: false, queue: 0 };
  const ridgeUniforms = { uScan: { value: -2 }, uFreq: { value: lowPower ? 12 : 18 },
                          uAlert: { value: 0 }, uActivity: { value: 0 }, uLight: { value: light ? 1 : 0 } };
  const pointUniforms = { uTime: { value: 0 }, uScale: { value: 1 }, uAlert: { value: 0 }, uActivity: { value: 0 },
                          uLight: { value: light ? 1 : 0 } };
  const cageUniforms = { uTime: { value: 0 }, uScale: { value: 1 }, uAlert: { value: 0 }, uActivity: { value: 0 },
                         uLight: { value: light ? 1 : 0 } };

  // Follow body theme changes without rebuilding the scene or losing scan/drag state.
  const themeObserver = new MutationObserver(() => {
    const next = document.body.classList.contains('light');
    if(next === light) return;
    light = next;
    BLEND = light ? THREE.NormalBlending : THREE.AdditiveBlending;
    [ridgeUniforms,pointUniforms,cageUniforms].forEach(u => { u.uLight.value = light ? 1 : 0; });
    disposables.forEach(m => { if(m.isMaterial && m.transparent){ m.blending=BLEND; m.needsUpdate=true; } });
    themeLines.forEach(([m,lc,dc,lo,darkOpacity]) => { m.color.setHex(light ? lc : dc); m.opacity=light ? lo : darkOpacity; });
  });
  themeObserver.observe(document.body,{attributes:true,attributeFilter:['class']});

  // ---- Network globe ("cage"): geodesic wireframe, glowing nodes at its vertices, and data arcs between distant
  // nodes with a packet travelling along each one.
  const ico = track(new THREE.IcosahedronGeometry(CAGE_RADIUS, 2));
  const cageLineMat = track(new THREE.LineBasicMaterial({
    color: light ? 0x2f5fd0 : 0x6fb6ff, transparent: true, opacity: light ? 0.3 : 0.2,
    blending: BLEND, depthWrite: false }));
  themeLines.push([cageLineMat,0x2f5fd0,0x6fb6ff,.3,.2]);
  const cageEdges = new THREE.LineSegments(track(new THREE.EdgesGeometry(ico)), cageLineMat);
  cageEdges.renderOrder = -3;
  cageGroup.add(cageEdges);

  // unique vertices -> nodes
  const verts = [];
  {
    const pos = ico.getAttribute("position");
    const seen = new Set();
    for (let i = 0; i < pos.count; i++) {
      const key = `${pos.getX(i).toFixed(3)},${pos.getY(i).toFixed(3)},${pos.getZ(i).toFixed(3)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      verts.push(new THREE.Vector3(pos.getX(i), pos.getY(i), pos.getZ(i)));
    }
  }
  let seed = 9001;
  const rnd = () => { seed = (seed * 16807) % 2147483647; return seed / 2147483647; };
  {
    const nPos = new Float32Array(verts.length * 3);
    const nPhase = new Float32Array(verts.length);
    const nSize = new Float32Array(verts.length);
    verts.forEach((v, i) => {
      nPos.set([v.x, v.y, v.z], i * 3);
      nPhase[i] = rnd() * Math.PI * 2;
      nSize[i] = 1.6 + rnd() * 2.4;
    });
    const g = track(new THREE.BufferGeometry());
    g.setAttribute("position", new THREE.BufferAttribute(nPos, 3));
    g.setAttribute("aPhase", new THREE.BufferAttribute(nPhase, 1));
    g.setAttribute("aSize", new THREE.BufferAttribute(nSize, 1));
    const m = track(new THREE.ShaderMaterial({ uniforms: cageUniforms, vertexShader: POINT_VERT,
      fragmentShader: POINT_FRAG, transparent: true, depthWrite: false, blending: BLEND }));
    const pts = new THREE.Points(g, m);
    pts.renderOrder = -2;
    cageGroup.add(pts);
  }

  // data arcs: great-circle arcs lifted slightly off the globe, between nodes far apart
  const arcs = [];
  {
    const ARC_COUNT = lowPower ? 8 : 14;
    const arcMat = track(new THREE.LineBasicMaterial({
      color: light ? 0x1d4ed8 : 0x9fdcff, transparent: true, opacity: light ? 0.38 : 0.3,
      blending: BLEND, depthWrite: false }));
    themeLines.push([arcMat,0x1d4ed8,0x9fdcff,.38,.3]);
    let guard = 0;
    while (arcs.length < ARC_COUNT && guard++ < 400) {
      const a = verts[Math.floor(rnd() * verts.length)];
      const b = verts[Math.floor(rnd() * verts.length)];
      if (a.angleTo(b) < 1.2) continue;
      const mid = a.clone().add(b).normalize().multiplyScalar(CAGE_RADIUS * 1.16);
      const curve = new THREE.QuadraticBezierCurve3(a.clone().multiplyScalar(1.01), mid, b.clone().multiplyScalar(1.01));
      const points = curve.getPoints(28);
      const line = new THREE.Line(track(new THREE.BufferGeometry().setFromPoints(points)), arcMat);
      line.renderOrder = -3;
      cageGroup.add(line);
      arcs.push({ curve, t: rnd(), speed: 0.12 + rnd() * 0.18 });
    }
  }
  const packetPos = new Float32Array(arcs.length * 3);
  const packetGeo = track(new THREE.BufferGeometry());
  packetGeo.setAttribute("position", new THREE.BufferAttribute(packetPos, 3));
  packetGeo.setAttribute("aPhase", new THREE.BufferAttribute(new Float32Array(arcs.length).map(() => rnd() * 6.28), 1));
  packetGeo.setAttribute("aSize", new THREE.BufferAttribute(new Float32Array(arcs.length).fill(3.6), 1));
  const packetMat = track(new THREE.ShaderMaterial({ uniforms: cageUniforms, vertexShader: POINT_VERT,
    fragmentShader: POINT_FRAG, transparent: true, depthWrite: false, blending: BLEND }));
  const packets = new THREE.Points(packetGeo, packetMat);
  packets.renderOrder = -2;
  packets.frustumCulled = false;
  cageGroup.add(packets);

  // ---- Head
  let disposed = false;
  const avatarSurface = {
    uniforms:{...ridgeUniforms,uFreq:{value:lowPower?8:11}},
    fragmentShader:RIDGE_FRAG
      .replace('noise(p * 2.3) * 1.7 + noise(p * 6.0) * 0.35', 'noise(p * 2.3) * 0.25')
      .replace('float fill = rim * 0.09', 'float fill = 0.07 + diffuse * 0.035 + rim * 0.09'),
    blending:BLEND,
    vertexShader:RIDGE_VERT.replace('varying vec3 vPos;', 'uniform mat4 uAvatarMatrix;\nvarying vec3 vPos;')
      .replace('vPos = position;', 'vPos = (uAvatarMatrix * vec4(position, 1.0)).xyz;'),
  };
  let avatar = variant === 'legacy' ? null : buildRobotAvatar(headGroup, variant, {lowPower,reduceMotion,surfaceStyle:avatarSurface});
  if (variant === 'legacy') new GLTFLoader().load(
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
        fragmentShader: RIDGE_FRAG, transparent: true, depthWrite: false, blending: BLEND }));
      headGroup.add(new THREE.Mesh(geometry, ridgeMat));

      // Neural nodes sampled from the surface, plus links between near ones.
      const posAttr = geometry.getAttribute("position");
      const nrmAttr = geometry.getAttribute("normal");
      const count = lowPower ? 70 : 130;
      const nodePos = [];
      let g2 = 0;
      while (nodePos.length < count && g2++ < 6000) {
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
        fragmentShader: POINT_FRAG, transparent: true, depthWrite: false, blending: BLEND }));
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
      const lMat = track(new THREE.LineBasicMaterial({ color: light ? 0x2f5fd0 : 0x9fdcff, transparent: true,
        opacity: light ? 0.4 : 0.28, blending: BLEND, depthWrite: false }));
      themeLines.push([lMat,0x2f5fd0,0x9fdcff,.4,.28]);
      headGroup.add(new THREE.LineSegments(lGeo, lMat));
    },
    undefined,
    () => { if (!disposed) onFail(); },
  );

  let reservePx = 0;
  const pointer = { x: 0, y: 0, tx: 0, ty: 0 };
  // Manual view: dragging turns the head and the globe together; releasing keeps a little momentum.
  const view = { yaw: 0, pitch: 0, vyaw: 0, vpitch: 0, dragging: false, lastX: 0, lastY: 0 };
  const resize = () => {
    const w = wrap.clientWidth;
    const h = wrap.clientHeight;
    if (w === 0 || h === 0) return;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    // Back the camera off until the whole globe fits in both directions (tall narrow areas are width-limited).
    const halfFov = (camera.fov * Math.PI) / 360;
    const usableAspect = Math.max(0.25, (w - reservePx) / h);
    camera.position.set(0, CENTER_Y + 0.07, ((CAGE_RADIUS + 0.2) / Math.tan(halfFov)) / Math.min(1, usableAspect));
    camera.lookAt(0, CENTER_Y, 0);
    camera.updateProjectionMatrix();
    const dist = camera.position.z;
    pointUniforms.uScale.value = cageUniforms.uScale.value =
      (h * pixelRatio * 0.5) / Math.tan(halfFov) * 0.0105 * (dist / 6.4);
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

  canvas.style.cursor = "grab";
  canvas.style.touchAction = "none";
  const onDown = (e) => {
    view.dragging = true; view.lastX = e.clientX; view.lastY = e.clientY; view.vyaw = 0; view.vpitch = 0;
    canvas.style.cursor = "grabbing";
    try { canvas.setPointerCapture(e.pointerId); } catch (err) { /* not supported: dragging still works while over the canvas */ }
  };
  const onDrag = (e) => {
    if (!view.dragging) return;
    const dx = e.clientX - view.lastX;
    const dy = e.clientY - view.lastY;
    view.lastX = e.clientX; view.lastY = e.clientY;
    view.yaw += dx * 0.008;
    view.pitch = Math.max(-0.9, Math.min(0.9, view.pitch + dy * 0.006));
    view.vyaw = dx * 0.008; view.vpitch = dy * 0.006;
  };
  const onUp = () => { view.dragging = false; canvas.style.cursor = "grab"; };
  const onReset = () => { view.yaw = 0; view.pitch = 0; view.vyaw = 0; view.vpitch = 0; };
  canvas.addEventListener("pointerdown", onDown);
  canvas.addEventListener("pointermove", onDrag);
  canvas.addEventListener("pointerup", onUp);
  canvas.addEventListener("pointercancel", onUp);
  canvas.addEventListener("dblclick", onReset);

  let tabHidden = false;
  const onVis = () => { tabHidden = document.hidden; };
  document.addEventListener("visibilitychange", onVis);

  const tmp = new THREE.Vector3();
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
    // queued pulses: start the next red flash as soon as the previous one has faded
    if (state.queue > 0 && state.alert < 0.12) { state.alert = 1; state.activity = 1; state.queue--; }
    const step = dt * (reduceMotion ? 0 : state.speed);
    clock += step;
    scanPhase += step * 0.55 * (1 + state.activity * 1.6);

    pointer.x += (pointer.tx - pointer.x) * 0.06;
    pointer.y += (pointer.ty - pointer.y) * 0.06;
    if (!view.dragging) {
      // momentum after letting go
      view.yaw += view.vyaw; view.pitch = Math.max(-0.9, Math.min(0.9, view.pitch + view.vpitch));
      view.vyaw *= 0.93; view.vpitch *= 0.93;
      if (Math.abs(view.vyaw) < 0.0002) view.vyaw = 0;
      if (Math.abs(view.vpitch) < 0.0002) view.vpitch = 0;
    }
    const follow = view.dragging ? 0 : 1;   // the pointer-follow tilt would fight the drag
    headGroup.rotation.y = BASE_YAW + view.yaw + follow * pointer.x * 0.38 + (reduceMotion ? 0 : Math.sin(clock * 0.35) * 0.1);
    headGroup.rotation.x = -0.04 + view.pitch + follow * pointer.y * 0.12;
    headGroup.position.y = reduceMotion ? 0 : Math.sin(clock * 0.8) * 0.015;

    // the globe turns slowly against the head, tilted, and nudges with the pointer too
    cageGroup.rotation.y = clock * 0.16 + view.yaw - follow * pointer.x * 0.15;
    cageGroup.rotation.x = 0.32 + view.pitch + follow * pointer.y * 0.06;

    // packets run along the arcs, faster while the scan is busy
    for (let i = 0; i < arcs.length; i++) {
      const arc = arcs[i];
      arc.t = (arc.t + step * arc.speed * (1 + state.activity * 2.5)) % 1;
      arc.curve.getPoint(arc.t, tmp);
      packetPos[i * 3] = tmp.x; packetPos[i * 3 + 1] = tmp.y; packetPos[i * 3 + 2] = tmp.z;
    }
    packetGeo.attributes.position.needsUpdate = true;

    const flash = state.alert;
    cageLineMat.opacity = (light ? 0.3 : 0.2) + flash * 0.3 + state.activity * 0.08;
    cageLineMat.color.setHex(flash > 0.15 ? (light ? 0xc81e2d : 0xff6b6b) : (light ? 0x2f5fd0 : 0x6fb6ff));

    ridgeUniforms.uScan.value = reduceMotion ? -2 : (scanPhase % 3.2) - 1.3;
    ridgeUniforms.uAlert.value = state.alert;
    ridgeUniforms.uActivity.value = state.activity;
    pointUniforms.uTime.value = cageUniforms.uTime.value = clock;
    pointUniforms.uAlert.value = cageUniforms.uAlert.value = state.alert;
    pointUniforms.uActivity.value = cageUniforms.uActivity.value = state.activity;

    avatar?.update(clock, state.alert, state.activity, light, state.paused);
    renderer.render(scene, camera);
  };
  raf = requestAnimationFrame(frame);

  return {
    setVariant(name) {
      if(!ROBOT_VARIANTS.includes(name) || avatar?.variant === name || disposed)return;
      // Rebuild only the original procedural bust; retain cage, camera, drag and scan state.
      if(variant === 'legacy')return;
      avatar?.dispose();
      avatar=buildRobotAvatar(headGroup,name,{lowPower,reduceMotion,surfaceStyle:avatarSurface});
    },
    pulse(amount = 0.6) { state.activity = Math.min(1, state.activity + amount); },
    alert() { state.alert = 1; state.activity = 1; },
    setReserve(px) {
      const next = Math.max(0, Math.round(px));
      if (next !== reservePx) { reservePx = next; resize(); }
    },
    alertPulses(n = 3) { state.queue = Math.max(state.queue, Math.max(0, n)); },
    getShield() {
      const w = wrap.clientWidth;
      const h = wrap.clientHeight;
      camera.updateMatrixWorld();
      const centre = new THREE.Vector3(0, CENTER_Y, 0);
      const ndc = centre.clone().project(camera);
      const dist = camera.position.distanceTo(centre);
      const halfFov = (camera.fov * Math.PI) / 360;
      // silhouette radius of a sphere seen in perspective: angular radius asin(R / d)
      const r = (Math.tan(Math.asin(Math.min(0.99, CAGE_RADIUS / dist))) / Math.tan(halfFov)) * (h / 2);
      return { cx: ((ndc.x + 1) / 2) * w, cy: ((1 - ndc.y) / 2) * h, r };
    },
    setPaused(paused) { state.paused = !!paused; },
    dispose() {
      disposed = true;
      cancelAnimationFrame(raf);
      ro.disconnect();
      themeObserver.disconnect();
      window.removeEventListener("pointermove", onMove);
      wrap.removeEventListener("pointerleave", onLeave);
      canvas.removeEventListener("pointerdown", onDown);
      canvas.removeEventListener("pointermove", onDrag);
      canvas.removeEventListener("pointerup", onUp);
      canvas.removeEventListener("pointercancel", onUp);
      canvas.removeEventListener("dblclick", onReset);
      document.removeEventListener("visibilitychange", onVis);
      avatar?.dispose();
      disposables.forEach((d) => d.dispose());
      renderer.dispose();
      renderer.forceContextLoss();
    },
  };
}
