/* Isometric 3D topology view: one slab per subnet, isolated subnets chained
 * after the dual-homed host that reaches them, declared pivot steps as arrows.
 * Reads the same /api/topology payload as the Cytoscape view. Requires
 * three.min.js, three-OrbitControls.js and three-CSS2DRenderer.js. */
(function () {
  'use strict';

  // Flat face colors (top / left / right) so blocks read the same from any angle
  const FAM = {
    router: { name: 'Routeur',                   top: '#AFA9EC', left: '#7F77DD', right: '#534AB7', h: 1.0 },
    iot:    { name: 'Service IoT',               top: '#5DCAA5', left: '#1D9E75', right: '#0F6E56', h: 1.5 },
    pivot:  { name: 'Service (chaîne de pivot)', top: '#5DCAA5', left: '#1D9E75', right: '#0F6E56', h: 1.5 },
    it:     { name: 'Service IT',                top: '#85B7EB', left: '#378ADD', right: '#185FA5', h: 1.5 },
    ot:     { name: 'Service OT / industriel',   top: '#F0997B', left: '#D85A30', right: '#993C1D', h: 1.5 },
    cloud:  { name: 'Service cloud / API',       top: '#ED93B1', left: '#D4537E', right: '#993556', h: 1.5 },
    audit:  { name: "Poste d'audit",             top: '#D3D1C7', left: '#888780', right: '#5F5E5A', h: 1.3 },
  };
  const PATH = '#EF9F27', FLOW = '#85B7EB';
  const GRID = 4.2, PAD = 2.4, GAP_X = 5, GAP_Z = 9, SLAB = 0.4;
  const AUDIT_ID = '__audit__';

  function family(node) {
    if (node.type === 'router') return 'router';
    const role = node.role || '';
    if (/^(pivot|heldout)_/.test(role)) return 'pivot';
    if (/^(cloud|api)_/.test(role) || role === 'web_upload') return 'cloud';
    if (/modbus|opcua|bacnet|^ot_/.test(role)) return 'ot';
    if (/mqtt|coap|iot_gateway|camera|nvr|wireless|ota|pki|boot|device_|provisioning|firmware|snmp/.test(role)) return 'iot';
    if (!role && ['gateway', 'sensor', 'camera', 'ap'].includes(node.type)) return 'iot';
    return 'it';
  }
  const sub = ip => String(ip || '').split('.').slice(0, 3).join('.');
  const shortIp = ip => '.' + String(ip).split('.').slice(2).join('.');
  const displayName = id => String(id).replace(/^s[0-9]+[a-z]*-/i, '');
  const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const C = h => new THREE.Color(h);

  let host, stage, renderer, labels, scene, camera, controls, world, legendEl, state = null, viewSize = 30, opts = {};
  let showIps = true;

  function init(container) {
    host = container;
    host.innerHTML = `
      <div class="t3d-stage"></div>
      <div class="t3d-tools">
        <button type="button" class="t3d-btn" data-act="iso">Vue isométrique</button>
        <button type="button" class="t3d-btn" data-act="ip" aria-pressed="true">Adresses IP</button>
      </div>
      <div class="t3d-legend"></div>
      <div class="t3d-hint">Clic gauche : tourner · clic droit : déplacer · molette : zoom · clic sur un équipement : détails</div>`;
    stage = host.querySelector('.t3d-stage');
    legendEl = host.querySelector('.t3d-legend');
    renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    stage.appendChild(renderer.domElement);
    labels = new THREE.CSS2DRenderer();
    labels.domElement.className = 't3d-labels';
    stage.appendChild(labels.domElement);
    scene = new THREE.Scene();
    camera = new THREE.OrthographicCamera(-1, 1, 1, -1, -1000, 1000);
    controls = new THREE.OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true; controls.dampingFactor = 0.12;
    controls.maxPolarAngle = Math.PI / 2 - 0.05;
    controls.mouseButtons = { LEFT: THREE.MOUSE.ROTATE, MIDDLE: THREE.MOUSE.DOLLY, RIGHT: THREE.MOUSE.PAN };
    world = new THREE.Group(); scene.add(world);
    new ResizeObserver(resize).observe(stage);

    host.querySelector('[data-act="iso"]').onclick = () => isoView();
    host.querySelector('[data-act="ip"]').onclick = e => {
      showIps = e.currentTarget.getAttribute('aria-pressed') !== 'true';
      e.currentTarget.setAttribute('aria-pressed', showIps);
      host.classList.toggle('t3d-no-ip', !showIps);
    };
    bindPicking();
    (function tick() {
      if (!host.hidden) { controls.update(); renderer.render(scene, camera); labels.render(scene, camera); }
      requestAnimationFrame(tick);
    })();
  }

  function resize() {
    const w = stage.clientWidth, h = stage.clientHeight;
    if (!w || !h) return;
    const a = w / h;
    camera.left = -viewSize * a / 2; camera.right = viewSize * a / 2; camera.top = viewSize / 2; camera.bottom = -viewSize / 2;
    camera.updateProjectionMatrix(); renderer.setSize(w, h); labels.setSize(w, h);
  }

  const add = o => (world.add(o), o);
  function label(html, cls, pos) {
    const d = document.createElement('div'); d.className = 't3d-lbl' + (cls ? ' ' + cls : ''); d.innerHTML = html;
    const o = new THREE.CSS2DObject(d); o.position.copy(pos); return add(o);
  }
  // BoxGeometry face order: +x, -x, +y, -y, +z, -z
  function flatBox(w, h, d, f) {
    const m = c => new THREE.MeshBasicMaterial({ color: C(c), transparent: true });
    const R = m(f.right), L = m(f.left), T = m(f.top);
    return new THREE.Mesh(new THREE.BoxGeometry(w, h, d), [R, R, T, R, L, L]);
  }
  function groundLoop(pts, color, dashed) {
    const g = new THREE.BufferGeometry().setFromPoints(pts.map(p => new THREE.Vector3(p[0], 0.01, p[1])));
    const l = new THREE.LineLoop(g, dashed
      ? new THREE.LineDashedMaterial({ color: C(color), dashSize: 0.5, gapSize: 0.35 })
      : new THREE.LineBasicMaterial({ color: C(color) }));
    if (dashed) l.computeLineDistances();
    return add(l);
  }
  function plank(a, b, color = PATH) {
    const len = Math.hypot(b.x - a.x, b.z - a.z);
    const m = add(new THREE.Mesh(new THREE.BoxGeometry(len, 0.08, 0.8),
      new THREE.MeshBasicMaterial({ color: C(color), transparent: true, opacity: 0.32, depthWrite: false })));
    m.position.set((a.x + b.x) / 2, 0.02, (a.z + b.z) / 2); m.rotation.y = -Math.atan2(b.z - a.z, b.x - a.x);
    const e = add(new THREE.LineSegments(new THREE.EdgesGeometry(m.geometry), new THREE.LineBasicMaterial({ color: C(color === PATH ? '#BA7517' : color) })));
    e.position.copy(m.position); e.rotation.copy(m.rotation);
  }

  // ---------- layout ----------
  function layout(data) {
    const nodes = (data.nodes || []).map(n => ({
      raw: n, id: n.id, ip: n.ip || '', type: n.type, role: (n.services || [])[0] || '',
      ip2: n.secondary_ip, vlan: n.vlan_id, vlan2: n.secondary_vlan_id,
    }));
    nodes.forEach(n => { n.fam = family(n); });
    const byId = Object.fromEntries(nodes.map(n => [n.id, n]));
    const router = nodes.find(n => n.fam === 'router');
    const withIp = nodes.filter(n => n.ip);
    const counts = {};
    withIp.forEach(n => { counts[sub(n.ip)] = (counts[sub(n.ip)] || 0) + 1; });
    const rsub = router?.ip ? sub(router.ip) : Object.keys(counts).sort((a, b) => counts[b] - counts[a])[0];
    const subs = [...new Set(withIp.flatMap(n => [sub(n.ip), n.ip2 && sub(n.ip2)]).filter(Boolean))];
    if (!subs.length) return null;
    const bridgesInto = s => nodes.filter(n => n.ip2 && sub(n.ip2) === s);
    const zones = Object.fromEntries(subs.map(s => {
      const iso = s !== rsub && bridgesInto(s).length > 0;
      const members = withIp.filter(n => n !== router && sub(n.ip) === s);
      const vlan = members.find(m => m.vlan)?.vlan ?? bridgesInto(s)[0]?.vlan2;
      return [s, { s, iso, main: s === rsub, members, vlan, bridges: bridgesInto(s), children: [] }];
    }));
    for (const z of Object.values(zones)) if (!z.main) {
      z.parent = z.iso ? zones[sub(z.bridges[0].ip)] || zones[rsub] : zones[rsub];
      z.parent.children.push(z);
    }
    const main = zones[rsub]; main.depth = 0;
    const queue = [main];
    while (queue.length) {
      const z = queue.shift();
      z.children.sort((a, b) => +a.s.split('.')[2] - +b.s.split('.')[2]);
      for (const c of z.children) { c.depth = z.depth + 1; queue.push(c); }
    }
    const order = ['it', 'cloud', 'iot', 'ot', 'pivot'];
    for (const z of Object.values(zones)) {
      const plain = z.members.filter(n => !n.ip2).sort((a, b) => order.indexOf(a.fam) - order.indexOf(b.fam));
      const list = [...(z.main && router ? [router] : []), ...plain, ...z.members.filter(n => n.ip2)];
      z.rows = Math.max(1, Math.ceil(Math.sqrt(list.length * 0.8)));
      z.cols = Math.max(1, Math.ceil(list.length / z.rows));
      z.list = list; z.w = z.cols * GRID + PAD; z.d = z.rows * GRID + PAD;
    }
    const placeMembers = z => z.list.forEach((n, i) => {
      const c = Math.floor(i / z.rows), r = i % z.rows;
      n.zone = z; n.pos = new THREE.Vector3(z.x0 + PAD / 2 + GRID * (c + 0.5), 0, z.z0 + PAD / 2 + GRID * (r + 0.5));
    });
    // one column per depth; a child zone is centred on the host bridging into it, so chains read as a staircase
    const depths = {};
    for (const z of Object.values(zones)) if (z.depth !== undefined) (depths[z.depth] ||= []).push(z);
    let x = 0;
    for (const d of Object.keys(depths).map(Number).sort((a, b) => a - b)) {
      const col = depths[d];
      for (const z of col) {
        z.x0 = x;
        const anchor = !z.parent ? z.d / 2 : z.iso && z.bridges[0].pos ? z.bridges[0].pos.z : z.parent.z0 + z.parent.d / 2;
        z.z0 = anchor - z.d / 2;
      }
      col.sort((a, b) => a.z0 - b.z0);
      for (let i = 1; i < col.length; i++) col[i].z0 = Math.max(col[i].z0, col[i - 1].z0 + col[i - 1].d + GAP_Z);
      col.forEach(placeMembers);
      x += Math.max(...col.map(z => z.w)) + GAP_X;
    }
    const placed = Object.values(zones).filter(z => z.x0 !== undefined);
    const audit = { id: AUDIT_ID, name: "poste d'audit", fam: 'audit', ip: '', pos: new THREE.Vector3(main.x0 - 5, 0, main.z0 + 1) };
    nodes.push(audit); byId.attacker = audit; byId[AUDIT_ID] = audit;
    return { nodes: nodes.filter(n => n.pos), byId, zones: placed, router, main, audit };
  }

  function zoneText(z) {
    const net = `${z.s}.0/24`, name = z.vlan ? 'VLAN ' + z.vlan : net;
    if (z.main) return { title: 'Réseau principal', sub: `${net} · routé` };
    if (z.iso) return { title: `${name} · isolé`, sub: `joignable via ${z.bridges.map(b => displayName(b.id)).join(', ')}` };
    return { title: `${name} · routé`, sub: `${net} · via le routeur` };
  }

  // ---------- build ----------
  function build(data) {
    scene.remove(world); world.traverse(o => o.element?.remove());
    world = new THREE.Group(); scene.add(world);
    scene.background = C(getComputedStyle(document.documentElement).getPropertyValue('--bg').trim() || '#0d1117');
    const L = layout(data);
    if (!L) { state = null; legendEl.innerHTML = ''; return; }
    const meshes = [];

    for (const z of L.zones) {
      const slab = add(flatBox(z.w, SLAB, z.d, z.main
        ? { top: '#1b2a3a', left: '#2f6bab', right: '#2a5f99' }
        : { top: '#262626', left: '#555552', right: '#4a4a47' }));
      slab.position.set(z.x0 + z.w / 2, -SLAB / 2, z.z0 + z.d / 2);
      groundLoop([[z.x0, z.z0], [z.x0 + z.w, z.z0], [z.x0 + z.w, z.z0 + z.d], [z.x0, z.z0 + z.d]], z.main ? '#378ADD' : '#b4b2a9', z.iso);
      z.text = zoneText(z);
      label(`${esc(z.text.title)}<small>${esc(z.text.sub)}</small>`, 't3d-zone', new THREE.Vector3(z.x0 + z.w * 0.35, -SLAB, z.z0 + z.d + 2.6));
    }
    if (L.router) for (const z of L.zones) if (!z.main && !z.iso) plank(L.router.pos, new THREE.Vector3(z.x0 + 0.6, 0, z.z0 + z.d / 2), '#7F77DD');
    for (const n of L.nodes) if (n.ip2) {
      const z = L.zones.find(q => q.s === sub(n.ip2));
      if (z) plank(n.pos, new THREE.Vector3(z.x0 + 1.2, 0, Math.min(Math.max(n.pos.z, z.z0 + 1.5), z.z0 + z.d - 1.5)));
    }

    for (const n of L.nodes) {
      const f = FAM[n.fam];
      const mesh = add(flatBox(n.fam === 'router' ? 1.6 : 1.5, f.h, n.fam === 'router' ? 1.6 : 1.5, f));
      mesh.position.set(n.pos.x, f.h / 2, n.pos.z); mesh.userData.node = n; meshes.push(mesh); n.mesh = mesh;
      const ip = n.ip ? `<small class="t3d-ip">${esc(shortIp(n.ip))}${n.ip2 ? ' · ' + esc(shortIp(n.ip2)) : ''}</small>` : '';
      const name = n.fam === 'router' ? 'routeur' : n.name || displayName(n.id);
      n.label = label(`${esc(name)}${ip}`, '', new THREE.Vector3(n.pos.x, f.h + 1.7, n.pos.z));
    }

    // Declared links: pivot steps (enforcement or intrusion hops) become numbered orange arrows, other flows thin blue arcs
    const arcs = [], links = [];
    let step = 0;
    for (const e of data.edges || []) {
      const pivot = !!e.enforcement || e.type === 'intrusion';
      if (!e.declared && !pivot && e.type !== 'discovered') continue;
      const a = L.byId[e.source], b = L.byId[e.target];
      if (!a || !b || !a.pos || !b.pos) continue;
      links.push(e);
      const color = C(pivot ? PATH : FLOW);
      const pa = a.pos.clone().setY(FAM[a.fam].h * 0.75), pb = b.pos.clone().setY(FAM[b.fam].h + 0.15);
      const mid = pa.clone().add(pb).multiplyScalar(0.5);
      mid.y = Math.max(pa.y, pb.y) + (pivot ? 5 + pa.distanceTo(pb) * 0.12 : 1.2 + pa.distanceTo(pb) * 0.1);
      const curve = new THREE.QuadraticBezierCurve3(pa, mid, pb);
      const tube = add(new THREE.Mesh(new THREE.TubeGeometry(curve, 48, pivot ? 0.07 : 0.035, 6),
        new THREE.MeshBasicMaterial({ color, transparent: true, opacity: pivot ? 1 : 0.6 })));
      const arc = { tube, a, b, base: pivot ? 1 : 0.6 };
      if (pivot) {
        const tip = add(new THREE.Mesh(new THREE.ConeGeometry(0.28, 0.75, 10), new THREE.MeshBasicMaterial({ color, transparent: true })));
        tip.position.copy(curve.getPoint(0.985)); tip.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), curve.getTangent(0.985));
        arc.tip = tip;
        const n = e.hop_label || `${++step} · ${e.protocol || ''}`;
        label(esc(n), 't3d-step', curve.getPoint(0.42).add(new THREE.Vector3(0, 1.0, 0)));
      } else {
        arc.label = label(esc(e.protocol || e.link_type || ''), 't3d-flow', curve.getPoint(0.5));
      }
      arcs.push(arc);
    }
    if (L.router && !links.some(e => L.byId[e.source] === L.audit)) {
      const g = new THREE.BufferGeometry().setFromPoints([L.audit.pos.clone().setY(0.6), L.router.pos.clone().setY(0.6)]);
      add(new THREE.Line(g, new THREE.LineDashedMaterial({ color: C('#888780'), dashSize: 0.4, gapSize: 0.3 }))).computeLineDistances();
    }

    let minX = Infinity, maxX = -Infinity, minZ = Infinity, maxZ = -Infinity;
    for (const z of L.zones) { minX = Math.min(minX, z.x0); maxX = Math.max(maxX, z.x0 + z.w); minZ = Math.min(minZ, z.z0); maxZ = Math.max(maxZ, z.z0 + z.d + 4); }
    minX = Math.min(minX, L.audit.pos.x - 1.5); minZ = Math.min(minZ, L.audit.pos.z - 1.5);
    const center = new THREE.Vector3((minX + maxX) / 2, 0, (minZ + maxZ) / 2), corners = [];
    for (const cx of [minX, maxX]) for (const cz of [minZ, maxZ]) for (const cy of [0, 7]) corners.push(new THREE.Vector3(cx, cy, cz));
    state = { L, meshes, arcs, links, center, corners };
    renderLegend();
  }

  function renderLegend() {
    const { L, links } = state;
    let h = [...new Set(L.nodes.map(n => n.fam))].map(f => `<span><i class="t3d-cube" style="background:${FAM[f].left}"></i>${FAM[f].name}</span>`).join('');
    if (links.some(e => e.enforcement || e.type === 'intrusion')) h += `<span><i class="t3d-arrow" style="color:${PATH}"></i>chemin d'attaque déclaré</span>`;
    if (links.some(e => !e.enforcement && e.type !== 'intrusion')) h += `<span><i class="t3d-arrow" style="color:${FLOW}"></i>flux déclaré (protocole au clic)</span>`;
    if (L.nodes.some(n => n.ip2)) h += '<span><i class="t3d-plank"></i>passerelle (2 interfaces)</span>';
    legendEl.innerHTML = h;
  }

  // ---------- camera ----------
  function isoView() {
    if (!state) return;
    const az = Math.PI / 4, el = Math.atan(1 / Math.SQRT2), d = 200, t = state.center;
    controls.target.copy(t);
    camera.position.set(t.x + d * Math.cos(el) * Math.sin(az), t.y + d * Math.sin(el), t.z + d * Math.cos(el) * Math.cos(az));
    camera.zoom = 1; camera.lookAt(t); camera.updateMatrixWorld();
    const right = new THREE.Vector3().setFromMatrixColumn(camera.matrixWorld, 0), up = new THREE.Vector3().setFromMatrixColumn(camera.matrixWorld, 1);
    let w = 0, h = 0;
    for (const p of state.corners) { const v = p.clone().sub(t); w = Math.max(w, Math.abs(v.dot(right))); h = Math.max(h, Math.abs(v.dot(up))); }
    const aspect = stage.clientWidth / Math.max(stage.clientHeight, 1);
    viewSize = Math.max(2 * h + 7, (2 * w + 6) / aspect) * 0.95;
    resize(); controls.update();
  }

  // ---------- selection ----------
  function bindPicking() {
    const ray = new THREE.Raycaster(), ptr = new THREE.Vector2();
    let down = null;
    const pick = e => {
      if (!state) return null;
      const r = renderer.domElement.getBoundingClientRect();
      ptr.set(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1);
      ray.setFromCamera(ptr, camera);
      return ray.intersectObjects(state.meshes)[0]?.object.userData.node || null;
    };
    renderer.domElement.addEventListener('pointerdown', e => { down = [e.clientX, e.clientY]; });
    renderer.domElement.addEventListener('pointerup', e => {
      if (!down || Math.hypot(e.clientX - down[0], e.clientY - down[1]) > 5) return;
      const n = pick(e);
      highlight(n);
      if (n && n.raw) opts.onSelect?.(n.raw); else opts.onClear?.();
    });
    renderer.domElement.addEventListener('pointermove', e => { renderer.domElement.style.cursor = pick(e) ? 'pointer' : 'grab'; });
  }
  function highlight(n) {
    if (!state) return;
    const near = new Set(n ? [n] : []);
    if (n) for (const a of state.arcs) { if (a.a === n) near.add(a.b); if (a.b === n) near.add(a.a); }
    for (const m of state.L.nodes) {
      const on = !n || near.has(m);
      for (const mat of m.mesh.material) mat.opacity = on ? 1 : 0.18;
      m.label.element.classList.toggle('t3d-dim', !on);
    }
    for (const a of state.arcs) {
      const touches = n && (a.a === n || a.b === n);
      const op = !n || touches ? a.base : 0.08;
      a.tube.material.opacity = op; if (a.tip) a.tip.material.opacity = op;
      a.label?.element.classList.toggle('t3d-on', !!touches);
    }
  }

  window.Topology3D = {
    show(container, data, options = {}) {
      opts = options;
      if (host !== container) init(container);
      container.hidden = false;
      build(data);
      requestAnimationFrame(() => { resize(); isoView(); });
    },
    hide() { if (host) host.hidden = true; },
    clearSelection() { highlight(null); },
  };
})();
