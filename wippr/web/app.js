/**
 * Wippr — Frontend Controller
 * Real-time telemetry receiver, scenario runner, state inspector, and diff modal.
 * Built for wippr: in-flight behavioral firewall & execution harness.
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM References
  const btnScenario1 = document.getElementById('btnScenario1');
  const btnScenario2 = document.getElementById('btnScenario2');
  const btnScenario3 = document.getElementById('btnScenario3');
  const btnScenario4 = document.getElementById('btnScenario4');
  const btnScenario5 = document.getElementById('btnScenario5');

  const btnModeProtected = document.getElementById('btnModeProtected');
  const btnModeUnprotected = document.getElementById('btnModeUnprotected');

  const statusBadge = document.getElementById('statusBadge');
  const statusLabel = document.getElementById('statusLabel');
  const driftBar = document.getElementById('driftBar');
  const driftVal = document.getElementById('driftVal');
  const taintCountEl = document.getElementById('taintCount');
  const rollbackCountEl = document.getElementById('rollbackCount');
  const evalLatency = document.getElementById('evalLatency');

  const btnForensics = document.getElementById('btnForensics');
  const btnDiff = document.getElementById('btnDiff');
  const btnClear = document.getElementById('btnClear');

  const sessionStatus = document.getElementById('sessionStatus');
  const threadFeed = document.getElementById('threadFeed');

  const checkpointsTimeline = document.getElementById('checkpointsTimeline');
  const chkCount = document.getElementById('chkCount');

  const stateInspector = document.getElementById('stateInspector');
  const inspectorTitle = document.getElementById('inspectorTitle');
  const inspectorCode = document.getElementById('inspectorCode');
  const btnInspectorClose = document.getElementById('btnInspectorClose');

  const modalBackdrop = document.getElementById('modalBackdrop');
  const modalTitle = document.getElementById('modalTitle');
  const modalCode = document.getElementById('modalCode');
  const modalClose = document.getElementById('modalClose');

  // State
  let isProtected = true;
  let isRunning = false;
  let taintCount = 0;
  let rollbackCount = 0;
  let checkpoints = [];
  let socket = null;

  // ══════════════════════════════════════════════════════════════
  // WebSocket Connection
  // ══════════════════════════════════════════════════════════════
  let reconnectDelay = 1000;
  let engineOnline = false;

  function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    socket = new WebSocket(`${protocol}//${window.location.host}/ws/telemetry`);

    socket.onopen = () => {
      reconnectDelay = 1000;
    };

    socket.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        handleTelemetry(payload.event, payload.data || {});
      } catch (err) {
        console.error('[wippr] bad telemetry frame:', err);
      }
    };

    socket.onclose = () => {
      if (!engineOnline) return;
      setTimeout(initWebSocket, reconnectDelay);
      reconnectDelay = Math.min(reconnectDelay * 2, 15000);
    };
  }

  // Detects whether the local engine is reachable (it isn't on static hosting)
  async function checkEngine() {
    const offline = document.getElementById('cockpitOffline');
    try {
      const res = await fetch('api/health', { cache: 'no-store' });
      engineOnline = res.ok && (await res.json()).status === 'ok';
    } catch (err) {
      engineOnline = false;
    }
    if (offline) offline.hidden = engineOnline;
    if (engineOnline) {
      enablePills();
      initWebSocket();
    } else {
      disablePills();
    }
  }

  // ══════════════════════════════════════════════════════════════
  // Telemetry Dispatcher
  // ══════════════════════════════════════════════════════════════
  function handleTelemetry(type, data) {
    switch (type) {
      case 'GOAL_RECEIVED':
        hidePlaceholders();
        sessionStatus.textContent = 'running';
        sessionStatus.className = 'state-pill active';
        addThreadCard({
          variant: 'goal',
          tag: 'User Objective',
          body: `<strong>${escapeHtml(data.user_goal)}</strong><br><span style="color:var(--text-dim);font-size:11px;">Scenario: ${escapeHtml(data.scenario_id)} · Harness: ${data.protected ? 'Protected (Firewall Armed)' : 'Vulnerable (Firewall Bypassed)'}</span>`
        });
        break;

      case 'AGENT_THINKING':
        addThreadCard({
          variant: 'thought',
          tag: `Step ${data.step_index} · Reasoning`,
          body: escapeHtml(data.thought)
        });
        break;

      case 'CHECKPOINT_CAPTURED':
        addCheckpointRow(data);
        break;

      case 'TAINT_DETECTED':
        taintCount++;
        taintCountEl.textContent = taintCount;
        const stamps = (data.markers && data.markers.length)
          ? data.markers.map(m => `<span class="stamp-pill">${escapeHtml(m)}</span>`).join(' ')
          : '';
        const chain = data.source_chain
          ? `<div class="lineage-trace">source chain: ${escapeHtml(data.source_chain)}</div>`
          : '';
        addThreadCard({
          variant: 'taint',
          tag: 'Untrusted Data Ingress',
          body: `Source tool <code>${escapeHtml(data.source)}</code> ingested external payload.
                 <div>${stamps}</div>
                 ${chain}
                 <div class="payload-box">${escapeHtml(data.snippet)}</div>`
        });
        break;

      case 'INTERCEPTING_TOOL_CALL':
        addThreadCard({
          variant: 'thought',
          tag: 'Firewall Gate Evaluation',
          body: `Proposed Tool Action: <code>${escapeHtml(data.tool_name)}</code>
                 <div class="payload-box">${escapeHtml(JSON.stringify(data.arguments, null, 2))}</div>`
        });
        break;

      case 'FIREWALL_EVALUATED':
        updateGauges(data.drift_score, data.latency_ms);
        if (data.action === 'QUARANTINE') {
          addThreadCard({
            variant: 'quarantine',
            tag: 'Firewall · Trajectory Quarantined',
            body: `<strong>Action arrested mid-thought.</strong><br>${escapeHtml(data.reason)}<br>
                   <span style="font-size:11px;opacity:0.8;">Intent drift: ${(Number(data.drift_score) * 100).toFixed(0)}% · Taint violation: ${data.taint_violation ? 'Yes' : 'No'} · Gate latency: ${escapeHtml(data.latency_ms)}ms</span>`
          });
        }
        break;

      case 'TOOL_EXECUTED_UNPROTECTED':
        taintCount++;
        taintCountEl.textContent = taintCount;
        updateGauges(0.99, 0.05);
        addThreadCard({
          variant: 'pwned',
          tag: 'Critical · System Compromised',
          body: `<strong>${escapeHtml(data.danger)}</strong><br>
                 Tool <code>${escapeHtml(data.tool_name)}</code> executed without firewall inspection.
                 <div class="payload-box">${escapeHtml(JSON.stringify(data.arguments, null, 2))}</div>`
        });
        break;

      case 'TRAJECTORY_QUARANTINED':
        markCheckpointQuarantined(data.blocked_tool);
        break;

      case 'TIME_TRAVEL_ROLLBACK':
        rollbackCount++;
        rollbackCountEl.textContent = rollbackCount;
        addRewindRibbon(data.from_step, data.to_step, data.latency_ms);
        const lineageInfo = (data.source_chain && data.source_chain.length)
          ? `<div class="lineage-trace">quarantined lineage: ${escapeHtml(data.source_chain.join(', '))}</div>`
          : '';
        addThreadCard({
          variant: 'rollback',
          tag: 'Time-Travel State Recovery',
          body: `Memory rewound from <strong>Step ${escapeHtml(data.from_step)}</strong> to safe checkpoint <strong>Step ${escapeHtml(data.to_step)}</strong> in <strong>${escapeHtml(data.latency_ms)}ms</strong>.
                 ${lineageInfo}`
        });
        break;

      case 'STATE_RESTORED_AND_MASKED':
        addThreadCard({
          variant: 'thought',
          tag: 'Self-Healing Scratchpad',
          body: 'Context sanitized with security tombstone mask. Clean state restored for execution.'
        });
        break;

      case 'TOOL_EXECUTED_SAFE':
        addThreadCard({
          variant: 'success',
          tag: 'Permitted Tool Executed',
          body: `Tool <code>${escapeHtml(data.tool_name)}</code> ran safely.<br>
                 <div class="payload-box">${escapeHtml(JSON.stringify(data.output, null, 2))}</div>`
        });
        break;

      case 'MISSION_SUCCESS':
        sessionStatus.textContent = 'finished';
        sessionStatus.className = 'state-pill';
        addThreadCard({
          variant: 'success',
          tag: 'Task Complete',
          body: `<strong>${escapeHtml(data.summary)}</strong>`
        });
        break;

      case 'MISSION_FAILED':
        sessionStatus.textContent = 'compromised';
        sessionStatus.className = 'state-pill';
        addThreadCard({
          variant: 'pwned',
          tag: 'Run Ended · Agent Hijacked',
          body: `<strong>${escapeHtml(data.summary)}</strong><br>Switch to <em>protected</em> and run it again to see wippr stop this attack.`
        });
        break;

      case 'RUN_ERROR':
        addThreadCard({ variant: 'quarantine', tag: 'Engine Error', body: escapeHtml(data.error) });
        break;
    }
  }

  // ══════════════════════════════════════════════════════════════
  // UI Renderers
  // ══════════════════════════════════════════════════════════════
  function addThreadCard({ variant, tag, body }) {
    const card = document.createElement('div');
    card.className = `thread-card variant-${variant}`;

    const now = new Date();
    const timeStr = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;

    card.innerHTML = `
      <div class="card-head">
        <span class="card-tag">${tag}</span>
        <span class="card-time">${timeStr}</span>
      </div>
      <div class="card-body">${body}</div>
    `;

    threadFeed.appendChild(card);
    threadFeed.scrollTop = threadFeed.scrollHeight;
  }

  function addCheckpointRow(data) {
    checkpoints.push(data);
    chkCount.textContent = `${checkpoints.length} checkpoint${checkpoints.length === 1 ? '' : 's'}`;

    const row = document.createElement('div');
    row.className = 'chk-row';
    row.id = `row-${data.checkpoint_id}`;
    row.onclick = () => selectCheckpoint(data);

    row.innerHTML = `
      <div class="chk-left">
        <span class="chk-index">#${escapeHtml(data.step_index)}</span>
        <span class="chk-id">${escapeHtml(data.checkpoint_id)}</span>
      </div>
      <span class="chk-status clean" id="status-${escapeHtml(data.checkpoint_id)}">${escapeHtml(data.status)}</span>
    `;

    checkpointsTimeline.appendChild(row);
    checkpointsTimeline.scrollTop = checkpointsTimeline.scrollHeight;
  }

  function markCheckpointQuarantined(blockedTool) {
    if (checkpoints.length === 0) return;
    const last = checkpoints[checkpoints.length - 1];
    const statusEl = document.getElementById(`status-${last.checkpoint_id}`);
    if (statusEl) {
      statusEl.className = 'chk-status quarantined';
      statusEl.textContent = `quarantined: ${blockedTool}`;
    }
  }

  function addRewindRibbon(fromStep, toStep, latencyMs) {
    const ribbon = document.createElement('div');
    ribbon.className = 'rewind-connector-ribbon';
    ribbon.innerHTML = `
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>
      <span>Time-Travel Rollback: Step ${escapeHtml(fromStep)} &rarr; Step ${escapeHtml(toStep)} (${escapeHtml(latencyMs)}ms)</span>
    `;
    checkpointsTimeline.appendChild(ribbon);
    checkpointsTimeline.scrollTop = checkpointsTimeline.scrollHeight;
  }

  function selectCheckpoint(data) {
    document.querySelectorAll('.chk-row').forEach(el => el.classList.remove('selected'));
    const row = document.getElementById(`row-${data.checkpoint_id}`);
    if (row) row.classList.add('selected');

    stateInspector.style.display = 'flex';
    inspectorTitle.textContent = `State Frame: ${data.checkpoint_id} (Step ${data.step_index})`;
    inspectorCode.textContent = JSON.stringify(data, null, 2);
  }

  function updateGauges(drift, latency) {
    const pct = Math.min(100, Math.max(0, Math.round(drift * 100)));
    driftBar.style.width = `${pct}%`;
    driftVal.textContent = drift.toFixed(2);
    if (latency !== undefined && latency !== null) {
      evalLatency.textContent = `${Number(latency).toFixed(2)}ms`;
    }
  }

  // Looked up each time: resetCockpit() re-creates these nodes
  function hidePlaceholders() {
    const feed = document.getElementById('feedPlaceholder');
    const lineage = document.getElementById('lineagePlaceholder');
    if (feed) feed.style.display = 'none';
    if (lineage) {
      if (isProtected) {
        lineage.style.display = 'none';
      } else {
        lineage.innerHTML = '<p>No checkpoints: the firewall is bypassed, so there is nothing to rewind to.</p>';
      }
    }
  }

  function resetCockpit() {
    threadFeed.innerHTML = `
      <div class="feed-placeholder" id="feedPlaceholder">
        <div class="placeholder-icon">
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">
            <circle cx="12" cy="12" r="10"/>
            <polyline points="12 6 12 12 16 14"/>
          </svg>
        </div>
        <h4 class="placeholder-title">Ready for execution</h4>
        <p class="placeholder-desc">Choose a scenario above to test indirect prompt injection mitigation, live checkpointing, and time-travel recovery.</p>
      </div>
    `;

    checkpointsTimeline.innerHTML = `
      <div class="lineage-placeholder" id="lineagePlaceholder">
        <p>Checkpoints captured at each step will appear here with state diffs and quarantine badges.</p>
      </div>
    `;

    checkpoints = [];
    chkCount.textContent = '0 checkpoints';
    taintCount = 0;
    rollbackCount = 0;
    taintCountEl.textContent = '0';
    rollbackCountEl.textContent = '0';
    driftBar.style.width = '0%';
    driftVal.textContent = '0.00';
    evalLatency.textContent = '0.00ms';
    sessionStatus.textContent = 'idle';
    sessionStatus.className = 'state-pill';
    inspectorTitle.textContent = 'State Inspector';
    inspectorCode.textContent = 'Select any checkpoint node above to review its frame payload, scratchpad, and taint metadata.';
  }

  // ══════════════════════════════════════════════════════════════
  // Mode Controller
  // ══════════════════════════════════════════════════════════════
  function setMode(protect) {
    isProtected = protect;
    if (isProtected) {
      btnModeProtected.classList.add('active');
      btnModeUnprotected.classList.remove('active');
      statusBadge.className = 'status-badge armed';
      statusLabel.textContent = 'armed';
    } else {
      btnModeProtected.classList.remove('active');
      btnModeUnprotected.classList.add('active');
      statusBadge.className = 'status-badge bypassed';
      statusLabel.textContent = 'bypassed';
    }
  }

  btnModeProtected.onclick = () => setMode(true);
  btnModeUnprotected.onclick = () => setMode(false);

  // ══════════════════════════════════════════════════════════════
  // Scenario Runner
  // ══════════════════════════════════════════════════════════════
  async function runScenario(scenarioId) {
    if (isRunning || !engineOnline) return;
    isRunning = true;
    disablePills();
    resetCockpit();
    hidePlaceholders();

    try {
      const res = await fetch('api/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario_id: scenarioId, protected: isProtected, delay: 0.6 })
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `HTTP ${res.status}`);
      }
    } catch (err) {
      addThreadCard({
        variant: 'quarantine',
        tag: 'Dispatch Error',
        body: `Could not run the scenario: ${escapeHtml(err.message)}`
      });
      sessionStatus.textContent = 'error';
      sessionStatus.className = 'state-pill';
    } finally {
      isRunning = false;
      enablePills();
    }
  }

  const scenarioButtons = [btnScenario1, btnScenario2, btnScenario3, btnScenario4, btnScenario5].filter(Boolean);

  function disablePills() {
    scenarioButtons.forEach(btn => { btn.disabled = true; });
  }

  function enablePills() {
    if (!engineOnline) return;
    scenarioButtons.forEach(btn => { btn.disabled = false; });
  }

  btnScenario1.onclick = () => runScenario('poisoned_invoice');
  btnScenario2.onclick = () => runScenario('malicious_pr');
  btnScenario3.onclick = () => runScenario('clean_workflow');
  if (btnScenario4) btnScenario4.onclick = () => runScenario('openclaw_telegram_exploit');
  if (btnScenario5) btnScenario5.onclick = () => runScenario('deepseek_r1_code_poisoning');

  // ══════════════════════════════════════════════════════════════
  // Modals & Inspector
  // ══════════════════════════════════════════════════════════════
  btnForensics.onclick = async () => {
    try {
      if (!engineOnline) return;
      const res = await fetch('api/forensics');
      const data = await res.json();
      modalTitle.textContent = `Incident Forensics Archive (${data.length} records)`;
      modalCode.textContent = JSON.stringify(data, null, 2);
      modalBackdrop.classList.add('open');
    } catch (err) {
      console.error(err);
    }
  };

  btnDiff.onclick = async () => {
    try {
      if (!engineOnline) return;
      const chkRes = await fetch('api/checkpoints');
      const list = await chkRes.json();
      if (list.length < 2) {
        modalTitle.textContent = 'Checkpoint State Diff';
        modalCode.textContent = 'At least two checkpoints are needed to compute a state difference. Run a scenario first.';
        modalBackdrop.classList.add('open');
        return;
      }
      const a = list[0].checkpoint_id;
      const b = list[list.length - 1].checkpoint_id;
      const diffRes = await fetch(`api/checkpoints/diff?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`);
      const diffData = await diffRes.json();
      modalTitle.textContent = `State Mutation: [${a}] vs [${b}]`;
      modalCode.textContent = JSON.stringify(diffData, null, 2);
      modalBackdrop.classList.add('open');
    } catch (err) {
      console.error(err);
    }
  };

  btnClear.onclick = () => {
    if (isRunning) return;
    resetCockpit();
  };

  btnInspectorClose.onclick = () => {
    stateInspector.style.display = 'none';
  };

  modalClose.onclick = () => {
    modalBackdrop.classList.remove('open');
  };

  modalBackdrop.onclick = (e) => {
    if (e.target === modalBackdrop) {
      modalBackdrop.classList.remove('open');
    }
  };

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      modalBackdrop.classList.remove('open');
      stateInspector.style.display = 'none';
    }
  });

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // Install method tabs (arrow keys move between tabs)
  const tabs = Array.from(document.querySelectorAll('.install-tab'));
  function selectTab(tab) {
    tabs.forEach(t => {
      const selected = t === tab;
      t.classList.toggle('active', selected);
      t.setAttribute('aria-selected', String(selected));
      t.tabIndex = selected ? 0 : -1;
      const panel = document.getElementById(t.getAttribute('aria-controls'));
      if (panel) panel.hidden = !selected;
    });
  }
  tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => selectTab(tab));
    tab.addEventListener('keydown', (e) => {
      if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
      const next = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
      selectTab(next);
      next.focus();
    });
  });

  // Copy buttons
  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (err) {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.setAttribute('readonly', '');
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(textarea);
      return ok;
    }
  }

  document.querySelectorAll('[data-copy]').forEach(btn => {
    const label = btn.querySelector('.copy-label');
    let timer = null;
    btn.addEventListener('click', async () => {
      const source = document.getElementById(btn.dataset.copy);
      if (!source) return;
      const ok = await copyText(source.textContent.trim());
      btn.classList.toggle('copied', ok);
      if (label) label.textContent = ok ? 'copied' : 'press ⌘C';
      clearTimeout(timer);
      timer = setTimeout(() => {
        btn.classList.remove('copied');
        if (label) label.textContent = 'copy';
      }, 1800);
    });
  });

  // Initialize
  disablePills();
  checkEngine();
});

/**
 * Scroll engine for the landing page.
 *
 *   data-scroll="pin"      tall section with a sticky child; --p = 0 → 1 while it is pinned
 *   data-scroll="through"  --p = 0 when the element enters at the bottom, 1 when it leaves at the top
 *   data-scroll="enter"    --p = 0 when the top hits the bottom edge, 1 when it reaches ~35% from the top
 *   data-scroll="end"      --p reaches 1 exactly at the bottom of the page
 *
 * CSS turns --p into transforms/opacity. With reduced motion every --p is pinned to 1.
 */
(() => {
  // Content that waits for scroll reveal is only hidden once this script is running
  document.documentElement.classList.add('js-ready');
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const clamp = (v, a = 0, b = 1) => Math.min(b, Math.max(a, v));

  function ready(fn) {
    if (document.readyState !== 'loading') fn();
    else document.addEventListener('DOMContentLoaded', fn);
  }

  ready(() => {
    const nav = document.getElementById('topNav');
    const scrollers = Array.from(document.querySelectorAll('[data-scroll]'));
    const tour = document.getElementById('tour');
    const typedEl = document.getElementById('tourTyped');
    const tourItems = tour ? Array.from(tour.querySelectorAll('.tour-item')) : [];
    const tourSteps = tour ? Array.from(tour.querySelectorAll('.tt')) : [];
    const prompt = 'Process invoice INV-402, calculate the tax, and save the accounting report.';

    function progressOf(el, mode, vh) {
      const r = el.getBoundingClientRect();
      if (mode === 'pin') return clamp(-r.top / Math.max(1, r.height - vh));
      if (mode === 'through') return clamp((vh - r.top) / (vh + r.height));
      if (mode === 'end') {
        // completes exactly when the page bottom is reached (for footer elements)
        const toBottom = document.documentElement.scrollHeight - (window.scrollY + vh);
        return clamp(1 - toBottom / (vh * 0.55));
      }
      return clamp((vh - r.top) / (vh * 0.65));
    }

    // Tour timeline (fractions of the pinned scroll):
    //   0.00–0.18  typing the goal while zoomed in on the composer
    //   0.18–0.30  zoom out to the whole window
    //   then one step every ~0.14
    const STEP_AT = [0.30, 0.42, 0.55, 0.68, 0.80];

    function renderTour(p) {
      const typed = clamp(p / 0.18);
      if (typedEl) typedEl.textContent = prompt.slice(0, Math.round(typed * prompt.length));
      const zoom = clamp((p - 0.18) / 0.12);
      tour.style.setProperty('--zoom', (1 - Math.pow(1 - zoom, 3)).toFixed(4));

      let step = -1;
      STEP_AT.forEach((at, i) => { if (p >= at) step = i; });
      tour.dataset.step = String(step);
      tourSteps.forEach((el, i) => el.classList.toggle('is-in', i <= step));

      // Caption list: the "type a goal" item is active until the first event lands
      const active = Math.max(0, step);
      tourItems.forEach((el, i) => {
        el.classList.toggle('is-active', i === active);
        el.classList.toggle('is-done', i < active);
      });
    }

    function frame() {
      const vh = window.innerHeight;
      if (nav) nav.classList.toggle('is-scrolled', window.scrollY > 8);
      for (const el of scrollers) {
        const p = reduceMotion ? 1 : progressOf(el, el.dataset.scroll, vh);
        el.style.setProperty('--p', p.toFixed(4));
        if (el === tour) renderTour(p);
      }
    }

    let queued = false;
    function onScroll() {
      if (queued) return;
      queued = true;
      requestAnimationFrame(() => { queued = false; frame(); });
    }
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll, { passive: true });
    frame();

    // Fade-in for generic content
    const reveals = document.querySelectorAll('.reveal');
    if (reduceMotion || !('IntersectionObserver' in window)) {
      reveals.forEach(el => el.classList.add('is-visible'));
    } else {
      const io = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          if (!entry.isIntersecting) return;
          entry.target.classList.add('is-visible');
          io.unobserve(entry.target);
        });
      }, { rootMargin: '0px 0px -10% 0px', threshold: 0.1 });
      reveals.forEach(el => io.observe(el));
    }

    // Active nav link
    const links = Array.from(document.querySelectorAll('.nav-links a'));
    const targets = new Map();
    links.forEach(a => {
      const id = a.getAttribute('href');
      const el = id === '#how' ? document.getElementById('tour') : document.querySelector(id);
      if (el) targets.set(el, a);
    });
    if ('IntersectionObserver' in window && targets.size) {
      const spy = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          const a = targets.get(entry.target);
          if (!a) return;
          if (entry.isIntersecting) {
            links.forEach(l => { l.classList.remove('is-active'); l.removeAttribute('aria-current'); });
            a.classList.add('is-active');
            a.setAttribute('aria-current', 'true');
          } else if (a.classList.contains('is-active')) {
            a.classList.remove('is-active');
            a.removeAttribute('aria-current');
          }
        });
      }, { rootMargin: '-45% 0px -50% 0px' });
      targets.forEach((_, el) => spy.observe(el));
    }

    // Integration code tabs
    const codeTabs = Array.from(document.querySelectorAll('.code-tab'));
    function selectCodeTab(tab) {
      codeTabs.forEach(t => {
        const on = t === tab;
        t.classList.toggle('active', on);
        t.setAttribute('aria-selected', String(on));
        t.tabIndex = on ? 0 : -1;
        const panel = document.getElementById(t.getAttribute('aria-controls'));
        if (panel) panel.hidden = !on;
      });
    }
    codeTabs.forEach((tab, i) => {
      tab.addEventListener('click', () => selectCodeTab(tab));
      tab.addEventListener('keydown', (e) => {
        if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
        const next = codeTabs[(i + (e.key === 'ArrowRight' ? 1 : codeTabs.length - 1)) % codeTabs.length];
        selectCodeTab(next);
        next.focus();
      });
    });

    const panelCopy = document.querySelector('[data-copy-panel]');
    if (panelCopy) {
      const label = panelCopy.querySelector('.copy-label');
      let timer = null;
      panelCopy.addEventListener('click', async () => {
        const panel = document.querySelector('.code-block:not([hidden])');
        if (!panel) return;
        let ok = true;
        try { await navigator.clipboard.writeText(panel.textContent); } catch (err) { ok = false; }
        panelCopy.classList.toggle('copied', ok);
        if (label) label.textContent = ok ? 'copied' : 'select & copy';
        clearTimeout(timer);
        timer = setTimeout(() => { panelCopy.classList.remove('copied'); if (label) label.textContent = 'copy'; }, 1800);
      });
    }
  });
})();
