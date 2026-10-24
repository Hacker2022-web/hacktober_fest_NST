/**
 * Whipper — Frontend Controller
 * Real-time telemetry receiver, scenario runner, state inspector, and diff modal.
 * Built for Whipper: In-Flight Behavioral Firewall & Execution Harness.
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM References
  const btnScenario1 = document.getElementById('btnScenario1');
  const btnScenario2 = document.getElementById('btnScenario2');
  const btnScenario3 = document.getElementById('btnScenario3');

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
  const feedPlaceholder = document.getElementById('feedPlaceholder');

  const checkpointsTimeline = document.getElementById('checkpointsTimeline');
  const lineagePlaceholder = document.getElementById('lineagePlaceholder');
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
  function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;

    socket = new WebSocket(wsUrl);

    socket.onopen = () => {
      console.log('[Whipper] Live telemetry stream connected.');
    };

    socket.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        handleTelemetry(payload.event, payload.data);
      } catch (err) {
        console.error('Failed to parse frame:', err);
      }
    };

    socket.onclose = () => {
      console.warn('[Whipper] Stream disconnected. Retrying in 2s...');
      setTimeout(initWebSocket, 2000);
    };
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
          tag: 'ShadowWall Gate Evaluation',
          body: `Proposed Tool Action: <code>${escapeHtml(data.tool_name)}</code>
                 <div class="payload-box">${escapeHtml(JSON.stringify(data.arguments, null, 2))}</div>`
        });
        break;

      case 'FIREWALL_EVALUATED':
        updateGauges(data.drift_score, data.latency_ms);
        if (data.action === 'QUARANTINE') {
          addThreadCard({
            variant: 'quarantine',
            tag: 'ShadowWall · Trajectory Quarantined',
            body: `<strong>Action arrested mid-thought.</strong><br>${escapeHtml(data.reason)}<br>
                   <span style="font-size:11px;opacity:0.8;">Intent drift: ${(data.drift_score * 100).toFixed(0)}% · Taint violation: ${data.taint_violation ? 'Yes' : 'No'} · Gate latency: ${data.latency_ms}ms</span>`
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
          body: `Memory rewound from <strong>Step ${data.from_step}</strong> to safe checkpoint <strong>Step ${data.to_step}</strong> in <strong>${data.latency_ms}ms</strong>.
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
        isRunning = false;
        enablePills();
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
        <span class="chk-index">#${data.step_index}</span>
        <span class="chk-id">${data.checkpoint_id}</span>
      </div>
      <span class="chk-status clean" id="status-${data.checkpoint_id}">${data.status}</span>
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
      <span>Time-Travel Rollback: Step ${fromStep} &rarr; Step ${toStep} (${latencyMs}ms)</span>
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

  function hidePlaceholders() {
    if (feedPlaceholder) feedPlaceholder.style.display = 'none';
    if (lineagePlaceholder) lineagePlaceholder.style.display = 'none';
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
    if (isRunning) return;
    isRunning = true;
    disablePills();
    resetCockpit();
    hidePlaceholders();

    try {
      const res = await fetch('/api/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario_id: scenarioId,
          protected: isProtected,
          delay: 0.6
        })
      });
      const data = await res.json();
      console.log('Scenario completed:', data);
    } catch (err) {
      console.error('Failed to dispatch scenario:', err);
      addThreadCard({
        variant: 'quarantine',
        tag: 'Dispatch Error',
        body: `Error contacting backend: ${escapeHtml(err.message)}`
      });
      isRunning = false;
      enablePills();
    }
  }

  function disablePills() {
    btnScenario1.disabled = true;
    btnScenario2.disabled = true;
    btnScenario3.disabled = true;
  }

  function enablePills() {
    btnScenario1.disabled = false;
    btnScenario2.disabled = false;
    btnScenario3.disabled = false;
  }

  btnScenario1.onclick = () => runScenario('poisoned_invoice');
  btnScenario2.onclick = () => runScenario('malicious_pr');
  btnScenario3.onclick = () => runScenario('clean_workflow');

  // ══════════════════════════════════════════════════════════════
  // Modals & Inspector
  // ══════════════════════════════════════════════════════════════
  btnForensics.onclick = async () => {
    try {
      const res = await fetch('/api/forensics');
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
      const chkRes = await fetch('/api/checkpoints');
      const list = await chkRes.json();
      if (list.length < 2) {
        modalTitle.textContent = 'Checkpoint State Diff';
        modalCode.textContent = 'At least two checkpoints are needed to compute a state difference. Run a scenario first.';
        modalBackdrop.classList.add('open');
        return;
      }
      const a = list[0].checkpoint_id;
      const b = list[list.length - 1].checkpoint_id;
      const diffRes = await fetch(`/api/checkpoints/diff?a=${a}&b=${b}`);
      const diffData = await diffRes.json();
      modalTitle.textContent = `State Mutation: [${a}] vs [${b}]`;
      modalCode.textContent = JSON.stringify(diffData, null, 2);
      modalBackdrop.classList.add('open');
    } catch (err) {
      console.error(err);
    }
  };

  btnClear.onclick = () => {
    resetCockpit();
    isRunning = false;
    enablePills();
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
    if (!str) return '';
    return str.toString()
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  // Copy command button with tactile feedback
  const btnCopyCmd = document.getElementById('btnCopyCmd');
  const installCmd = document.getElementById('installCmd');
  const copyText = document.getElementById('copyText');
  const copyIcon = document.getElementById('copyIcon');

  if (btnCopyCmd && installCmd) {
    btnCopyCmd.addEventListener('click', async () => {
      const textToCopy = installCmd.textContent.trim() || 'pip install whipper-firewall && whipper listen';
      try {
        await navigator.clipboard.writeText(textToCopy);
      } catch (err) {
        const textarea = document.createElement('textarea');
        textarea.value = textToCopy;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
      btnCopyCmd.classList.add('copied');
      copyText.textContent = 'copied!';
      copyIcon.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;
      setTimeout(() => {
        btnCopyCmd.classList.remove('copied');
        copyText.textContent = 'copy';
        copyIcon.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
      }, 2000);
    });
  }

  // Initialize
  initWebSocket();
});
