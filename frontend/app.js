/**
 * ShadowHarness Cockpit Frontend Application Logic.
 * Handles WebSocket telemetry stream, trajectory visualization, and time-travel lineage graph.
 */

document.addEventListener('DOMContentLoaded', () => {
  // UI Elements
  const fwStatusBadge = document.getElementById('fwStatusBadge');
  const fwStatusText = document.getElementById('fwStatusText');
  const driftBar = document.getElementById('driftBar');
  const driftVal = document.getElementById('driftVal');
  const taintCountEl = document.getElementById('taintCount');
  const rollbackCountEl = document.getElementById('rollbackCount');
  const evalLatencyEl = document.getElementById('evalLatency');
  const toggleProtectionBtn = document.getElementById('toggleProtectionBtn');
  const toggleProtectionLabel = document.getElementById('toggleProtectionLabel');
  const streamStatus = document.getElementById('streamStatus');
  const trajectoryFeed = document.getElementById('trajectoryFeed');
  const lineageGraphContainer = document.getElementById('lineageGraphContainer');
  const lineageSummary = document.getElementById('lineageSummary');
  const inspectorDrawer = document.getElementById('inspectorDrawer');
  const inspectorTitle = document.getElementById('inspectorTitle');
  const inspectorContent = document.getElementById('inspectorContent');
  const closeDrawerBtn = document.getElementById('closeDrawerBtn');

  // Control Buttons
  const btnScenario1 = document.getElementById('btnScenario1');
  const btnScenario2 = document.getElementById('btnScenario2');
  const btnScenario3 = document.getElementById('btnScenario3');
  const clearBtn = document.getElementById('clearBtn');

  // State
  let isProtected = true;
  let taintViolations = 0;
  let rollbackCount = 0;
  let checkpointStore = [];
  let ws = null;
  let isRunning = false;

  // Initialize WebSocket Connection
  function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      console.log('[ShadowHarness] Connected to live telemetry stream.');
    };

    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        handleTelemetryEvent(payload.event, payload.data);
      } catch (err) {
        console.error('Failed to parse WebSocket message:', err);
      }
    };

    ws.onclose = () => {
      console.warn('[ShadowHarness] WebSocket disconnected. Retrying in 2s...');
      setTimeout(initWebSocket, 2000);
    };
  }

  // Handle Inbound Telemetry Events
  function handleTelemetryEvent(eventType, data) {
    console.log(`[Event: ${eventType}]`, data);

    switch (eventType) {
      case 'GOAL_RECEIVED':
        clearFeedPlaceholders();
        streamStatus.textContent = 'EXECUTING';
        streamStatus.className = 'pane-badge running';
        addTrajectoryCard({
          type: 'goal',
          tag: 'USER OBJECTIVE',
          body: `<strong>Goal:</strong> ${data.user_goal}<br><small style="color:var(--text-dim)">Harness: ${data.protected ? 'SHIELD ARMED' : 'VULNERABLE (UNPROTECTED)'}</small>`
        });
        break;

      case 'AGENT_THINKING':
        addTrajectoryCard({
          type: 'thought',
          tag: `STEP ${data.step_index} : REASONING`,
          body: data.thought
        });
        break;

      case 'CHECKPOINT_CAPTURED':
        addCheckpointNode(data);
        break;

      case 'TAINT_DETECTED':
        taintViolations++;
        taintCountEl.textContent = taintViolations;
        const chainBadge = data.source_chain ? `<div class="chain-badge">🔗 Lineage: <code>${escapeHtml(data.source_chain)}</code></div>` : '';
        addTrajectoryCard({
          type: 'taint',
          tag: 'UNTRUSTED DATA INGESTION',
          body: `Source tool <code>${data.source}</code> ingested external payload.
                 ${chainBadge}
                 <div class="danger-tag">${data.markers.join(' | ') || 'UNVERIFIED PAYLOAD'}</div>
                 <div class="payload-snippet">${escapeHtml(data.snippet)}</div>`
        });
        break;

      case 'INTERCEPTING_TOOL_CALL':
        addTrajectoryCard({
          type: 'inspect',
          tag: 'PROPOSED TOOL INVOCATION',
          body: `Candidate Tool: <code>${data.tool_name}</code>
                 <div class="payload-snippet">${escapeHtml(JSON.stringify(data.arguments, null, 2))}</div>`
        });
        break;

      case 'FIREWALL_EVALUATED':
        updateGauges(data.drift_score, data.latency_ms);
        if (data.action === 'QUARANTINE') {
          addTrajectoryCard({
            type: 'quarantine',
            tag: 'SHADOWWALL INTERCEPT: BLOCKED',
            body: `<strong>QUARANTINE ENFORCED MID-THOUGHT</strong><br>
                   Reason: ${data.reason}<br>
                   <small>Drift Score: ${(data.drift_score * 100).toFixed(0)}% | Taint: ${data.taint_violation ? 'VIOLATION' : 'CLEAN'}</small>`
          });
        }
        break;

      case 'TOOL_EXECUTED_UNPROTECTED':
        taintViolations++;
        taintCountEl.textContent = taintViolations;
        updateGauges(0.99, 1.2);
        addTrajectoryCard({
          type: 'pwned',
          tag: 'AGENT PWNED! (NO FIREWALL)',
          body: `<strong>CRITICAL COMPROMISE:</strong> ${data.danger}<br>
                 Tool <code>${data.tool_name}</code> executed unauthorized payload!<br>
                 <div class="payload-snippet">${escapeHtml(JSON.stringify(data.arguments, null, 2))}</div>`
        });
        break;

      case 'TRAJECTORY_QUARANTINED':
        markLastNodeQuarantined(data.blocked_tool);
        break;

      case 'TIME_TRAVEL_ROLLBACK':
        rollbackCount++;
        rollbackCountEl.textContent = rollbackCount;
        renderRewindConnector(data.from_step, data.to_step, data.latency_ms);
        const chainInfo = data.source_chain && data.source_chain.length ? `<div class="chain-badge" style="margin-top:6px;">⛓️ Intercepted Lineage: <code>${escapeHtml(data.source_chain.join(', '))}</code></div>` : '';
        addTrajectoryCard({
          type: 'rollback',
          tag: 'TIME-TRAVEL STATE RECOVERY',
          body: `⏪ <strong>Rollback Executed</strong> in <strong>${data.latency_ms} ms</strong>.<br>
                 Rewound from Step ${data.from_step} to safe checkpoint (Step ${data.to_step}).
                 ${chainInfo}`
        });
        break;

      case 'STATE_RESTORED_AND_MASKED':
        addTrajectoryCard({
          type: 'thought',
          tag: 'SELF-HEALING SCRATCHPAD',
          body: `Context sanitized with security tombstone. Agent memory restored.`
        });
        break;

      case 'TOOL_EXECUTED_SAFE':
        addTrajectoryCard({
          type: 'success',
          tag: 'SAFE TOOL EXECUTED',
          body: `Tool <code>${data.tool_name}</code> completed safely.<br>
                 <div class="payload-snippet">${escapeHtml(JSON.stringify(data.output, null, 2))}</div>`
        });
        break;

      case 'MISSION_SUCCESS':
        streamStatus.textContent = 'COMPLETED';
        streamStatus.className = 'pane-badge';
        addTrajectoryCard({
          type: 'success',
          tag: 'MISSION COMPLETE',
          body: `<strong>${data.summary}</strong>`
        });
        isRunning = false;
        break;
    }
  }

  // Trajectory Card Builder
  function addTrajectoryCard({ type, tag, body }) {
    const card = document.createElement('div');
    card.className = `trajectory-card card-${type}`;

    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');

    card.innerHTML = `
      <div class="card-header">
        <span class="card-tag">${tag}</span>
        <span class="card-time">${timeStr}</span>
      </div>
      <div class="card-body">${body}</div>
    `;

    trajectoryFeed.appendChild(card);
    trajectoryFeed.scrollTop = trajectoryFeed.scrollHeight;
  }

  // Lineage Graph Checkpoint Builder
  function addCheckpointNode(data) {
    clearGraphPlaceholders();
    checkpointStore.push(data);

    const node = document.createElement('div');
    node.className = 'checkpoint-node';
    node.id = `node-${data.checkpoint_id}`;
    node.onclick = () => inspectCheckpoint(data);

    node.innerHTML = `
      <div class="node-left">
        <span class="node-badge node-status-clean">STEP ${data.step_index}</span>
        <span class="node-title">Checkpoint [${data.checkpoint_id}]</span>
      </div>
      <div class="node-right">
        <span>${data.status}</span>
      </div>
    `;

    lineageGraphContainer.appendChild(node);
    lineageGraphContainer.scrollTop = lineageGraphContainer.scrollHeight;
    lineageSummary.textContent = `${checkpointStore.length} Checkpoints Captured`;
  }

  function markLastNodeQuarantined(blockedTool) {
    const nodes = lineageGraphContainer.querySelectorAll('.checkpoint-node');
    if (nodes.length > 0) {
      const lastNode = nodes[nodes.length - 1];
      const badge = lastNode.querySelector('.node-badge');
      badge.className = 'node-badge node-status-quarantine';
      badge.textContent = `QUARANTINE`;
      lastNode.querySelector('.node-right').innerHTML = `<span style="color:var(--accent-red)">Blocked: ${blockedTool}</span>`;
    }
  }

  function renderRewindConnector(fromStep, toStep, latencyMs) {
    const wire = document.createElement('div');
    wire.className = 'rewind-wire';
    wire.innerHTML = `
      <span>&#x21BA; TIME-TRAVEL ROLLBACK: Step ${fromStep} &rarr; Step ${toStep} (${latencyMs}ms)</span>
    `;
    lineageGraphContainer.appendChild(wire);
  }

  function inspectCheckpoint(data) {
    inspectorDrawer.style.display = 'flex';
    inspectorTitle.textContent = `Checkpoint Frame: ${data.checkpoint_id} (Step ${data.step_index})`;
    inspectorContent.textContent = JSON.stringify(data, null, 2);

    // Highlight selected node
    document.querySelectorAll('.checkpoint-node').forEach(n => n.classList.remove('active-selected'));
    const el = document.getElementById(`node-${data.checkpoint_id}`);
    if (el) el.classList.add('active-selected');
  }

  function updateGauges(drift, latency) {
    const percentage = Math.min(100, Math.round(drift * 100));
    driftBar.style.width = `${percentage}%`;
    driftVal.textContent = drift.toFixed(2);
    evalLatencyEl.textContent = `${latency.toFixed(1)} ms`;
  }

  function clearFeedPlaceholders() {
    const ph = trajectoryFeed.querySelector('.feed-placeholder');
    if (ph) ph.remove();
  }

  function clearGraphPlaceholders() {
    const ph = lineageGraphContainer.querySelector('.graph-placeholder');
    if (ph) ph.remove();
  }

  function resetCockpit() {
    trajectoryFeed.innerHTML = `
      <div class="feed-placeholder">
        <div class="placeholder-icon">🛡️</div>
        <h3>System Ready & Listening</h3>
        <p>Select an attack or clean scenario below to initiate an autonomous agent trajectory.</p>
      </div>
    `;
    lineageGraphContainer.innerHTML = `
      <div class="graph-placeholder">
        <p>Checkpoints will be mapped visually as the agent advances through its reasoning loop.</p>
      </div>
    `;
    checkpointStore = [];
    taintViolations = 0;
    rollbackCount = 0;
    taintCountEl.textContent = '0';
    rollbackCountEl.textContent = '0';
    evalLatencyEl.textContent = '0 ms';
    driftBar.style.width = '0%';
    driftVal.textContent = '0.00';
    streamStatus.textContent = 'IDLE';
    streamStatus.className = 'pane-badge';
    lineageSummary.textContent = '0 Checkpoints Captured';
    inspectorDrawer.style.display = 'none';
  }

  function toggleProtection() {
    isProtected = !isProtected;
    if (isProtected) {
      toggleProtectionBtn.className = 'toggle-protection-btn btn-protected';
      toggleProtectionLabel.textContent = 'PROTECTED';
      fwStatusBadge.className = 'status-indicator-badge active';
      fwStatusText.textContent = 'ARMED (ACTIVE)';
    } else {
      toggleProtectionBtn.className = 'toggle-protection-btn btn-unprotected';
      toggleProtectionLabel.textContent = 'VULNERABLE';
      fwStatusBadge.className = 'status-indicator-badge disabled';
      fwStatusText.textContent = 'BYPASSED (OFF)';
    }
  }

  async function triggerScenario(scenarioId) {
    if (isRunning) return;
    isRunning = true;
    resetCockpit();
    clearFeedPlaceholders();
    clearGraphPlaceholders();

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
      console.error('Failed to trigger scenario:', err);
      isRunning = false;
    }
  }

  function escapeHtml(text) {
    if (!text) return '';
    return text.toString()
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  // Forensics and Checkpoint Diff handlers
  const btnForensics = document.getElementById('btnForensics');
  const btnDiff = document.getElementById('btnDiff');

  if (btnForensics) {
    btnForensics.onclick = async () => {
      try {
        const res = await fetch('/api/forensics');
        const data = await res.json();
        inspectorDrawer.style.display = 'flex';
        inspectorTitle.textContent = `Security Forensics Archive (${data.length} incidents logged)`;
        inspectorContent.textContent = JSON.stringify(data, null, 2);
      } catch (err) {
        console.error('Failed to load forensics:', err);
      }
    };
  }

  if (btnDiff) {
    btnDiff.onclick = async () => {
      try {
        const chkRes = await fetch('/api/checkpoints');
        const checkpoints = await chkRes.json();
        if (checkpoints.length < 2) {
          inspectorDrawer.style.display = 'flex';
          inspectorTitle.textContent = 'Checkpoint Diff Engine';
          inspectorContent.textContent = 'Need at least 2 checkpoints to compute a state diff. Run a scenario first.';
          return;
        }
        const chkA = checkpoints[0].checkpoint_id;
        const chkB = checkpoints[checkpoints.length - 1].checkpoint_id;
        const diffRes = await fetch(`/api/checkpoints/diff?a=${chkA}&b=${chkB}`);
        const diffData = await diffRes.json();

        inspectorDrawer.style.display = 'flex';
        inspectorTitle.textContent = `State Mutation Diff: [${chkA}] vs [${chkB}]`;
        inspectorContent.textContent = JSON.stringify(diffData, null, 2);
      } catch (err) {
        console.error('Failed to load checkpoint diff:', err);
      }
    };
  }

  // Event Listeners
  toggleProtectionBtn.onclick = toggleProtection;
  clearBtn.onclick = resetCockpit;
  closeDrawerBtn.onclick = () => { inspectorDrawer.style.display = 'none'; };

  btnScenario1.onclick = () => triggerScenario('poisoned_invoice');
  btnScenario2.onclick = () => triggerScenario('malicious_pr');
  btnScenario3.onclick = () => triggerScenario('clean_workflow');

  // Start WebSocket
  initWebSocket();
});
