// wippr guard for OpenClaw — framework-independent core.
//
// Talks to wippr either by spawning `wippr hook --format openclaw` per event (default,
// no daemon) or over HTTP to `wippr serve` (`gateUrl` + `token`). Kept free of OpenClaw
// imports so it can be unit-tested with plain Node.

import { spawn } from "node:child_process";

export const DEFAULTS = Object.freeze({
  wipprCommand: "wippr",
  wipprArgs: [],
  gateUrl: "",
  token: "",
  timeoutMs: 10000, // OpenClaw fails before_tool_call closed at 15 s; stay well under it
  failClosed: true,
  mode: "enforce", // or "monitor": log verdicts, never block
  ingestToolResults: true,
  ingestMessages: true,
  approvalTimeoutMs: 120000,
});

export function sessionOf(event = {}, ctx = {}) {
  const r = ctx.requester || {};
  return String(
    ctx.sessionKey || ctx.sessionId || event.sessionKey || event.sessionId ||
      (r.channel || r.senderId ? `${r.channel || "channel"}:${r.senderId || "unknown"}` : "openclaw"),
  );
}

function runCli(cfg, payload) {
  return new Promise((resolve, reject) => {
    const args = [...cfg.wipprArgs, "hook", "--format", "openclaw"];
    if (cfg.mode === "monitor") args.push("--monitor");
    if (!cfg.failClosed) args.push("--fail-open");
    let child;
    try {
      child = spawn(cfg.wipprCommand, args, { stdio: ["pipe", "pipe", "pipe"], env: process.env });
    } catch (e) {
      reject(e);
      return;
    }
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`wippr timed out after ${cfg.timeoutMs} ms`));
    }, cfg.timeoutMs);
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", () => {
      clearTimeout(timer);
      try {
        resolve(JSON.parse(stdout.trim().split("\n").pop() || "{}"));
      } catch {
        reject(new Error(`wippr returned invalid output: ${(stderr || stdout).slice(0, 300)}`));
      }
    });
    child.stdin.end(JSON.stringify(payload));
  });
}

async function runHttp(cfg, payload, fetchImpl) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), cfg.timeoutMs);
  try {
    const res = await fetchImpl(`${cfg.gateUrl.replace(/\/$/, "")}/v1/hook`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(cfg.token ? { authorization: `Bearer ${cfg.token}` } : {}) },
      body: JSON.stringify({ ...payload, monitor: cfg.mode === "monitor" }),
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`wippr gate HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

export function createGuard(config = {}, deps = {}) {
  const cfg = { ...DEFAULTS, ...(config || {}) };
  const log = deps.log || console;
  const call = deps.call || ((payload) => (cfg.gateUrl ? runHttp(cfg, payload, deps.fetch || fetch) : runCli(cfg, payload)));

  async function beforeToolCall(event = {}, ctx = {}) {
    const payload = {
      event: "before_tool_call",
      session: sessionOf(event, ctx),
      toolName: event.toolName,
      params: event.params || {},
      toolCallId: event.toolCallId,
      requester: ctx.requester || null,
      approvalTimeoutMs: cfg.approvalTimeoutMs,
    };
    try {
      const out = await call(payload);
      if (out && out.error && !out.result) throw new Error(out.error);
      const d = out && out.decision;
      if (d && d.action !== "allow") {
        log.warn?.(`[wippr] ${d.action} ${event.toolName}: ${d.reason} (${d.incident_id || "no incident"})`);
      }
      return (out && out.result) || undefined; // undefined = no decision, let OpenClaw continue
    } catch (e) {
      log.error?.(`[wippr] gate failed for ${event.toolName}: ${e.message}`);
      if (cfg.mode === "monitor" || !cfg.failClosed) return undefined;
      return { block: true, blockReason: `wippr could not inspect ${event.toolName} (${e.message}); blocked because failClosed is on.` };
    }
  }

  async function afterToolCall(event = {}, ctx = {}) {
    if (!cfg.ingestToolResults || event.result === undefined || event.result === null) return;
    try {
      const out = await call({
        event: "after_tool_call",
        session: sessionOf(event, ctx),
        toolName: event.toolName,
        params: event.params || {},
        result: event.result,
      });
      const ing = out && out.ingest;
      if (ing && ing.tainted && (ing.risk === "high" || ing.risk === "critical")) {
        log.warn?.(`[wippr] injection detected in ${event.toolName} result: ${(ing.markers || []).join(", ")}`);
      }
    } catch (e) {
      log.error?.(`[wippr] could not record ${event.toolName} result: ${e.message}`);
    }
  }

  async function messageReceived(event = {}, ctx = {}) {
    if (!cfg.ingestMessages) return;
    const r = ctx.requester || {};
    try {
      await call({
        event: "message_received",
        session: sessionOf(event, ctx),
        content: event.content ?? event.text ?? "",
        channel: event.channel ?? r.channel,
        senderId: event.senderId ?? event.from ?? r.senderId,
        senderIsOwner: event.senderIsOwner ?? r.senderIsOwner,
      });
    } catch (e) {
      log.error?.(`[wippr] could not record inbound message: ${e.message}`);
    }
  }

  return { config: cfg, beforeToolCall, afterToolCall, messageReceived };
}
