// wippr guard — OpenClaw plugin entry.
// Gates every tool call through wippr before it runs, and records tool results and
// inbound channel messages so later calls are checked against untrusted input.
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { createGuard } from "./guard.mjs";

export default definePluginEntry({
  id: "wippr-guard",
  name: "wippr guard",
  description: "In-flight firewall: blocks prompt-injected tool calls before they run.",
  register(api) {
    const guard = createGuard(api.pluginConfig ?? {}, { log: api.logger ?? console });

    // Highest priority so a block is terminal before other plugins rewrite params.
    api.on("before_tool_call", (event, ctx) => guard.beforeToolCall(event, ctx), {
      priority: 1000,
      timeoutMs: guard.config.timeoutMs + 2000,
    });

    // Observation-only hooks: don't await, so they never slow the agent down.
    api.on("after_tool_call", (event, ctx) => {
      void guard.afterToolCall(event, ctx);
    });
    api.on("message_received", (event, ctx) => {
      void guard.messageReceived(event, ctx);
    });
  },
});
