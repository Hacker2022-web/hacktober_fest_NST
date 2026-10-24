# wippr guard — OpenClaw plugin

Runs every OpenClaw tool call through [wippr](../../../README.md) before it executes.

| Hook | What wippr does |
| :-- | :-- |
| `before_tool_call` | Gates the call. Returns `block` (with a reason and incident id) or `requireApproval` (allow-once / deny), or nothing to let OpenClaw continue. Fails closed if wippr can't be reached. |
| `after_tool_call` | Records results of `web_fetch`, `web_search` and `browser` as untrusted input; local reads and command output only count if they carry an injection. |
| `message_received` | Records inbound channel messages. Non-owner senders taint the session. |

`ctx.requester.senderIsOwner` is honoured: runs started by someone other than the owner need approval for `exec`, file writes and outbound tools.

## Install

```bash
wippr openclaw plugin --dir ~/.wippr/openclaw-plugin
openclaw plugins install --link ~/.wippr/openclaw-plugin --force
openclaw plugins enable wippr-guard
```

## Configure (`plugins.entries.wippr-guard.config`)

| Key | Default | Meaning |
| :-- | :-- | :-- |
| `wipprCommand` / `wipprArgs` | `wippr` / `[]` | How to start wippr. Use `python3` with `["-m", "wippr"]` if it isn't on the gateway's PATH. |
| `gateUrl` / `token` | — | Talk to a running `wippr serve` instead of spawning (token in `~/.wippr/token`). Faster for busy gateways. |
| `mode` | `enforce` | `monitor` logs verdicts without blocking — use it to trial wippr. |
| `failClosed` | `true` | Block tool calls when wippr errors or times out. |
| `timeoutMs` | `10000` | Per-call budget (OpenClaw itself fails closed at 15 s). |
| `ingestToolResults` / `ingestMessages` | `true` | Feed results and inbound messages into taint tracking. |

## Inspect

```bash
wippr session list           # sessions OpenClaw has used
wippr session show <key>     # taint, checkpoints, decisions, incidents
wippr incidents              # everything that was blocked or held
```

## Test

```bash
node --test wippr/integrations/openclaw/guard.test.mjs   # from the wippr repo
```
