"""
Tool classification and deterministic content checks for real agent tool calls.

Maps tool names from OpenClaw, Claude Code, DeepSeek-Harness and generic agents
onto a small set of kinds, extracts the fields that matter (command, path, url,
outbound text), and checks them for secrets, protected paths and exfil hosts.
"""

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# kind → tool names (lowercased). Unknown tools are "other".
KIND_TOOLS: Dict[str, set] = {
    "exec": {
        "exec", "bash", "shell", "terminal", "process", "bash_exec", "shell_exec", "execute_shell",
        "run_command", "run_shell", "subprocess_spawn", "child_process", "pty_exec", "term_input",
        "terminal_run", "code_mode_exec", "mcp_remote_exec", "computer",
    },
    "spawn": {"spawn", "sessions_spawn", "nodes", "portal"},
    "fs_write": {
        "write", "edit", "multiedit", "apply_patch", "notebookedit", "fs_write", "fs_move", "fs_write_file",
        "fs_move_file", "fs_chmod", "patch_apply", "write_file", "create_file", "str_replace_editor",
    },
    "fs_delete": {"fs_delete", "fs_delete_file", "delete_file", "rm"},
    "fs_read": {"read", "fs_read", "fs_read_file", "read_file", "view", "cat", "grep", "glob", "fs_list_dir"},
    "network": {
        "web_fetch", "webfetch", "fetch", "http", "http_request", "send_http", "post_webhook", "curl",
        "browser_navigate", "browser_goto", "download",
    },
    "search": {"web_search", "websearch", "search_web", "search"},
    "browser": {"browser", "browser_evaluate", "browser_click", "mobile_ui"},
    "message": {
        "message", "send_message", "sessions_send", "conversations_send", "conversations_turn", "send_email",
        "reply", "post_message", "slack_send", "telegram_send",
    },
    "control": {"gateway", "plugins", "automations", "openclaw", "cron", "cron_register", "schedule_job", "intent"},
}
_NAME_TO_KIND = {name: kind for kind, names in KIND_TOOLS.items() for name in names}

# Kinds that can move data off the machine or change it irreversibly
OUTBOUND_KINDS = {"exec", "spawn", "network", "browser", "message"}
MUTATING_KINDS = {"exec", "spawn", "fs_write", "fs_delete", "control"}
# Kinds whose output is external content that must be treated as untrusted input
UNTRUSTED_RESULT_KINDS = {"network", "search", "browser"}

_COMMAND_KEYS = ("command", "cmd", "script", "shell", "code", "commandLine", "input")
_PATH_KEYS = ("path", "file_path", "filePath", "file", "target", "destination", "dest", "filename", "notebook_path")
_URL_KEYS = ("url", "uri", "href", "endpoint", "link")
_TEXT_KEYS = ("content", "text", "message", "body", "data", "payload", "new_string", "patch", "prompt", "query")

SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws-secret-key", re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"=: ]+[A-Za-z0-9/+]{40}\b")),
    ("private-key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("github-token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("openai-key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9_-]{32,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}\b")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe-key", re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{24,}\b")),
    ("telegram-bot-token", re.compile(r"\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]

# Writes here grant persistence or credentials; reads here expose secrets
PROTECTED_WRITE_PATHS = re.compile(
    r"(^|/)(\.ssh/|\.aws/|\.kube/|\.gnupg/|\.docker/config\.json|\.netrc|\.git-credentials)|"
    r"(^|/)\.(bashrc|zshrc|profile|bash_profile|zprofile|zshenv|config/fish/config\.fish)$|"
    r"(^|/)(Library/LaunchAgents|Library/LaunchDaemons)/|^/etc/|^/usr/|^/bin/|^/sbin/|^/boot/|^/System/|"
    r"(^|/)\.git/hooks/|(^|/)crontab|/var/spool/cron|(^|/)\.config/systemd/|(^|/)\.openclaw/|(^|/)\.claude/settings",
    re.IGNORECASE,
)
SECRET_READ_PATHS = re.compile(
    r"(^|/)\.env(\.[\w-]+)?$|(^|/)id_(rsa|ed25519|ecdsa|dsa)$|(^|/)\.ssh/|(^|/)\.aws/credentials|(^|/)\.netrc$|"
    r"(^|/)\.git-credentials$|(^|/)\.kube/config$|(^|/)\.docker/config\.json$|\.pem$|\.p12$|\.key$|"
    r"(^|/)etc/(shadow|sudoers)$|(^|/)\.gnupg/|(^|/)Keychains/|(^|/)\.config/gh/hosts\.yml$",
    re.IGNORECASE,
)
EXFIL_HOSTS = re.compile(
    r"(^|\.)(webhook\.site|requestbin\.(com|net)|pipedream\.net|ngrok(-free)?\.(io|app|dev)|pastebin\.com|"
    r"transfer\.sh|0x0\.st|file\.io|interact\.sh|oast\.(fun|me|pro|site|live|online)|burpcollaborator\.net|"
    r"hookbin\.com|beeceptor\.com|requestcatcher\.com|discord(app)?\.com/api/webhooks|canarytokens\.com)$",
    re.IGNORECASE,
)


@dataclass
class ToolView:
    name: str
    kind: str
    command: str = ""
    paths: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    text: str = ""

    def outbound(self) -> bool:
        return self.kind in OUTBOUND_KINDS


@dataclass
class ContentFinding:
    rule: str
    severity: str  # medium | high | critical
    detail: str


def classify(name: str) -> str:
    n = (name or "").strip().lower()
    if n in _NAME_TO_KIND:
        return _NAME_TO_KIND[n]
    # mcp__server__tool and namespaced names
    tail = re.split(r"[.:/]|__", n)[-1]
    if tail in _NAME_TO_KIND:
        return _NAME_TO_KIND[tail]
    for kind, words in (("exec", ("exec", "shell", "bash", "terminal", "command")),
                        ("network", ("fetch", "http", "webhook", "request", "upload")),
                        ("message", ("send", "message", "email", "post")),
                        ("fs_write", ("write", "edit", "patch", "save", "create")),
                        ("fs_delete", ("delete", "remove", "unlink")),
                        ("fs_read", ("read", "open", "view", "list"))):
        if any(w in tail for w in words):
            return kind
    return "other"


def _first_str(params: Dict[str, Any], keys) -> str:
    for k in keys:
        v = params.get(k)
        if isinstance(v, str) and v.strip():
            return v
        if isinstance(v, (list, tuple)) and v and all(isinstance(x, str) for x in v):
            return " ".join(v)
    return ""


def view(name: str, params: Optional[Dict[str, Any]]) -> ToolView:
    params = params if isinstance(params, dict) else {}
    kind = classify(name)
    tv = ToolView(name=name, kind=kind)
    if kind in ("exec", "spawn", "other"):
        tv.command = _first_str(params, _COMMAND_KEYS)
    for k in _PATH_KEYS:
        v = params.get(k)
        if isinstance(v, str) and v:
            tv.paths.append(v)
    for k in ("paths", "files"):
        v = params.get(k)
        if isinstance(v, list):
            tv.paths.extend(str(x) for x in v if isinstance(x, (str, os.PathLike)))
    patch = (params.get("patch") or params.get("input")) if kind == "fs_write" else None
    if isinstance(patch, str):
        tv.paths.extend(re.findall(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$", patch, re.M))
        tv.paths.extend(re.findall(r"^\+\+\+ (?:b/)?(\S+)", patch, re.M))
    for k in _URL_KEYS:
        v = params.get(k)
        if isinstance(v, str) and v:
            tv.urls.append(v)
    texts = [str(params[k]) for k in _TEXT_KEYS if k in params and params[k] not in (None, "")]
    if not texts and kind in OUTBOUND_KINDS:
        texts = [json.dumps(params, default=str)]
    tv.text = "\n".join(texts)[:200_000]
    if tv.command:
        tv.urls.extend(re.findall(r"https?://[^\s'\"|;&)]+", tv.command))
    return tv


def has_payload(params: Dict[str, Any]) -> bool:
    """True when the call carries a body/data field, i.e. it can upload something."""
    return any(params.get(k) not in (None, "", {}, []) for k in ("content", "text", "message", "body", "data", "payload", "json", "form", "files"))


def find_secrets(text: str) -> List[ContentFinding]:
    out = []
    for rule, pattern in SECRET_PATTERNS:
        m = pattern.search(text or "")
        if m:
            masked = m.group(0)[:6] + "…" if len(m.group(0)) > 8 else "…"
            out.append(ContentFinding(f"secret:{rule}", "critical", f"{rule} ({masked})"))
    return out


def _norm(path: str) -> str:
    p = os.path.expanduser(path.strip().strip("'\""))
    home = os.path.expanduser("~")
    return p.replace(home, "~", 1) if p.startswith(home) else p


def protected_write(paths: List[str]) -> Optional[str]:
    for p in paths:
        for candidate in (p, _norm(p), os.path.expanduser(p)):
            if PROTECTED_WRITE_PATHS.search(candidate):
                return p
    return None


def secret_read(paths: List[str]) -> Optional[str]:
    for p in paths:
        for candidate in (p, _norm(p), os.path.expanduser(p)):
            if SECRET_READ_PATHS.search(candidate):
                return p
    return None


def exfil_host(urls: List[str]) -> Optional[str]:
    for u in urls:
        try:
            parsed = urlparse(u if "://" in u else f"https://{u}")
        except ValueError:
            continue
        host = (parsed.hostname or "").lower()
        target = host + (parsed.path if "discord" in host else "")
        if host and EXFIL_HOSTS.search(target):
            return host
    return None


def secrets_in_url(urls: List[str]) -> List[ContentFinding]:
    findings = []
    for u in urls:
        findings.extend(find_secrets(u))
    return findings
