"""
Prompt-injection scanner for untrusted text (web pages, emails, documents, issues).

    curl -s https://example.com/page | wippr scan
"""

import re
from dataclasses import dataclass, asdict
from typing import Dict, List

from .commands import SEVERITY_ORDER, analyze_command
from .adapters.openclaw import OPENCLAW_SPECIAL_TOKENS, OPENCLAW_SUSPICIOUS_PATTERNS


@dataclass(frozen=True)
class ScanFinding:
    rule: str
    severity: str
    line: int
    description: str
    excerpt: str

    def to_dict(self) -> Dict:
        return asdict(self)


_I = re.IGNORECASE
_DIRECTIVE_WORDS = r"(ignore|disregard|override|system|instruction|you must|immediately|execute|invoke|exec\b|curl|wget|send_http|api[_ -]?key|password|secret|token|exfiltrat)"

_TEXT_RULES = [
    ("instruction-override", "high", "Attempts to override the agent's instructions",
     re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)|"
                r"disregard\s+(all\s+)?(previous|prior|above|your)|forget\s+(everything|all|your)\s+(instructions?|rules?)|"
                r"system\s*(override|cmd|command|prompt)\s*:?|new\s+instructions?\s*:", _I)),
    ("role-hijack", "high", "Tries to reassign the agent's role or persona",
     re.compile(r"\byou\s+are\s+now\s+(a|an|the)\s+|\bact\s+as\s+(an?\s+)?(admin|root|system|developer mode)|"
                r"\bdeveloper\s+mode\s+(enabled|on)\b|\bjailbreak\b", _I)),
    ("tool-directive", "high", "Instructs the agent to invoke a privileged tool",
     re.compile(r"\b(invoke|call|run|execute|use)\s+(the\s+)?(tool\s+)?[`'\"]?"
                r"(send_http|post_webhook|send_email|bash_exec|shell_exec|execute_shell|exec|spawn|terminal|fs_write|fs_delete|subprocess_spawn)\b", _I)),
    ("exfiltration-url", "high", "Contains a URL that looks like an exfiltration endpoint",
     re.compile(r"https?://[^\s\"'<>]+/(exfil|exfiltrate|webhook|leak|collect|steal|dump)\b|webhook\.site|requestbin|pipedream\.net|ngrok\.io", _I)),
    ("credential-targeting", "medium", "Asks for credentials or secrets",
     re.compile(r"\b(aws[_ -]?(secret|access)[_ -]?key|api[_ -]?keys?|private\s+key|ssh\s+key|password|bearer\s+token|credentials)\b", _I)),
]

_HIDDEN_CHARS = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _excerpt(s: str, width: int = 90) -> str:
    s = " ".join(s.split())
    return s if len(s) <= width else s[: width - 1] + "…"


def scan_text(text: str) -> List[ScanFinding]:
    """Scans text for prompt-injection indicators. Returns findings, most severe first."""
    findings: List[ScanFinding] = []
    seen = set()

    def add(rule: str, sev: str, idx: int, desc: str, excerpt: str):
        line = _line_of(text, idx)
        key = (rule, line)
        if key not in seen:
            seen.add(key)
            findings.append(ScanFinding(rule, sev, line, desc, _excerpt(excerpt)))

    for m in _HTML_COMMENT.finditer(text):
        if re.search(_DIRECTIVE_WORDS, m.group(1), _I):
            add("hidden-comment-directive", "high", m.start(), "Hidden HTML comment carries instructions", m.group(0))

    for rule, sev, desc, pattern in _TEXT_RULES:
        for m in pattern.finditer(text):
            add(rule, sev, m.start(), desc, text[max(0, m.start() - 20): m.end() + 40])

    for pattern in OPENCLAW_SUSPICIOUS_PATTERNS:
        m = pattern.search(text)
        if m:
            add("injection-pattern", "medium", m.start(), "Matches a known prompt-injection phrasing", m.group(0))

    for token in OPENCLAW_SPECIAL_TOKENS:
        idx = text.find(token)
        if idx != -1:
            add("special-token-spoofing", "high", idx, f"Contains model control token {token}", token)

    m = _HIDDEN_CHARS.search(text)
    if m:
        add("invisible-characters", "medium", m.start(), "Contains zero-width or bidi control characters (hidden text)",
            repr(text[max(0, m.start() - 10): m.end() + 10]))

    # Embedded shell commands, checked line by line
    offset = 0
    for raw_line in text.splitlines(keepends=True):
        for cf in analyze_command(raw_line):
            if SEVERITY_ORDER[cf.severity] >= SEVERITY_ORDER["high"]:
                add(f"command:{cf.rule}", cf.severity, offset, cf.description, cf.match)
        offset += len(raw_line)

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.line))
    return findings


def risk_level(findings: List[ScanFinding]) -> str:
    if not findings:
        return "none"
    return max(findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity
