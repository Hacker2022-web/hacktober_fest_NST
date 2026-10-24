"""
Static risk analysis for shell commands proposed by agents.

Used by the firewall for any tool call that carries a `command` / `cmd`
argument, and by `wippr check` / `wippr exec` on the command line.
"""

import re
from dataclasses import dataclass, asdict
from typing import Dict, List, Pattern, Tuple

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class CommandFinding:
    rule: str
    severity: str  # low | medium | high | critical
    description: str
    match: str

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


_FLAGS = re.IGNORECASE

# (rule id, severity, description, pattern)
_RULES: List[Tuple[str, str, str, Pattern]] = [
    # Remote code piped straight into an interpreter
    ("pipe-to-shell", "critical", "Downloads remote content and pipes it into a shell/interpreter",
     re.compile(r"\b(curl|wget|fetch|iwr|invoke-webrequest)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k|c|fi)?sh\b|"
                r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(python[0-9.]*|perl|ruby|node|php)\b", _FLAGS)),
    ("shell-eval-remote", "critical", "Evaluates remotely downloaded code via command substitution",
     re.compile(r"(ba|z)?sh\s+-c\s+[\"']?\$\(\s*(curl|wget)\b|\beval\s+[\"']?\$\(\s*(curl|wget)\b|"
                r"(ba|z)?sh\s+<\(\s*(curl|wget)\b", _FLAGS)),
    ("reverse-shell", "critical", "Opens a reverse shell to a remote host",
     re.compile(r"/dev/(tcp|udp)/|\b(nc|ncat|netcat)\b[^|;&]*\s-[a-z]*e\b|\bsocat\b[^|;&]*exec:|"
                r"\bbash\s+-i\b[^|;&]*>&|\bmkfifo\b[^|;&]*\b(nc|ncat)\b", _FLAGS)),
    ("data-exfiltration", "critical", "Uploads local data to a remote endpoint",
     re.compile(r"\|\s*(curl|wget|nc|ncat)\b|"
                r"\bcurl\b[^|;&]*\s(-d|--data(-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file)\s*[\"']?@|"
                r"\bwget\b[^|;&]*--post-file", _FLAGS)),
    ("credential-access", "high", "Reads credentials, keys, or secret stores",
     re.compile(r"~?/?\.ssh/(id_[a-z0-9]+|authorized_keys|config)|\.aws/credentials|\.kube/config|"
                r"\.docker/config\.json|\.netrc|\.git-credentials|/etc/(shadow|sudoers)|"
                r"\bsecurity\s+find-(generic|internet)-password\b|\.gnupg/|\bkeychain\b", _FLAGS)),
    ("env-dump", "high", "Dumps environment variables that may contain secrets",
     re.compile(r"(^|[;&|]\s*)(env|printenv|set)\s*(\||>|$)|\bcat\s+[^|;&]*\.env\b|/proc/[0-9a-z]+/environ", _FLAGS)),
    ("destructive-delete", "critical", "Recursively deletes critical or root-level paths",
     re.compile(r"\brm\s+(-[a-z]*r[a-z]*f?|-[a-z]*f[a-z]*r|--recursive)[a-z\s-]*\s+"
                r"(/|/\*|~|~/|\$home|/(etc|usr|var|bin|boot|lib|opt|system|users|home)(/[^\s]*)?)(\s|$)|"
                r"--no-preserve-root", _FLAGS)),
    ("disk-wipe", "critical", "Overwrites or formats a disk device",
     re.compile(r"\bmkfs(\.[a-z0-9]+)?\b|\bdd\b[^|;&]*\bof=/dev/(sd|nvme|disk|hd|xvd|mmcblk)|"
                r">\s*/dev/(sd|nvme|disk|hd)|\bdiskutil\s+(erase|zero)|\bshred\b", _FLAGS)),
    ("fork-bomb", "critical", "Fork bomb / resource exhaustion",
     re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", _FLAGS)),
    ("crypto-miner", "critical", "Crypto-miner binary or mining pool",
     re.compile(r"\b(xmrig|cpuminer|minerd|ethminer|nbminer|t-rex|lolminer|cgminer|bfgminer)\b|"
                r"stratum\+(tcp|ssl)://|\b(supportxmr|nanopool|minexmr|hashvault|moneroocean|nicehash)\b", _FLAGS)),
    ("persistence", "high", "Installs persistence (cron, shell profile, launch agents, services)",
     re.compile(r"\bcrontab\b|/etc/cron|>>?\s*~?/?\.?(bashrc|zshrc|profile|bash_profile)\b|"
                r"LaunchAgents|LaunchDaemons|\bsystemctl\s+(enable|daemon-reload)\b|/etc/rc\.local", _FLAGS)),
    ("security-tamper", "high", "Disables security controls or wipes audit logs",
     re.compile(r"\bsetenforce\s+0\b|\bufw\s+disable\b|\biptables\s+-F\b|\bspctl\s+--master-disable\b|"
                r"\bcsrutil\s+disable\b|history\s+-c|/var/log/(audit|auth|secure)|unset\s+HISTFILE", _FLAGS)),
    ("privilege-escalation", "medium", "Escalates privileges or loosens permissions broadly",
     re.compile(r"\bsudo\b|\bchmod\s+(-R\s+)?(777|\+s|u\+s)\b|\bchown\s+-R\s+root\b", _FLAGS)),
    ("obfuscation", "high", "Decodes and executes obfuscated payloads",
     re.compile(r"base64\s+(-d|--decode|-D)[^|;&]*\|\s*(ba|z)?sh\b|\bxxd\s+-r[^|;&]*\|\s*(ba|z)?sh\b|"
                r"python[0-9.]*\s+-c\s+[\"'][^\"']*(exec|eval)\s*\(", _FLAGS)),
    ("remote-download", "low", "Downloads content from the network",
     re.compile(r"\b(curl|wget)\b", _FLAGS)),
]


def analyze_command(command: str) -> List[CommandFinding]:
    """Returns all rule findings for a shell command, most severe first."""
    if not command:
        return []
    findings: List[CommandFinding] = []
    seen = set()
    for rule_id, severity, description, pattern in _RULES:
        m = pattern.search(command)
        if m and rule_id not in seen:
            seen.add(rule_id)
            findings.append(CommandFinding(rule_id, severity, description, m.group(0).strip()[:80]))
    # A plain download is only noteworthy when nothing worse fired
    if len(findings) > 1:
        findings = [f for f in findings if f.rule != "remote-download"]
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)
    return findings


def max_severity(findings: List[CommandFinding]) -> str:
    """Highest severity among findings, or 'none'."""
    if not findings:
        return "none"
    return max(findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity


def is_blocking(findings: List[CommandFinding]) -> bool:
    """High and critical findings block execution."""
    return any(SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER["high"] for f in findings)


def extract_command(arguments: Dict) -> str:
    """Pulls a shell command string out of tool-call arguments, if present."""
    if not isinstance(arguments, dict):
        return ""
    for key in ("command", "cmd", "script", "shell", "code"):
        val = arguments.get(key)
        if isinstance(val, str):
            return val
        if isinstance(val, (list, tuple)) and all(isinstance(v, str) for v in val):
            return " ".join(val)
    return ""
