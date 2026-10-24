"""
Terminal presentation helpers for the wippr CLI.

Colour is enabled only for TTYs and honours NO_COLOR / FORCE_COLOR.
Unicode symbols fall back to ASCII when the output encoding can't represent them.
"""

import os
import re
import shutil
import sys
from typing import List, Optional, Sequence

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _supports_color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("TERM") == "dumb":
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _supports_unicode(stream) -> bool:
    encoding = (getattr(stream, "encoding", None) or "").lower()
    return "utf" in encoding


class Theme:
    def __init__(self):
        self.color = _supports_color(sys.stdout)
        self.unicode = _supports_unicode(sys.stdout)
        if self.color and os.name == "nt":
            os.system("")  # enables ANSI escape processing on Windows 10+ consoles

    def disable_color(self):
        self.color = False

    def _wrap(self, code: str, text: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.color else text

    def bold(self, t: str) -> str: return self._wrap("1", t)
    def dim(self, t: str) -> str: return self._wrap("2", t)
    def red(self, t: str) -> str: return self._wrap("31", t)
    def green(self, t: str) -> str: return self._wrap("32", t)
    def yellow(self, t: str) -> str: return self._wrap("33", t)
    def blue(self, t: str) -> str: return self._wrap("34", t)
    def magenta(self, t: str) -> str: return self._wrap("35", t)
    def cyan(self, t: str) -> str: return self._wrap("36", t)
    # Brand mustard (#D5A52E) via 256-colour palette
    def accent(self, t: str) -> str: return self._wrap("38;5;178", t)

    def badge(self, text: str, kind: str) -> str:
        """Inverse-video status badge, e.g. ' BLOCKED '."""
        codes = {"ok": "30;42", "fail": "97;41", "warn": "30;43", "info": "30;46"}
        label = f" {text} "
        return self._wrap(codes.get(kind, "7") + ";1", label) if self.color else f"[{text}]"

    def sym(self, name: str) -> str:
        table = {
            "ok": ("✓", "+"), "fail": ("✗", "x"), "warn": ("!", "!"), "dot": ("●", "*"),
            "arrow": ("→", "->"), "rewind": ("↺", "<-"), "bar": ("│", "|"), "pointer": ("›", ">"),
            "dash": ("─", "-"),
        }
        uni, ascii_ = table[name]
        return uni if self.unicode else ascii_


theme = Theme()


def visible_len(text: str) -> int:
    return len(_ANSI_RE.sub("", text))


def term_width(default: int = 100) -> int:
    return max(60, min(shutil.get_terminal_size((default, 24)).columns, 140))


def truncate(text: str, width: int) -> str:
    text = " ".join(str(text).split())
    if len(text) <= width:
        return text
    return text[: max(0, width - 1)] + ("…" if theme.unicode else "~")


def pad(text: str, width: int) -> str:
    return text + " " * max(0, width - visible_len(text))


def out(text: str = "") -> None:
    print(text)


def read_stdin_text() -> str:
    """Reads all of stdin as UTF-8, replacing undecodable bytes (binary or mis-encoded input never crashes)."""
    buf = getattr(sys.stdin, "buffer", None)
    if buf is not None:
        return buf.read().decode("utf-8", errors="replace")
    return sys.stdin.read()


def err(text: str) -> None:
    print(text, file=sys.stderr)


def rule(width: Optional[int] = None) -> str:
    return theme.dim(theme.sym("dash") * (width or min(term_width(), 88)))


def header(title: str, subtitle: str = "") -> None:
    """Section heading: '▌ title  subtitle'."""
    mark = theme.accent("▌" if theme.unicode else "|")
    line = f"{mark} {theme.bold(title)}"
    if subtitle:
        line += f"  {theme.dim(subtitle)}"
    out()
    out(line)
    out()


def kv(key: str, value: str, key_width: int = 12, indent: int = 2) -> None:
    out(" " * indent + theme.dim(pad(key, key_width)) + value)


def table(headers: Sequence[str], rows: List[Sequence[str]], indent: int = 2) -> None:
    """Renders an aligned table; cell widths ignore ANSI codes."""
    widths = [visible_len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], visible_len(cell))
    gap = "  "
    prefix = " " * indent
    last = len(headers) - 1

    def cell_text(text: str, i: int) -> str:
        return text if i == last else pad(text, widths[i])

    out(prefix + gap.join(theme.dim(cell_text(h.upper(), i)) for i, h in enumerate(headers)))
    for row in rows:
        out(prefix + gap.join(cell_text(cell, i) for i, cell in enumerate(row)))


SEVERITY_STYLE = {
    "critical": lambda t: theme.red(theme.bold(t)),
    "high": theme.red,
    "medium": theme.yellow,
    "low": theme.dim,
    "none": theme.green,
}


def severity(level: str) -> str:
    return SEVERITY_STYLE.get(level, str)(level)
