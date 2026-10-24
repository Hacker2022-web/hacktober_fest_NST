#!/bin/sh
# wippr installer
#
#   curl -fsSL https://raw.githubusercontent.com/Hacker2022-web/hacktober_fest_NST/main/install.sh | sh
#
# Options (pass after `sh -s --`):
#   --ref <git ref>   install a branch, tag, or commit (default: main)
#   --uninstall       remove wippr
#
# Environment:
#   WIPPR_HOME        install root            (default: ~/.wippr)
#   WIPPR_BIN_DIR     where the `wippr` link goes (default: ~/.local/bin)
#   WIPPR_REF         same as --ref
#   WIPPR_SOURCE      pip-installable path/URL to install instead of GitHub (for testing)

set -eu

REPO="Hacker2022-web/hacktober_fest_NST"

main() {
    WIPPR_HOME="${WIPPR_HOME:-$HOME/.wippr}"
    WIPPR_BIN_DIR="${WIPPR_BIN_DIR:-$HOME/.local/bin}"
    REF="${WIPPR_REF:-main}"
    ACTION="install"

    while [ $# -gt 0 ]; do
        case "$1" in
            --ref) [ $# -ge 2 ] || die "--ref needs a value"; REF="$2"; shift 2 ;;
            --ref=*) REF="${1#--ref=}"; shift ;;
            --uninstall) ACTION="uninstall"; shift ;;
            -h|--help) sed -n '2,16p' "$0" 2>/dev/null || true; exit 0 ;;
            *) die "unknown option: $1" ;;
        esac
    done

    setup_colors
    if [ "$ACTION" = "uninstall" ]; then
        uninstall
        return
    fi

    say "${BOLD}wippr installer${RESET}"

    case "$(uname -s)" in
        Linux|Darwin) ;;
        MINGW*|MSYS*|CYGWIN*) die "on Windows, install with: pip install \"https://github.com/$REPO/archive/$REF.tar.gz\"" ;;
        *) warn "untested platform $(uname -s); continuing" ;;
    esac

    PY="$(find_python)" || die "Python 3.10+ is required. Install it from https://www.python.org/downloads/ and re-run."
    step "using $("$PY" -c 'import sys; print(sys.executable, ".".join(map(str, sys.version_info[:3])))')"

    SOURCE="${WIPPR_SOURCE:-https://github.com/$REPO/archive/$REF.tar.gz}"
    VENV="$WIPPR_HOME/venv"

    mkdir -p "$WIPPR_HOME" "$WIPPR_BIN_DIR"
    if [ ! -x "$VENV/bin/python" ]; then
        step "creating virtual environment in $VENV"
        "$PY" -m venv "$VENV" >/dev/null 2>&1 || die "could not create a virtual environment (on Debian/Ubuntu: sudo apt install python3-venv)"
    fi

    step "installing wippr from $SOURCE"
    "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check --upgrade pip >/dev/null 2>&1 || true
    if ! "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check --upgrade "$SOURCE"; then
        die "pip install failed (see output above)"
    fi

    ln -sf "$VENV/bin/wippr" "$WIPPR_BIN_DIR/wippr"
    VERSION="$("$VENV/bin/wippr" --version 2>/dev/null | head -n 1)" || die "installed, but \`wippr --version\` failed"
    ok "installed ${BOLD}$VERSION${RESET}"
    say "  ${DIM}binary:${RESET} $WIPPR_BIN_DIR/wippr"

    case ":$PATH:" in
        *":$WIPPR_BIN_DIR:"*) ;;
        *)
            say ""
            warn "$WIPPR_BIN_DIR is not on your PATH. Add it with:"
            say "    echo 'export PATH=\"$WIPPR_BIN_DIR:\$PATH\"' >> $(shell_rc) && exec \$SHELL"
            ;;
    esac

    say ""
    say "  ${DIM}get started:${RESET}"
    say "    wippr demo invoice         ${DIM}# watch an attack get stopped${RESET}"
    say "    wippr check \"curl x | sh\"   ${DIM}# vet a command${RESET}"
    say "    wippr serve --open         ${DIM}# web cockpit${RESET}"
    say ""
}

uninstall() {
    if [ -L "$WIPPR_BIN_DIR/wippr" ] || [ -f "$WIPPR_BIN_DIR/wippr" ]; then
        rm -f "$WIPPR_BIN_DIR/wippr"
        step "removed $WIPPR_BIN_DIR/wippr"
    fi
    if [ -d "$WIPPR_HOME/venv" ]; then
        rm -rf "$WIPPR_HOME/venv"
        step "removed $WIPPR_HOME/venv"
    fi
    rmdir "$WIPPR_HOME" 2>/dev/null || true
    ok "wippr uninstalled"
}

find_python() {
    for candidate in python3.13 python3.12 python3.11 python3.10 python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 &&
           "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
            command -v "$candidate"
            return 0
        fi
    done
    return 1
}

shell_rc() {
    case "${SHELL:-}" in
        */zsh) echo "~/.zshrc" ;;
        */bash) [ "$(uname -s)" = Darwin ] && echo "~/.bash_profile" || echo "~/.bashrc" ;;
        */fish) echo "~/.config/fish/config.fish" ;;
        *) echo "~/.profile" ;;
    esac
}

setup_colors() {
    if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
        BOLD="$(printf '\033[1m')"; DIM="$(printf '\033[2m')"; RED="$(printf '\033[31m')"
        GREEN="$(printf '\033[32m')"; YELLOW="$(printf '\033[33m')"; ACCENT="$(printf '\033[38;5;178m')"; RESET="$(printf '\033[0m')"
    else
        BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; ACCENT=""; RESET=""
    fi
}

say()  { printf '%s\n' "$*"; }
step() { printf '%s›%s %s\n' "$ACCENT" "$RESET" "$*"; }
ok()   { printf '%s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%s!%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
die()  { setup_colors 2>/dev/null || true; printf '%serror:%s %s\n' "${RED:-}" "${RESET:-}" "$*" >&2; exit 1; }

# Everything runs from main so a truncated download can't execute a partial script
main "$@"
