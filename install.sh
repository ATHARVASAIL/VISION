#!/usr/bin/env bash
# Vision bootstrap installer.
#
#   ./install.sh              install into a venv here
#   ./install.sh --system     also symlink into /usr/local/bin
#
# Safe to re-run. Installs nothing outside the venv unless --system is passed.

set -euo pipefail

BOLD=$'\033[1m'; DIM=$'\033[2m'; GRN=$'\033[38;5;114m'
YLW=$'\033[38;5;221m'; RED=$'\033[38;5;203m'; ACC=$'\033[38;5;81m'; OFF=$'\033[0m'

ok()   { printf '  %s✓%s %s\n' "$GRN" "$OFF" "$1"; }
warn() { printf '  %s!%s %s\n' "$YLW" "$OFF" "$1"; }
bad()  { printf '  %s✗%s %s\n' "$RED" "$OFF" "$1"; }
info() { printf '  %s·%s %s\n' "$ACC" "$OFF" "$1"; }
head_() { printf '\n%s▸ %s%s\n' "$BOLD" "$1" "$OFF"; }

SYSTEM=0
[[ "${1:-}" == "--system" ]] && SYSTEM=1

cd "$(dirname "$0")"

head_ "Environment"

if [[ ! -f pyproject.toml ]]; then
  bad "run this from the vision directory (pyproject.toml not found)"
  exit 1
fi

PY=$(command -v python3 || true)
if [[ -z "$PY" ]]; then
  bad "python3 not found"
  exit 1
fi
PYV=$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
if "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)'; then
  ok "python $PYV"
else
  bad "python 3.10+ required, found $PYV"
  exit 1
fi

DISTRO=$(grep -oP '^ID=\K.*' /etc/os-release 2>/dev/null | tr -d '"' || echo unknown)
if [[ "$DISTRO" == "kali" ]]; then
  ok "Kali detected — most tools should already be present"
else
  info "distro: $DISTRO (Kali is the best-supported platform)"
fi

# python3-venv is a separate package on Debian derivatives and its absence
# produces a confusing error deep inside the venv creation step.
if ! "$PY" -c 'import venv, ensurepip' 2>/dev/null; then
  warn "python3-venv missing — installing"
  SUDO=""; [[ $EUID -ne 0 ]] && SUDO="sudo"
  $SUDO apt-get update -qq && $SUDO apt-get install -y python3-venv python3-pip
fi

head_ "Virtual environment"
if [[ -d .venv ]]; then
  info "reusing existing .venv"
else
  "$PY" -m venv .venv
  ok "created .venv"
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -e .

# Verify the package is actually importable. `pip install -e .` can succeed
# while installing nothing if the project layout is wrong, and a bare
# $(vision --version) inside a string masks the failure.
if ! VER=$(vision --version 2>&1); then
  bad "vision installed but not runnable:"
  printf '%s\n' "$VER" | sed 's/^/      /'
  exit 1
fi
if ! "$PY" -c 'import vision.cli' 2>/dev/null; then
  bad "package not importable — check pyproject packaging config"
  exit 1
fi
ok "$VER"

if [[ $SYSTEM -eq 1 ]]; then
  SUDO=""; [[ $EUID -ne 0 ]] && SUDO="sudo"
  $SUDO ln -sf "$(pwd)/.venv/bin/vision" /usr/local/bin/vision
  ok "symlinked to /usr/local/bin/vision"
fi

head_ "Self-test"
if ./run_tests.sh >/dev/null 2>&1; then
  ok "test suite passed"
else
  warn "test suite reported failures — run: ./run_tests.sh"
fi

# setup.sh calls this script and then performs these steps itself, so
# repeating them there would tell the operator to do work already done.
if [[ "${VISION_FROM_SETUP:-0}" != "1" ]]; then
  head_ "Next steps"
  info "${ACC}./setup.sh${OFF}        do everything below in one command"
  printf '\n'
  info "or step by step:"
  info "  1. ${ACC}vision doctor${OFF}   see what's installed"
  info "  2. ${ACC}vision setup${OFF}    install the missing toolchain"
  info "  3. ${ACC}vision index${OFF}    build the Metasploit module index"
  printf '\n'
  info "then: ${ACC}vision${OFF}  (or ${ACC}vision run --scope IP --rfc1918-only${OFF})"
fi

if [[ $SYSTEM -eq 0 ]]; then
  printf '\n'
  warn "activate the venv in new shells: ${DIM}source $(pwd)/.venv/bin/activate${OFF}"
  info "or re-run with ${ACC}--system${OFF} to symlink it onto your PATH"
fi
printf '\n'
