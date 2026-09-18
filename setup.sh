#!/usr/bin/env bash
#
# setup.sh — everything, in one command.
#
#   ./setup.sh            install Vision and get it ready to scan
#   ./setup.sh --tools    also install the missing security toolchain
#
# install.sh builds the Python package. This does that AND the three follow-up
# steps an operator otherwise has to discover one at a time:
#
#   1. put `vision` on PATH
#   2. initialise the Metasploit database (needed before the module index)
#   3. build the offline module index (without it the exploit advisory is
#      silently empty, which reads as "no exploits exist for this host")
#
# Every step is skipped if it is already done, so re-running is safe and fast.

set -uo pipefail

GRN=$'\033[32m'; YEL=$'\033[33m'; RED=$'\033[31m'
DIM=$'\033[2m'; BLD=$'\033[1m'; OFF=$'\033[0m'
ACC=$'\033[38;5;81m'

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

WITH_TOOLS=0
for arg in "$@"; do
  case "$arg" in
    --tools) WITH_TOOLS=1 ;;
    -h|--help)
      sed -n '2,18p' "$0" | sed 's/^# \?//'
      exit 0 ;;
  esac
done

step()  { printf '\n%s▸ %s%s\n' "$ACC" "$1" "$OFF"; }
ok()    { printf '  %s✓%s %s\n' "$GRN" "$OFF" "$1"; }
warn()  { printf '  %s!%s %s\n' "$YEL" "$OFF" "$1"; }
bad()   { printf '  %s✗%s %s\n' "$RED" "$OFF" "$1"; }
note()  { printf '      %s%s%s\n' "$DIM" "$1" "$OFF"; }

printf '%s\n' "$BLD"
printf '   vision setup\n'
printf '%s' "$OFF"
note "one command, then you are ready to scan"

# ---------------------------------------------------------------- 1. package

step "Installing Vision"
if ! VISION_FROM_SETUP=1 bash install.sh --system; then
  bad "install.sh failed — nothing else will work until that is fixed"
  exit 1
fi

VISION="$HERE/.venv/bin/vision"
[[ -x "$VISION" ]] || VISION="$(command -v vision || true)"
if [[ -z "$VISION" ]]; then
  bad "cannot locate the vision binary after install"
  exit 1
fi

# ---------------------------------------------------------------- 2. toolchain

if [[ $WITH_TOOLS -eq 1 ]]; then
  step "Installing the security toolchain"
  note "this can take 10-30 minutes on a fresh box"
  sudo "$VISION" setup --no-banner || warn "some tools did not install — 'vision doctor' will show which"
else
  step "Checking the toolchain"
  MISSING="$("$VISION" doctor --no-banner 2>/dev/null | grep -c '✗' || true)"
  if [[ "${MISSING:-0}" -gt 0 ]]; then
    warn "$MISSING tool(s) missing — stages needing them will skip cleanly"
    note "run ./setup.sh --tools to install them, or 'vision setup' later"
  else
    ok "all known tools present"
  fi
fi

# ---------------------------------------------------------------- 3. metasploit

step "Metasploit"
if ! command -v msfconsole >/dev/null 2>&1; then
  warn "metasploit not installed — scanning and reporting still work"
  note "the exploit advisory needs it; install with: sudo apt install metasploit-framework"
else
  # The database is what makes msfconsole start in seconds instead of minutes.
  if sudo -n true 2>/dev/null || [[ $EUID -eq 0 ]]; then
    sudo msfdb init >/dev/null 2>&1 && ok "database initialised" \
      || note "database already set up, or msfdb reported it was not needed"
  else
    warn "skipping 'msfdb init' — needs sudo"
    note "run: sudo msfdb init"
  fi

  CACHE="${HOME}/.vision/msf-index.json"
  if [[ -s "$CACHE" ]]; then
    ok "module index already built"
  else
    printf '  · building the offline module index…\n'
    if "$VISION" index --no-banner >/dev/null 2>&1; then
      ok "module index built"
      note "without this the exploit advisory is empty, which looks like"
      note "'no exploits exist' rather than 'the index was never built'"
    else
      warn "index build failed — run 'vision index' to see why"
    fi
  fi
fi

# ---------------------------------------------------------------- 4. ready

step "Ready"
ok "$("$VISION" --version 2>/dev/null || echo vision)"
printf '\n  Start here:\n'
printf '    %svision%s                       %sinteractive console%s\n' "$ACC" "$OFF" "$DIM" "$OFF"
printf '    %svision run --scope IP%s        %sautomated assessment%s\n' "$ACC" "$OFF" "$DIM" "$OFF"
printf '\n'
note "only scan systems you own or have written authorisation to test"
printf '\n'
