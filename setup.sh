#!/usr/bin/env bash
#
# setup.sh — install and set up Vision in one command.
#
#   sudo ./setup.sh            install Vision and build the Metasploit index
#   sudo ./setup.sh --tools    also install the full Kali toolchain (large: GBs)
#   sudo ./setup.sh --minimal  just make `vision` runnable, nothing else
#
# Vision has ZERO Python dependencies — it is pure standard library. So this
# does not build a wheel, create a virtualenv, or run pip (the parts that broke
# before). It installs a tiny launcher that runs this checkout with the system
# python3, which cannot fail as long as python3 ≥ 3.10 is present. Re-running is
# safe; every step is idempotent.

set -uo pipefail

BOLD=$'\033[1m'; DIM=$'\033[2m'; GRN=$'\033[38;5;114m'
YLW=$'\033[38;5;221m'; RED=$'\033[38;5;203m'; ACC=$'\033[38;5;81m'; OFF=$'\033[0m'
ok()    { printf '  %s✓%s %s\n' "$GRN" "$OFF" "$1"; }
warn()  { printf '  %s!%s %s\n' "$YLW" "$OFF" "$1"; }
bad()   { printf '  %s✗%s %s\n' "$RED" "$OFF" "$1"; }
info()  { printf '  %s·%s %s\n' "$ACC" "$OFF" "$1"; }
head_() { printf '\n%s▸ %s%s\n' "$BOLD" "$1" "$OFF"; }

WITH_TOOLS=0; MINIMAL=0
for arg in "$@"; do
  case "$arg" in
    --tools)   WITH_TOOLS=1 ;;
    --minimal) MINIMAL=1 ;;
    -h|--help) sed -n '2,10p' "$0" | sed 's/^#\s\?//'; exit 0 ;;
    *) warn "ignoring unknown option: $arg" ;;
  esac
done

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO"

printf '%s\n   vision setup%s\n' "$BOLD" "$OFF"
info "one command — launcher, then ready to scan"

# ── privilege ────────────────────────────────────────────────────────────────
# Writing the launcher to /usr/local/bin and installing packages needs root.
# The launcher itself runs as whoever calls `vision` later, so scan output is
# owned by that user, not root.
SUDO=""
if [[ $EUID -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    bad "run this as root (or install sudo):  su -c './setup.sh'"
    exit 1
  fi
fi

# ── 1. python3 ≥ 3.10 ────────────────────────────────────────────────────────
head_ "Python"
PY=$(command -v python3 || true)
if [[ -z "$PY" ]]; then
  warn "python3 not found — installing"
  $SUDO apt-get update -qq && $SUDO apt-get install -y python3 || true
  PY=$(command -v python3 || true)
fi
if [[ -z "$PY" ]]; then
  bad "python3 could not be installed — install it and re-run"
  exit 1
fi
PYV=$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)'; then
  bad "python 3.10+ required, found $PYV"
  exit 1
fi
ok "python $PYV"

# Sanity: the package must import from this checkout before we wire a launcher
# to it. Run from / so the current directory can't mask a real problem.
if ! ( cd / && PYTHONPATH="$REPO" "$PY" -c 'import vision.cli' 2>/dev/null ); then
  bad "this checkout is incomplete — vision/ did not import from $REPO"
  exit 1
fi
ok "vision package imports cleanly"

# ── 2. launcher on PATH ──────────────────────────────────────────────────────
head_ "Installing Vision"
LAUNCHER=/usr/local/bin/vision
TMP=$(mktemp)
cat > "$TMP" <<EOF
#!/usr/bin/env bash
# Vision launcher (installed by setup.sh). Runs the checkout at:
#   $REPO
# with the system python3. Zero dependencies, so no venv or pip is involved.
# If you move or delete that folder, re-run its setup.sh.
exec env PYTHONPATH="$REPO\${PYTHONPATH:+:\$PYTHONPATH}" python3 -m vision "\$@"
EOF
if $SUDO install -m 0755 "$TMP" "$LAUNCHER" 2>/dev/null; then
  rm -f "$TMP"
  ok "installed  $LAUNCHER"
else
  rm -f "$TMP"
  bad "could not write $LAUNCHER — re-run with sudo"
  exit 1
fi

# Make the just-installed launcher findable for the rest of this script: put its
# directory on PATH and drop any cached "not found" lookup. Without this, a bare
# `vision` below can fail even though the file is right there.
export PATH="$(dirname "$LAUNCHER"):$PATH"
hash -r 2>/dev/null || true

# ── 3. verify it runs from anywhere ──────────────────────────────────────────
# Call it by absolute path so the check can't fail on a PATH/caching quirk.
if VER=$(cd / && "$LAUNCHER" --version 2>&1); then
  ok "$VER"
else
  bad "vision installed but not runnable:"
  printf '%s\n' "$VER" | sed 's/^/      /'
  exit 1
fi

if [[ $MINIMAL -eq 1 ]]; then
  head_ "Done"
  info "run:  vision doctor   then   sudo vision"
  exit 0
fi

# ── 4. toolchain (opt-in — the metapackages are large) ───────────────────────
if [[ $WITH_TOOLS -eq 1 ]]; then
  head_ "Security toolchain"
  info "installing missing tools — this can take 10–30 minutes"
  # `yes` answers vision setup's install prompt non-interactively.
  yes | $SUDO vision setup --need standard || warn "some tools failed — see: vision doctor"
fi

# ── 5. Metasploit database + module index ────────────────────────────────────
# The exploit advisory needs an offline module index; without it the advisory
# reads as "no exploits exist" rather than "not built yet".
head_ "Metasploit module index"
if command -v msfconsole >/dev/null 2>&1; then
  command -v msfdb >/dev/null 2>&1 && $SUDO msfdb init >/dev/null 2>&1 || true
  if vision index >/dev/null 2>&1; then
    ok "module index built"
  else
    warn "could not build the index now — run later with:  vision index"
  fi
else
  info "metasploit not installed — skip (install with: ${ACC}sudo ./setup.sh --tools${OFF})"
fi

# ── 6. readiness ─────────────────────────────────────────────────────────────
head_ "Readiness"
vision doctor --no-banner 2>/dev/null || true

head_ "Ready"
info "start a scan:   ${ACC}sudo vision${OFF}                 (interactive console)"
info "or scripted:    ${ACC}sudo vision run --scope 192.168.56.0/24 --rfc1918-only${OFF}"
[[ $WITH_TOOLS -eq 0 ]] && info "missing tools?  ${ACC}sudo ./setup.sh --tools${OFF}   (installs the Kali toolchain)"
printf '\n'
