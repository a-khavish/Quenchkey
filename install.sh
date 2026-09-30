#!/usr/bin/env bash
#
# Quenchkey installer.
#
#   ./install.sh                 install for everyone, into /usr/local
#   ./install.sh --user          install for you only, into ~/.local
#   ./install.sh --no-deps       skip the package manager step
#   ./install.sh --uninstall     remove it again
#
# Quenchkey runs from a virtual environment of its own, so it never touches the
# distribution's Python packages and cannot be broken by them. The only things
# asked of the package manager are the X11 libraries Qt needs, which any
# desktop already has.

set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE=install
SCOPE=system
WITH_DEPS=1
PYTHON_BIN="${QUENCHKEY_PYTHON:-}"

RED=$'\033[31m'; GREEN=$'\033[32m'; AMBER=$'\033[33m'
BLUE=$'\033[36m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; OFF=$'\033[0m'
say()  { printf '%s\n' "$*"; }
step() { printf '\n%s==>%s %s\n' "$AMBER" "$OFF" "$*"; }
ok()   { printf '%s  ok%s  %s\n' "$GREEN" "$OFF" "$*"; }
warn() { printf '%s  !%s   %s\n' "$AMBER" "$OFF" "$*"; }
die()  { printf '%s  x%s   %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --user)      SCOPE=user ;;
    --no-deps)   WITH_DEPS=0 ;;
    --uninstall) MODE=uninstall ;;
    --python)    PYTHON_BIN="$2"; shift ;;
    -h|--help)   sed -n '3,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)           die "Unknown option: $1" ;;
  esac
  shift
done

[ "$(uname -s)" = "Linux" ] || die "Quenchkey's interface is Linux only for now."
[ "$(id -u)" -ne 0 ] || die "Run this as your normal user. It asks for sudo when it needs to."

if [ "$SCOPE" = "user" ]; then
  PREFIX="$HOME/.local"
  SUDO=""
else
  PREFIX="/usr/local"
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else
    die "sudo is not available. Use ./install.sh --user instead."
  fi
fi

ICON_SIZES="16 32 64 256"
LIB_DIR="$PREFIX/lib/quenchkey"
VENV="$LIB_DIR/venv"
BIN="$PREFIX/bin/quenchkey"
RECOVER_BIN="$PREFIX/bin/quenchkey-recover"
DESKTOP="$PREFIX/share/applications/quenchkey.desktop"
ICON_SVG="$PREFIX/share/icons/hicolor/scalable/apps/quenchkey.svg"
MIME_XML="$PREFIX/share/mime/packages/quenchkey.xml"

refresh_caches() {
  command -v update-desktop-database >/dev/null 2>&1 &&
    $SUDO update-desktop-database "$PREFIX/share/applications" 2>/dev/null || true
  command -v gtk-update-icon-cache >/dev/null 2>&1 &&
    $SUDO gtk-update-icon-cache -f -t "$PREFIX/share/icons/hicolor" 2>/dev/null || true
  command -v update-mime-database >/dev/null 2>&1 &&
    $SUDO update-mime-database "$PREFIX/share/mime" 2>/dev/null || true
}

# ---------------------------------------------------------------- uninstall

# Where an installation could be. Checked in turn, so "--uninstall" on its own
# finds whichever one exists rather than making you remember which scope you
# chose months ago. Requiring --user to match the original install would mean
# uninstalling was not really one command.
PREFIXES_TO_CHECK="$HOME/.local /usr/local"

remove_from() {
  local prefix="$1" sudo_cmd="$2"
  local lib="$prefix/lib/quenchkey"

  # Stop the timer before the binary it runs disappears, or every fifteen
  # minutes systemd logs a failure for a command that is no longer there.
  if command -v systemctl >/dev/null 2>&1; then
    systemctl --user disable --now quenchkey-sweep.timer 2>/dev/null || true
  fi
  $sudo_cmd rm -f "$HOME/.config/systemd/user/quenchkey-sweep.service" \
                  "$HOME/.config/systemd/user/quenchkey-sweep.timer" \
                  "$prefix/lib/systemd/user/quenchkey-sweep.service" \
                  "$prefix/lib/systemd/user/quenchkey-sweep.timer"
  command -v systemctl >/dev/null 2>&1 &&
    systemctl --user daemon-reload 2>/dev/null || true

  $sudo_cmd rm -rf "$lib"
  $sudo_cmd rm -f "$prefix/bin/quenchkey" \
                  "$prefix/bin/quenchkey-recover" \
                  "$prefix/share/applications/quenchkey.desktop" \
                  "$prefix/share/icons/hicolor/scalable/apps/quenchkey.svg" \
                  "$prefix/share/mime/packages/quenchkey.xml"
  for size in $ICON_SIZES; do
    $sudo_cmd rm -f "$prefix/share/icons/hicolor/${size}x${size}/apps/quenchkey.png"
  done
  command -v update-desktop-database >/dev/null 2>&1 &&
    $sudo_cmd update-desktop-database "$prefix/share/applications" 2>/dev/null || true
  command -v gtk-update-icon-cache >/dev/null 2>&1 &&
    $sudo_cmd gtk-update-icon-cache -f -t "$prefix/share/icons/hicolor" 2>/dev/null || true
  command -v update-mime-database >/dev/null 2>&1 &&
    $sudo_cmd update-mime-database "$prefix/share/mime" 2>/dev/null || true
}

if [ "$MODE" = "uninstall" ]; then
  step "Removing Quenchkey"
  removed=0
  for prefix in $PREFIXES_TO_CHECK; do
    if [ -e "$prefix/lib/quenchkey" ] || [ -e "$prefix/bin/quenchkey" ]; then
      if [ -w "$prefix" ] || [ "$prefix" = "$HOME/.local" ]; then
        this_sudo=""
      elif command -v sudo >/dev/null 2>&1; then
        this_sudo="sudo"
        say "${DIM}$prefix needs root; sudo will ask for your password.${OFF}"
      else
        warn "Found an installation in $prefix but cannot remove it without sudo."
        continue
      fi
      remove_from "$prefix" "$this_sudo"
      ok "Removed from $prefix"
      removed=$((removed + 1))
    fi
  done

  if [ "$removed" -eq 0 ]; then
    warn "No installation found in: $PREFIXES_TO_CHECK"
    say  "${DIM}Nothing to do.${OFF}"
    exit 0
  fi

  say ""
  say "${BOLD}Your vault was left alone.${OFF} It is still at ~/.quenchkey, and so are"
  say "any .qkey files you locked. Removing the application does not destroy"
  say "a single key — that only ever happens on a deadline you set, or when you"
  say "ask for it."
  say ""
  say "${DIM}To remove the vault as well — which makes every .qkey file you${OFF}"
  say "${DIM}locked permanently unreadable — delete ~/.quenchkey yourself.${OFF}"
  exit 0
fi

# ------------------------------------------------------------------ deps

detect_manager() {
  for candidate in apt-get dnf pacman zypper apk; do
    command -v "$candidate" >/dev/null 2>&1 && { echo "$candidate"; return; }
  done
  echo ""
}

pkg_exists() {
  case "$1" in
    apt-get) case "$(apt-cache policy "$2" 2>/dev/null)" in
               *"Candidate: (none)"*) return 1 ;;
               *"Candidate: "*)       return 0 ;;
               *)                     return 1 ;;
             esac ;;
    dnf)     $SUDO dnf -q list --available "$2" >/dev/null 2>&1 ||
             $SUDO dnf -q list --installed "$2" >/dev/null 2>&1 ;;
    pacman)  pacman -Si "$2" >/dev/null 2>&1 || pacman -Qi "$2" >/dev/null 2>&1 ;;
    zypper)  case "$(zypper --non-interactive info "$2" 2>/dev/null)" in
               *"Name"*) return 0 ;; *) return 1 ;; esac ;;
    apk)     apk search -e "$2" 2>/dev/null | grep -q . ;;
    *)       return 1 ;;
  esac
}

pkg_filter() {
  local manager="$1"; shift
  local found=""
  for candidate in "$@"; do
    pkg_exists "$manager" "$candidate" && found="$found $candidate"
  done
  printf '%s' "${found# }"
}

pkg_install() {
  local manager="$1"; shift
  [ "$#" -eq 0 ] && return 0
  case "$manager" in
    apt-get) $SUDO apt-get install -y "$@" ;;
    dnf)     $SUDO dnf install -y "$@" ;;
    pacman)  $SUDO pacman -S --needed --noconfirm "$@" ;;
    zypper)  $SUDO zypper install -y "$@" ;;
    apk)     $SUDO apk add "$@" ;;
    *)       return 1 ;;
  esac
}

install_deps() {
  local manager packages found
  manager="$(detect_manager)"
  case "$manager" in
    apt-get)
      packages="python3 python3-venv python3-pip libgl1 libegl1 libdbus-1-3
                libfontconfig1 libxkbcommon-x11-0 libxcb-xinerama0 libxcb-icccm4
                libxcb-image0 libxcb-keysyms1 libxcb-randr0 libxcb-render-util0
                libxcb-shape0 libxcb-cursor0"
      $SUDO apt-get update || warn "apt could not refresh its package list"
      ;;
    dnf)
      packages="python3 python3-pip mesa-libGL libxkbcommon-x11 dbus-libs
                fontconfig xcb-util-wm xcb-util-image xcb-util-keysyms
                xcb-util-renderutil xcb-util-cursor"
      ;;
    pacman)
      packages="python python-pip libglvnd libxkbcommon-x11 dbus fontconfig
                xcb-util-wm xcb-util-image xcb-util-keysyms xcb-util-renderutil
                xcb-util-cursor"
      ;;
    zypper)
      packages="python3 python3-pip Mesa-libGL1 libxkbcommon-x11-0 dbus-1
                fontconfig xcb-util-wm xcb-util-image xcb-util-keysyms
                xcb-util-renderutil"
      ;;
    apk)
      packages="python3 py3-pip mesa-gl libxkbcommon dbus-libs fontconfig"
      ;;
    *)
      warn "No apt, dnf, pacman, zypper or apk here, so these are up to you:"
      say "    python3 with venv, and the X11 libraries Qt needs"
      say "    (libGL, libxcb-*, libxkbcommon-x11, fontconfig, dbus)"
      return
      ;;
  esac

  found="$(pkg_filter "$manager" $packages)"
  if [ -n "$found" ] && pkg_install "$manager" $found; then
    ok "System libraries installed with $manager"
  else
    warn "Some libraries would not install. If Quenchkey starts and complains"
    warn "about the \"xcb\" platform plugin, that is what is missing."
  fi
}

# ------------------------------------------------------------------ install

say ""
say "${BOLD}${BLUE}Quenchkey${OFF} — data with a lifespan"
say "${DIM}Installing into $PREFIX${OFF}"

# Two copies on PATH is a confusing state to end up in by accident.
for other in "$HOME/.local" /usr/local; do
  [ "$other" = "$PREFIX" ] && continue
  if [ -e "$other/bin/quenchkey" ]; then
    warn "Quenchkey is already installed in $other."
    say  "${DIM}      Installing here as well leaves two copies on your PATH.${OFF}"
    say  "${DIM}      Run ./install.sh --uninstall first if you did not mean to.${OFF}"
  fi
done

if [ "$WITH_DEPS" -eq 1 ]; then
  step "Installing system libraries"
  install_deps
else
  step "Skipping system libraries, as asked"
fi

step "Choosing a Python"
if [ -z "$PYTHON_BIN" ]; then
  for candidate in python3 python3.13 python3.12 python3.11 python3.10 python3.9; do
    resolved="$(command -v "$candidate" 2>/dev/null || true)"
    [ -n "$resolved" ] || continue
    if "$resolved" -c 'import sys; raise SystemExit(sys.version_info < (3, 9))'; then
      PYTHON_BIN="$resolved"; break
    fi
  done
fi
[ -n "$PYTHON_BIN" ] || die "No Python 3.9 or newer found."
"$PYTHON_BIN" -c "import venv" 2>/dev/null ||
  die "$PYTHON_BIN cannot create virtual environments. Install python3-venv and try again."
ok "$PYTHON_BIN ($("$PYTHON_BIN" -c 'import platform; print(platform.python_version())'))"

step "Building the application"
WHEEL_DIR="$(mktemp -d)"
trap 'rm -rf "$WHEEL_DIR"' EXIT
if ! "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
  die "pip is not available for $PYTHON_BIN. Install python3-pip and try again."
fi
ok "Sources ready"

step "Creating a private environment"
$SUDO rm -rf "$LIB_DIR"
$SUDO mkdir -p "$LIB_DIR"
$SUDO "$PYTHON_BIN" -m venv "$VENV" ||
  die "Could not create the virtual environment at $VENV"
ok "$VENV"

step "Installing Quenchkey and its libraries"
say "${DIM}This downloads about 70 MB the first time, mostly Qt.${OFF}"
$SUDO "$VENV/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
$SUDO "$VENV/bin/python" -m pip install --quiet "$SOURCE_DIR" ||
  die "Installation failed. Run it again without --quiet to see why:
       $SUDO $VENV/bin/python -m pip install '$SOURCE_DIR'"
ok "Installed"

step "Putting it on your PATH"
$SUDO mkdir -p "$PREFIX/bin"
$SUDO tee "$BIN" >/dev/null <<WRAPPER
#!/bin/sh
# Quenchkey launcher. The application lives in its own virtual environment so it
# cannot be disturbed by, or disturb, the system's Python packages.
exec "$VENV/bin/quenchkey" "\$@"
WRAPPER
$SUDO chmod 0755 "$BIN"

$SUDO tee "$RECOVER_BIN" >/dev/null <<WRAPPER
#!/bin/sh
# The standalone decryptor. It imports nothing from the Quenchkey package and
# needs only cryptography and argon2-cffi, both of which are in this
# environment already — so it keeps working even if the application does not.
exec "$VENV/bin/python" "$LIB_DIR/quenchkey-recover.py" "\$@"
WRAPPER
$SUDO chmod 0755 "$RECOVER_BIN"
$SUDO cp "$SOURCE_DIR/tools/quenchkey-recover.py" "$LIB_DIR/quenchkey-recover.py"
$SUDO chmod 0755 "$LIB_DIR/quenchkey-recover.py"
ok "quenchkey, quenchkey-recover"

step "Adding it to your applications menu"
$SUDO mkdir -p "$PREFIX/share/applications" \
               "$PREFIX/share/icons/hicolor/scalable/apps" \
               "$PREFIX/share/mime/packages"
$SUDO cp "$SOURCE_DIR/packaging/quenchkey.desktop" "$DESKTOP"
$SUDO cp "$SOURCE_DIR/packaging/quenchkey.svg" "$ICON_SVG"
$SUDO cp "$SOURCE_DIR/packaging/quenchkey-mime.xml" "$MIME_XML"
for size in $ICON_SIZES; do
  source_png="$SOURCE_DIR/assets/quenchkey-${size}.png"
  if [ -f "$source_png" ]; then
    $SUDO mkdir -p "$PREFIX/share/icons/hicolor/${size}x${size}/apps"
    $SUDO cp "$source_png" "$PREFIX/share/icons/hicolor/${size}x${size}/apps/quenchkey.png"
  fi
done
refresh_caches
ok "Menu entry, icons and the .qkey file type"

step "Setting up the expiry timer"
# A systemd user timer, so a locked file whose deadline passes is cleaned up
# without the application being open. It does nothing at all until background
# expiry is switched on for a vault from inside the application — which is
# deliberate, because switching it on writes an index of deadlines outside the
# vault. Installing the timer now just means no terminal is needed later.
UNIT_DIR="$HOME/.config/systemd/user"
if [ "$SCOPE" != "user" ]; then
  UNIT_DIR="$PREFIX/lib/systemd/user"
fi
if command -v systemctl >/dev/null 2>&1; then
  $SUDO mkdir -p "$UNIT_DIR"
  sed "s|__QUENCHKEY_BIN__|$BIN|" "$SOURCE_DIR/packaging/quenchkey-sweep.service"     | $SUDO tee "$UNIT_DIR/quenchkey-sweep.service" >/dev/null
  $SUDO cp "$SOURCE_DIR/packaging/quenchkey-sweep.timer" "$UNIT_DIR/quenchkey-sweep.timer"
  if systemctl --user daemon-reload 2>/dev/null \
     && systemctl --user enable --now quenchkey-sweep.timer 2>/dev/null; then
    ok "Timer running — it checks every 15 minutes, and does nothing until you switch on background expiry"
  else
    warn "Units installed, but systemd would not start them from here."
    say  "      Run this once you are logged in at the desktop:"
    say  "      systemctl --user enable --now quenchkey-sweep.timer"
  fi
else
  warn "No systemd here, so there is no background expiry timer."
  say  "      Deadlines are still enforced whenever the application is open."
fi

step "Checking it runs"
if "$BIN" --version >/dev/null 2>&1; then
  ok "$("$BIN" --version | head -1)"
else
  die "Quenchkey installed but will not start. Try: $BIN --version"
fi

# Quenchkey opens the desktop's own file chooser through the XDG portal, which
# needs a backend for whichever desktop this is. GNOME and KDE both ship one
# already, so this only ever has anything to say on a minimal install — and it
# says it rather than installing a backend, because pulling the GTK one onto a
# Plasma desktop would replace a file chooser that was working perfectly well.
step "Checking the desktop's file chooser"
portal_backend=""
for dir in "$HOME/.local/share" /usr/local/share /usr/share; do
  for impl in "$dir"/dbus-1/services/org.freedesktop.impl.portal.desktop.*.service; do
    [ -f "$impl" ] && portal_backend="${impl##*desktop.}" && portal_backend="${portal_backend%.service}"
  done
done
if [ -n "$portal_backend" ]; then
  ok "Using your desktop's own file chooser (portal backend: $portal_backend)"
else
  warn "No desktop portal backend found, so Quenchkey will draw its own file"
  warn "chooser instead of your desktop's. To get the real one, install the"
  warn "backend for your desktop — xdg-desktop-portal-gnome, -kde, or -gtk."
fi

case ":$PATH:" in
  *":$PREFIX/bin:"*) ;;
  *) warn "$PREFIX/bin is not on your PATH. Add this to ~/.profile:"
     say  "      export PATH=\"$PREFIX/bin:\$PATH\"" ;;
esac

say ""
say "${GREEN}${BOLD}Done.${OFF} Start it from your applications menu, or run ${BOLD}quenchkey${OFF}."
say ""
say "${DIM}First run creates a vault at ~/.quenchkey. There is no way to reset its${OFF}"
say "${DIM}passphrase, so write the one it generates down before you rely on it.${OFF}"
say "${DIM}To remove Quenchkey later:  ./install.sh --uninstall${OFF}"
say ""
