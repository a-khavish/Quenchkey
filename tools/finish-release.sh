#!/usr/bin/env bash
#
# Finishes setting up the GitHub repository for Quenchkey 1.0.0.
#
# The code is already pushed. This does the parts that need your own GitHub
# credentials: the tag, the release, the repository description and topics.
#
# Run it once, from inside your clone of the repository:
#
#     bash tools/finish-release.sh
#
# It asks before anything that changes the repository, and it is safe to run
# again if a step fails halfway: every step checks whether it has already been
# done.
#
set -uo pipefail

OWNER="a-khavish"
REPO="Quenchkey"
TAG="v1.0.0"
SLUG="$OWNER/$REPO"

BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'
GREEN=$'\033[32m'; AMBER=$'\033[33m'; OFF=$'\033[0m'
if [ ! -t 1 ] || [ -n "${NO_COLOR:-}" ]; then
  BOLD=""; DIM=""; RED=""; GREEN=""; AMBER=""; OFF=""
fi

step()  { printf "\n%s==>%s %s\n" "$AMBER" "$OFF" "$1"; }
ok()    { printf "  %sok%s   %s\n" "$GREEN" "$OFF" "$1"; }
skip()  { printf "  %s--%s   %s\n" "$DIM" "$OFF" "$1"; }
warn()  { printf "  %s!%s    %s\n" "$AMBER" "$OFF" "$1"; }
die()   { printf "\n  %sstopped:%s %s\n\n" "$RED" "$OFF" "$1"; exit 1; }

ask() {
  # Returns 0 for yes, and defaults to yes on an empty answer. With nothing to
  # read from, it answers no: a script left running unattended should not start
  # changing a public repository on its own.
  local prompt="$1" reply
  printf "  %s [Y/n] " "$prompt"
  if [ -r /dev/tty ]; then
    read -r reply </dev/tty || { printf "\n"; return 1; }
  elif [ -t 0 ]; then
    read -r reply || { printf "\n"; return 1; }
  else
    printf "no terminal to ask at, skipping\n"
    return 1
  fi
  case "${reply,,}" in n|no) return 1 ;; *) return 0 ;; esac
}

# --------------------------------------------------------------------------
# before anything
# --------------------------------------------------------------------------

printf "%sQuenchkey 1.0.0 — finishing the GitHub setup%s\n" "$BOLD" "$OFF"
printf "%s%s%s\n" "$DIM" "https://github.com/$SLUG" "$OFF"

step "Checking what is here"

[ -f pyproject.toml ] && [ -d quenchkey ] \
  || die "run this from inside your clone of the repository, not from somewhere else"
ok "in the right directory"

command -v git >/dev/null || die "git is not installed"
ok "git"

if command -v gh >/dev/null; then
  if gh auth status >/dev/null 2>&1; then
    ok "gh, signed in"
    HAVE_GH=1
  else
    warn "gh is installed but not signed in. Run: gh auth login"
    HAVE_GH=0
  fi
else
  warn "gh is not installed. Install it from https://cli.github.com"
  warn "Without it this script can still push the tag; the rest needs it."
  HAVE_GH=0
fi

# --------------------------------------------------------------------------
# 1. the tag
# --------------------------------------------------------------------------

step "The $TAG tag"

if ! git rev-parse "$TAG" >/dev/null 2>&1; then
  warn "there is no $TAG tag in this clone"
  if ask "Create it on the current commit?"; then
    git tag -a "$TAG" -m "Quenchkey 1.0.0

First release. The key goes out." || die "could not create the tag"
    ok "created"
  else
    skip "no tag, so no release either"
  fi
fi

if git ls-remote --tags origin 2>/dev/null | grep -q "refs/tags/$TAG$"; then
  skip "already on GitHub"
else
  if ask "Push $TAG to GitHub?"; then
    git push origin "refs/tags/$TAG" || die "could not push the tag"
    ok "pushed"
  else
    skip "not pushed"
  fi
fi

# --------------------------------------------------------------------------
# 2. description, homepage, topics
# --------------------------------------------------------------------------

DESCRIPTION="Files that expire for real. The key is destroyed, not the file, so every copy stops opening at once."

TOPICS=(encryption cryptography file-encryption privacy security linux
        desktop-app python pyqt5 data-retention gdpr self-destructing
        argon2 chacha20-poly1305 aes-gcm expiring-files secure-file-sharing
        crypto-shredding)

step "Description and topics"

if [ "$HAVE_GH" = "1" ]; then
  CURRENT=$(gh api "repos/$SLUG" --jq '.description // ""' 2>/dev/null || echo "")
  if [ "$CURRENT" = "$DESCRIPTION" ]; then
    skip "description already set"
  else
    printf "    %s%s%s\n" "$DIM" "$DESCRIPTION" "$OFF"
    if ask "Set this as the repository description?"; then
      gh api -X PATCH "repos/$SLUG" \
        -f description="$DESCRIPTION" \
        -f homepage="https://github.com/$SLUG#readme" \
        >/dev/null && ok "description and homepage set" \
        || warn "could not set the description"
    else
      skip "left alone"
    fi
  fi

  printf "    %s%s%s\n" "$DIM" "${TOPICS[*]}" "$OFF"
  if ask "Set these topics? (they are how people find a repository)"; then
    ARGS=()
    for topic in "${TOPICS[@]}"; do ARGS+=(-f "names[]=$topic"); done
    gh api -X PUT "repos/$SLUG/topics" "${ARGS[@]}" >/dev/null \
      && ok "${#TOPICS[@]} topics set" || warn "could not set the topics"
  else
    skip "left alone"
  fi
else
  warn "needs gh. Set them by hand at:"
  printf "       https://github.com/%s  →  the gear icon beside About\n" "$SLUG"
  printf "\n    Description:\n      %s\n" "$DESCRIPTION"
  printf "\n    Topics:\n      %s\n" "${TOPICS[*]}"
fi

# --------------------------------------------------------------------------
# 3. the release
# --------------------------------------------------------------------------

step "The $TAG release"

if [ "$HAVE_GH" != "1" ]; then
  warn "needs gh. Create it by hand at:"
  printf "       https://github.com/%s/releases/new?tag=%s\n" "$SLUG" "$TAG"
elif gh release view "$TAG" --repo "$SLUG" >/dev/null 2>&1; then
  skip "already exists"
else
  NOTES=$(mktemp)
  cat > "$NOTES" <<'NOTES_END'
First release.

## What it does

Quenchkey locks files so that the encrypted file and its key live in different
places. When a file expires it is the **key** that is destroyed, not the file,
so every copy stops opening at the same moment — including copies on other
machines, in backups, and ones you have forgotten about.

## Getting it

```bash
git clone https://github.com/a-khavish/Quenchkey.git
cd Quenchkey
./install.sh --user
```

Linux only. The installer handles apt, dnf, pacman, zypper and apk, and puts
everything in your home folder. `./install.sh --uninstall` removes it and
leaves your vault alone.

## What's in it

- Four kinds of deadline: a date, an opening allowance, a check-in interval
  (a dead man's switch), or on demand. Warnings go out a week, a day and an
  hour before, so nothing fires unannounced.
- Signed certificates of destruction that verify with no passphrase and no
  vault, for when you need to prove a file was destroyed.
- A record for an auditor holding your retention policy and no file keys.
- Files that travel to somebody else's vault with the deadline attached, and
  files that open anywhere with a passphrase of their own.
- Vault backups that tell you what restoring one would undo before doing it.
- Loans: open a file to work on, and your edits go back in when you return it.
- A command line for scripting, where the vault passphrase can only come from
  a prompt.
- A standalone recovery tool that shares no code with the application, so your
  files open even if this project disappears.

## What it does not do

Stated in the application under *What this does not protect against*, and in
[SECURITY.md](https://github.com/a-khavish/Quenchkey/blob/main/SECURITY.md):
a file somebody has already opened cannot be recalled; a copy of the vault
taken before a deadline can be restored after it; files shared with a
passphrase can never expire; and your passphrase is the whole of the
protection, with no reset.

## Checking it

617 tests, every dialog checked at four text sizes on a small screen, and a
recorded walkthrough that drives the real program and fails if a button is
missing or a warning has disappeared from a dialog.

Nobody but the author has used this yet. If something is broken, please
[open an issue](https://github.com/a-khavish/Quenchkey/issues).
NOTES_END

  printf "    Release notes are ready. %s\n" "${DIM}They are in the notes file this script made.${OFF}"
  if ask "Create the $TAG release?"; then
    gh release create "$TAG" --repo "$SLUG" \
      --title "Quenchkey 1.0.0" --notes-file "$NOTES" --latest \
      && ok "release created" || warn "could not create the release"
  else
    skip "not created"
  fi
  rm -f "$NOTES"
fi

# --------------------------------------------------------------------------
# 4. a source archive on the release
# --------------------------------------------------------------------------

step "A downloadable archive"

printf "    %sGitHub attaches its own zip and tar.gz automatically. This adds one\n" "$DIM"
printf "    without the demo video, which is most of the size.%s\n" "$OFF"

if [ "$HAVE_GH" = "1" ] && gh release view "$TAG" --repo "$SLUG" >/dev/null 2>&1; then
  if gh release view "$TAG" --repo "$SLUG" --json assets \
       --jq '.assets[].name' 2>/dev/null | grep -q "quenchkey-1.0.0-slim"; then
    skip "already attached"
  elif ask "Build and attach a slim source archive?"; then
    ARCHIVE="/tmp/quenchkey-1.0.0-slim.tar.gz"
    tar --exclude='.git' --exclude='__pycache__' --exclude='.pytest_cache' \
        --exclude='.ruff_cache' --exclude='docs/demo' \
        -czf "$ARCHIVE" -C .. "$(basename "$PWD")" \
      && gh release upload "$TAG" "$ARCHIVE" --repo "$SLUG" \
      && ok "attached ($(du -h "$ARCHIVE" | cut -f1))" \
      || warn "could not attach the archive"
    rm -f "$ARCHIVE"
  else
    skip "not attached"
  fi
else
  skip "no release to attach it to"
fi

# --------------------------------------------------------------------------
# 5. optional extras
# --------------------------------------------------------------------------

step "Optional"

if [ "$HAVE_GH" = "1" ]; then
  if ask "Turn on Discussions? (somewhere for questions that are not bugs)"; then
    gh api -X PATCH "repos/$SLUG" -F has_discussions=true >/dev/null \
      && ok "Discussions on" || warn "could not turn Discussions on"
  else
    skip "Discussions left off"
  fi

  if ask "Turn on private vulnerability reporting? (recommended for this project)"; then
    gh api -X PUT "repos/$SLUG/private-vulnerability-reporting" >/dev/null 2>&1 \
      && ok "private reporting on" \
      || warn "could not turn it on; do it under Settings → Security"
  else
    skip "left off"
  fi
else
  printf "    Under Settings on GitHub, consider turning on:\n"
  printf "      - Discussions, for questions that are not bug reports\n"
  printf "      - Private vulnerability reporting, under Security\n"
fi

# --------------------------------------------------------------------------
# done
# --------------------------------------------------------------------------

printf "\n%sDone.%s\n\n" "$BOLD" "$OFF"
printf "  Repository   https://github.com/%s\n" "$SLUG"
printf "  Release      https://github.com/%s/releases/tag/%s\n" "$SLUG" "$TAG"
printf "\n"
printf "%sA few things worth doing by hand:%s\n" "$BOLD" "$OFF"
printf "  1. Look at the README on GitHub and check the video plays.\n"
printf "  2. Settings → General → Social preview: upload an image, so the link\n"
printf "     looks like something when you share it. assets/quenchkey-256.png\n"
printf "     works, though a wider one looks better.\n"
printf "  3. Watch the Actions tab on the first push: the tests and the install\n"
printf "     check run there, and a red mark on the front page is worth fixing\n"
printf "     before anybody sees it.\n"
printf "\n"
