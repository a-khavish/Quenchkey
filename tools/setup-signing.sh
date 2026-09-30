#!/usr/bin/env bash
#
# Sets up GPG commit signing, so commits show as Verified on GitHub.
#
#     bash tools/setup-signing.sh [path-to-your-key.asc]
#
# With no argument it looks for a key in ~/Downloads. Run it from inside your
# clone of the repository.
#
# Nothing here sends your key anywhere. The only thing that leaves your machine
# is the *public* half, which you paste into GitHub yourself at the end.
#
set -uo pipefail

BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'
GREEN=$'\033[32m'; AMBER=$'\033[33m'; OFF=$'\033[0m'
if [ ! -t 1 ] || [ -n "${NO_COLOR:-}" ]; then
  BOLD=""; DIM=""; RED=""; GREEN=""; AMBER=""; OFF=""
fi

step() { printf "\n%s==>%s %s\n" "$AMBER" "$OFF" "$1"; }
ok()   { printf "  %sok%s   %s\n" "$GREEN" "$OFF" "$1"; }
info() { printf "  %s--%s   %s\n" "$DIM" "$OFF" "$1"; }
warn() { printf "  %s!%s    %s\n" "$AMBER" "$OFF" "$1"; }
die()  { printf "\n  %sstopped:%s %s\n\n" "$RED" "$OFF" "$1"; exit 1; }

# A terminal to ask at, or nothing. /dev/tty can exist as a device node and
# still refuse to open, which is what happens inside most CI and container
# shells, so this tries to open it rather than trusting a test.
if { exec 3</dev/tty; } 2>/dev/null; then
  HAVE_TTY=1
elif [ -t 0 ]; then
  exec 3<&0
  HAVE_TTY=1
else
  HAVE_TTY=0
fi

ask() {
  local prompt="$1" reply
  if [ "$HAVE_TTY" != "1" ]; then
    printf "  %s %s[no terminal to ask at, skipping]%s\n" "$prompt" "$DIM" "$OFF"
    return 1
  fi
  printf "  %s [Y/n] " "$prompt"
  read -r reply <&3 || { printf "\n"; return 1; }
  case "${reply,,}" in n|no) return 1 ;; *) return 0 ;; esac
}

MATCHED=0

printf "%sSigning setup%s  %sso your commits show as Verified%s\n" \
  "$BOLD" "$OFF" "$DIM" "$OFF"

# --------------------------------------------------------------------------
# what we are working with
# --------------------------------------------------------------------------

step "Looking around"

command -v gpg >/dev/null || die "gpg is not installed.  sudo apt install gnupg"
ok "gpg $(gpg --version | head -1 | awk '{print $3}')"

command -v git >/dev/null || die "git is not installed"
git rev-parse --git-dir >/dev/null 2>&1 \
  || die "run this from inside a git repository"
ok "git repository"

KEYFILE="${1:-}"
if [ -z "$KEYFILE" ]; then
  for candidate in \
      "$HOME/Downloads"/*signing-key*.asc \
      "$HOME/Downloads"/*.private.asc \
      "$HOME/Downloads"/*.asc; do
    [ -f "$candidate" ] && { KEYFILE="$candidate"; break; }
  done
fi
[ -n "$KEYFILE" ] && [ -f "$KEYFILE" ] \
  || die "no key file found. Pass the path: bash $0 ~/Downloads/your-key.asc"
ok "key file: $KEYFILE"

COMMIT_EMAIL=$(git config user.email || true)
COMMIT_NAME=$(git config --get user.name || true)
[ -n "$COMMIT_EMAIL" ] || die "git has no user.email set in this repository"
info "commits are authored as: $COMMIT_NAME <$COMMIT_EMAIL>"

# --------------------------------------------------------------------------
# the key itself
# --------------------------------------------------------------------------

step "Importing the key"

count_secret_keys() {
  # grep -c prints 0 and exits 1 when it matches nothing, so the count is
  # taken from its output and the exit code ignored.
  gpg --list-secret-keys --with-colons 2>/dev/null | grep -c '^sec' || true
}

BEFORE=$(count_secret_keys)
gpg --import "$KEYFILE" 2>&1 | sed 's/^/       /'
AFTER=$(count_secret_keys)

if [ "${AFTER:-0}" -gt "${BEFORE:-0}" ] 2>/dev/null; then
  ok "imported"
else
  info "already in your keyring"
fi

# The newest secret key that can sign. Printed so you can check it is the one
# you meant before anything is configured to use it.
KEYID=$(gpg --list-secret-keys --keyid-format=long --with-colons 2>/dev/null \
  | awk -F: '/^sec/ {print $5}' | tail -1)
[ -n "$KEYID" ] || die "no secret key in your keyring after importing"

FPR=$(gpg --list-secret-keys --with-colons "$KEYID" 2>/dev/null \
  | awk -F: '/^fpr/ {print $10; exit}')

printf "\n"
gpg --list-secret-keys --keyid-format=long "$KEYID" 2>/dev/null | sed 's/^/       /'

EXPIRY=$(gpg --list-keys --with-colons "$KEYID" 2>/dev/null \
  | awk -F: '/^pub/ {print $7; exit}')
if [ -n "$EXPIRY" ] && [ "$EXPIRY" != "" ]; then
  NOW=$(date +%s)
  if [ "$EXPIRY" -lt "$NOW" ] 2>/dev/null; then
    warn "this key EXPIRED on $(date -d "@$EXPIRY" '+%Y-%m-%d' 2>/dev/null)"
    warn "GitHub will not show commits as Verified with an expired key."
    warn "Extend it:  gpg --edit-key $KEYID   then  expire   then  save"
  else
    ok "valid until $(date -d "@$EXPIRY" '+%Y-%m-%d' 2>/dev/null)"
  fi
else
  ok "no expiry date"
fi

# --------------------------------------------------------------------------
# the part that decides whether GitHub says Verified
# --------------------------------------------------------------------------

step "Does the key match your commits?"

printf "    %sGitHub shows Verified only when all three are true:%s\n" "$DIM" "$OFF"
printf "      1. the public key is uploaded to your GitHub account\n"
printf "      2. the commit's author email is one of the key's identities\n"
printf "      3. that email is confirmed on your GitHub account\n\n"

UIDS=$(gpg --list-keys --with-colons "$KEYID" 2>/dev/null \
  | awk -F: '/^uid/ {print $10}')
printf "    This key's identities:\n"
printf "%s\n" "$UIDS" | sed 's/^/      /'
printf "\n"

if printf "%s\n" "$UIDS" | grep -qiF "$COMMIT_EMAIL"; then
  ok "the key already covers $COMMIT_EMAIL"
  MATCHED=1
else
  warn "the key does NOT cover $COMMIT_EMAIL"
  MATCHED=0
  printf "\n    Two ways to fix it:\n\n"
  printf "    %sA.%s Add that address to the key (keeps your commit identity).\n" "$BOLD" "$OFF"
  printf "       This script can do it for you.\n\n"
  printf "    %sB.%s Change the repository to commit under an address the key\n" "$BOLD" "$OFF"
  printf "       already has, if that address is confirmed on your GitHub\n"
  printf "       account under Settings → Emails.\n\n"

  if ask "Do A — add $COMMIT_EMAIL to the key?"; then
    printf "\n    %sgpg will open. Type these, one per line:%s\n" "$DIM" "$OFF"
    printf "      adduid\n"
    printf "      %s            (real name)\n" "${COMMIT_NAME:-your name}"
    printf "      %s  (email)\n" "$COMMIT_EMAIL"
    printf "      %s            (comment: leave blank, press Enter)\n" ""
    printf "      O                     (to confirm)\n"
    printf "      trust  →  5  →  y     (so your own key is fully trusted)\n"
    printf "      save\n\n"
    if ask "Open gpg now?"; then
      gpg --edit-key "$KEYID" <&3
      UIDS=$(gpg --list-keys --with-colons "$KEYID" 2>/dev/null \
        | awk -F: '/^uid/ {print $10}')
      if printf "%s\n" "$UIDS" | grep -qiF "$COMMIT_EMAIL"; then
        ok "the key now covers $COMMIT_EMAIL"
        MATCHED=1
      else
        warn "still not there. Commits will sign, but show as Unverified."
      fi
    fi
  else
    info "left alone. Commits will sign, but GitHub will say Unverified"
    info "until the email on the key and the email on the commit agree."
  fi
fi

# --------------------------------------------------------------------------
# trust, so gpg stops warning at you locally
# --------------------------------------------------------------------------

step "Trusting your own key"

TRUST=$(gpg --list-keys --with-colons "$KEYID" 2>/dev/null \
  | awk -F: '/^pub/ {print $2; exit}')
if [ "$TRUST" = "u" ]; then
  info "already fully trusted"
else
  if ask "Mark this key as ultimately trusted? (it is yours)"; then
    printf "%s:6:\n" "$FPR" | gpg --import-ownertrust 2>/dev/null \
      && ok "trusted" || warn "could not set the trust level"
  else
    info "skipped; git log --show-signature will warn, harmlessly"
  fi
fi

# --------------------------------------------------------------------------
# tell git to use it
# --------------------------------------------------------------------------

step "Configuring git"

# If SSH signing was ever set up, gpg.format is "ssh" and git quietly ignores
# the GPG key, signs with ssh instead, and reports a confusing error. Setting
# the format explicitly is the difference between this working and appearing
# to work.
EXISTING_FORMAT=$(git config --get gpg.format 2>/dev/null || true)
if [ -n "$EXISTING_FORMAT" ] && [ "$EXISTING_FORMAT" != "openpgp" ]; then
  warn "git is currently set up for $EXISTING_FORMAT signing, not GPG."
  info "that will be switched to openpgp for this key to be used"
fi

if ask "Sign commits and tags in THIS repository with $KEYID?"; then
  git config gpg.format openpgp
  git config user.signingkey "$KEYID"
  git config commit.gpgsign true
  git config tag.gpgsign true
  git config gpg.program "$(command -v gpg)"
  ok "this repository will sign from now on"

  if ask "Do the same globally, for every repository?"; then
    git config --global gpg.format openpgp
    git config --global user.signingkey "$KEYID"
    git config --global commit.gpgsign true
    git config --global tag.gpgsign true
    git config --global gpg.program "$(command -v gpg)"
    ok "set globally"
  else
    info "only this repository"
  fi
else
  die "nothing configured"
fi

# gpg needs to know which terminal to ask for the passphrase on.
if ! grep -q "GPG_TTY" "$HOME/.bashrc" 2>/dev/null \
   && ! grep -q "GPG_TTY" "$HOME/.zshrc" 2>/dev/null; then
  printf "\n"
  warn "gpg needs GPG_TTY set, or signing fails in some terminals."
  if ask "Add 'export GPG_TTY=\$(tty)' to your shell startup file?"; then
    SHELLRC="$HOME/.bashrc"
    [ -n "${ZSH_VERSION:-}" ] || [ "$(basename "${SHELL:-}")" = "zsh" ] \
      && SHELLRC="$HOME/.zshrc"
    printf '\n# Let gpg find the terminal to ask for a passphrase on\nexport GPG_TTY=$(tty)\n' \
      >> "$SHELLRC"
    export GPG_TTY=$(tty)
    ok "added to $SHELLRC (and set for this session)"
  fi
else
  ok "GPG_TTY already set up"
fi

# --------------------------------------------------------------------------
# prove it works
# --------------------------------------------------------------------------

step "Testing a signature"

if echo test | gpg --local-user "$KEYID" --clearsign >/dev/null 2>&1; then
  ok "the key signs"
else
  warn "signing failed. Usually GPG_TTY, or a wrong passphrase."
  warn "Try it by hand:  echo test | gpg --clearsign"
fi

# --------------------------------------------------------------------------
# the public half, for GitHub
# --------------------------------------------------------------------------

step "The public key, for GitHub"

PUBOUT="$HOME/quenchkey-signing-key.public.asc"
gpg --armor --export "$KEYID" > "$PUBOUT" \
  && ok "written to $PUBOUT" || warn "could not export the public key"

printf "\n    %sPaste the whole file, including the BEGIN and END lines, at:%s\n" "$DIM" "$OFF"
printf "      https://github.com/settings/gpg/new\n\n"

if command -v gh >/dev/null && gh auth status >/dev/null 2>&1; then
  if ask "Upload it with gh instead?"; then
    gh gpg-key add "$PUBOUT" && ok "uploaded to your GitHub account" \
      || warn "could not upload; paste it at the link above"
  fi
elif command -v xclip >/dev/null; then
  if ask "Copy it to the clipboard?"; then
    xclip -selection clipboard < "$PUBOUT" && ok "copied"
  fi
fi

# --------------------------------------------------------------------------
# re-sign what is already there
# --------------------------------------------------------------------------

step "The commit that is already pushed"

if git log -1 --format='%G?' 2>/dev/null | grep -qE '^[GU]$'; then
  info "the last commit is already signed"
else
  printf "    %sYour existing commit was made before signing was on, so it is\n" "$DIM"
  printf "    unsigned. Re-signing it changes its ID, which means a force push.\n"
  printf "    On a repository with one commit and no collaborators, that is fine.%s\n\n" "$OFF"
  if ask "Re-sign the last commit and force-push it?"; then
    git commit --amend --no-edit -S || die "could not re-sign the commit"
    ok "re-signed as $(git rev-parse --short HEAD)"

    if git rev-parse v1.0.0 >/dev/null 2>&1; then
      git tag -d v1.0.0 >/dev/null 2>&1
      git tag -s v1.0.0 -m "Quenchkey 1.0.0

First release. The key goes out." && ok "tag re-made, signed"
    fi

    if ask "Push now? (force, because the commit ID changed)"; then
      git push --force-with-lease origin HEAD && ok "pushed"
      git rev-parse v1.0.0 >/dev/null 2>&1 \
        && git push --force origin refs/tags/v1.0.0 && ok "tag pushed"
    else
      info "push it yourself:  git push --force-with-lease origin main"
    fi
  fi
fi

# --------------------------------------------------------------------------
# tidy up
# --------------------------------------------------------------------------

step "The key file in Downloads"

printf "    %s%s%s\n" "$DIM" "$KEYFILE" "$OFF"
printf "    That is your %sprivate%s key sitting in a folder every browser\n" "$BOLD" "$OFF"
printf "    download lands in. It is now imported into gpg, so the file itself\n"
printf "    is no longer needed day to day.\n\n"

if ask "Move it somewhere safer (~/.gnupg-backup, readable only by you)?"; then
  mkdir -p "$HOME/.gnupg-backup" && chmod 700 "$HOME/.gnupg-backup"
  mv "$KEYFILE" "$HOME/.gnupg-backup/" \
    && chmod 600 "$HOME/.gnupg-backup/$(basename "$KEYFILE")" \
    && ok "moved to ~/.gnupg-backup/" || warn "could not move it"
  warn "That is still the only copy of a key you cannot regenerate."
  warn "Keep a second copy somewhere offline."
else
  chmod 600 "$KEYFILE" 2>/dev/null \
    && info "left where it is, now readable only by you"
fi

# --------------------------------------------------------------------------
# done
# --------------------------------------------------------------------------

printf "\n%sDone.%s\n\n" "$BOLD" "$OFF"
printf "  Signing with   %s\n" "$KEYID"
printf "  Public key     %s\n" "$PUBOUT"
printf "  Upload it at   https://github.com/settings/gpg/new\n\n"

if [ "$MATCHED" != "1" ]; then
  printf "  %sOne thing left:%s the key does not list %s,\n" "$AMBER" "$OFF" "$COMMIT_EMAIL"
  printf "  so GitHub will show your commits as Unverified until it does.\n"
  printf "  Run this script again and choose option A, or add the address by\n"
  printf "  hand with:  gpg --edit-key %s  then  adduid\n\n" "$KEYID"
fi

printf "  %sCheck it worked:%s\n" "$BOLD" "$OFF"
printf "    git log --show-signature -1        %s(locally)%s\n" "$DIM" "$OFF"
printf "    https://github.com/a-khavish/Quenchkey/commits/main   %s(the badge)%s\n" "$DIM" "$OFF"
printf "\n"
printf "  %sIf you would rather not deal with GPG at all:%s GitHub also accepts\n" "$DIM" "$OFF"
printf "  %sSSH signing, which reuses the key you already push with.%s\n" "$DIM" "$OFF"
printf "    git config --global gpg.format ssh\n"
printf "    git config --global user.signingkey ~/.ssh/id_ed25519.pub\n"
printf "    git config --global commit.gpgsign true\n"
printf "  %sThen add the same public key again at github.com/settings/keys,%s\n" "$DIM" "$OFF"
printf "  %schoosing \"Signing Key\" rather than \"Authentication Key\".%s\n" "$DIM" "$OFF"
printf "\n"
