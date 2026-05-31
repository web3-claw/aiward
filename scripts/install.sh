#!/usr/bin/env sh
# install.sh — installs ward and wires it into your shell PATH
# Usage: curl -sSfL https://raw.githubusercontent.com/aiWardsh/aiward/main/scripts/install.sh | sh

set -e

BINARY="ward"
PACKAGE="aiward"
CARGO_BIN="$HOME/.cargo/bin"

# ── helpers ────────────────────────────────────────────────────────────────────

info()  { printf "  \033[1;34m>\033[0m %s\n" "$*"; }
ok()    { printf "  \033[1;32m✓\033[0m %s\n" "$*"; }
warn()  { printf "  \033[1;33m!\033[0m %s\n" "$*"; }
die()   { printf "  \033[1;31m✗\033[0m %s\n" "$*" >&2; exit 1; }

# ── check cargo ────────────────────────────────────────────────────────────────

if ! command -v cargo >/dev/null 2>&1; then
  die "cargo not found. Install Rust first: https://rustup.rs"
fi

# ── install binary ─────────────────────────────────────────────────────────────

info "Installing $PACKAGE via cargo..."
cargo install "$PACKAGE" --quiet
ok "$BINARY installed to $CARGO_BIN/$BINARY"

# ── wire PATH ──────────────────────────────────────────────────────────────────

PATH_LINE="export PATH=\"\$HOME/.cargo/bin:\$PATH\""
PATH_COMMENT="# Added by ward installer"

add_to_file() {
  file="$1"
  if [ -f "$file" ]; then
    if grep -q '\.cargo/bin' "$file" 2>/dev/null; then
      ok "$file already contains .cargo/bin"
      return
    fi
    printf '\n%s\n%s\n' "$PATH_COMMENT" "$PATH_LINE" >> "$file"
    ok "Added .cargo/bin to $file"
  fi
}

# Detect shell and target the right profile
SHELL_NAME=$(basename "${SHELL:-sh}")

case "$SHELL_NAME" in
  zsh)
    add_to_file "$HOME/.zshrc"
    add_to_file "$HOME/.zprofile"
    RELOAD_CMD="source ~/.zshrc"
    ;;
  bash)
    add_to_file "$HOME/.bashrc"
    add_to_file "$HOME/.bash_profile"
    RELOAD_CMD="source ~/.bash_profile"
    ;;
  fish)
    FISH_CONFIG="$HOME/.config/fish/config.fish"
    mkdir -p "$(dirname "$FISH_CONFIG")"
    if [ -f "$FISH_CONFIG" ] && grep -q '\.cargo/bin' "$FISH_CONFIG" 2>/dev/null; then
      ok "$FISH_CONFIG already contains .cargo/bin"
    else
      printf '\n%s\nfish_add_path "%s"\n' "$PATH_COMMENT" "$CARGO_BIN" >> "$FISH_CONFIG"
      ok "Added .cargo/bin to $FISH_CONFIG"
    fi
    RELOAD_CMD="source ~/.config/fish/config.fish"
    ;;
  *)
    # Fallback: try common profile files
    add_to_file "$HOME/.profile"
    RELOAD_CMD="source ~/.profile"
    ;;
esac

# ── make available in current session ─────────────────────────────────────────

export PATH="$CARGO_BIN:$PATH"

# ── done ───────────────────────────────────────────────────────────────────────

printf "\n"
ok "ward $(ward --version 2>/dev/null | awk '{print $2}') is ready"
printf "\n"
info "ward is now available in this shell session."
info "To use it in new terminals, run:  $RELOAD_CMD"
info "  or open a new terminal window."
printf "\n"
info "Get started:"
printf "    cd your-project\n"
printf "    ward setup\n"
printf "\n"
