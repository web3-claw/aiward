#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN_DIR="${ENVGATE_INSTALL_BIN_DIR:-$HOME/.local/bin}"
TARGET="$BIN_DIR/envgate"
REPO="${ENVGATE_GITHUB_REPO:-}"
VERSION="${ENVGATE_VERSION:-latest}"

detect_target() {
  os=$(uname -s)
  arch=$(uname -m)
  case "$os:$arch" in
    Darwin:arm64) echo "aarch64-apple-darwin" ;;
    Darwin:x86_64) echo "x86_64-apple-darwin" ;;
    Linux:x86_64) echo "x86_64-unknown-linux-gnu" ;;
    *) echo "unsupported" ;;
  esac
}

release_url() {
  target_triple=$1
  asset="envgate-$target_triple.tar.gz"
  if [ "$VERSION" = "latest" ]; then
    echo "https://github.com/$REPO/releases/latest/download/$asset"
  else
    echo "https://github.com/$REPO/releases/download/$VERSION/$asset"
  fi
}

if [ "${ENVGATE_INSTALL_DRY_RUN:-0}" = "1" ]; then
  echo "Would install EnvGate to $TARGET"
  if [ -n "$REPO" ] && [ "${ENVGATE_FORCE_LOCAL_BUILD:-0}" != "1" ]; then
    target_triple=$(detect_target)
    echo "Would download EnvGate release $(release_url "$target_triple")"
  else
    echo "Would build EnvGate locally with Cargo"
  fi
else
  mkdir -p "$BIN_DIR"
  if [ -n "$REPO" ] && [ "${ENVGATE_FORCE_LOCAL_BUILD:-0}" != "1" ]; then
    target_triple=$(detect_target)
    if [ "$target_triple" = "unsupported" ]; then
      echo "Unsupported platform for release download; set ENVGATE_FORCE_LOCAL_BUILD=1 to build with Cargo." >&2
      exit 1
    fi
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT INT TERM
    curl -fsSL "$(release_url "$target_triple")" -o "$tmp_dir/envgate.tar.gz"
    tar -xzf "$tmp_dir/envgate.tar.gz" -C "$tmp_dir"
    cp "$tmp_dir/envgate" "$TARGET"
  else
    cargo build --release --manifest-path "$ROOT_DIR/Cargo.toml"
    cp "$ROOT_DIR/target/release/envgate" "$TARGET"
  fi
  chmod +x "$TARGET"
  echo "Installed EnvGate to $TARGET"
fi

case ":$PATH:" in
  *":$BIN_DIR:"*) echo "envgate is on PATH." ;;
  *) echo "Add EnvGate to PATH: export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac
