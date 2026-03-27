#!/usr/bin/env bash
set -euo pipefail

SOCKET_PATH="${TOUCHID_AGENT_SOCKET:-$HOME/.ssh/touchid-agent.sock}"

if [[ -n "${1:-}" ]]; then
  RC_FILE="$1"
else
  case "${SHELL:-}" in
    */zsh) RC_FILE="$HOME/.zshrc" ;;
    */bash) RC_FILE="$HOME/.bashrc" ;;
    *) RC_FILE="$HOME/.zshrc" ;;
  esac
fi

mkdir -p "$(dirname "$RC_FILE")"
[[ -f "$RC_FILE" ]] || touch "$RC_FILE"

MARKER_BEGIN="# touchid-ssh-agent env"
MARKER_END="# /touchid-ssh-agent env"
BLOCK=$(cat <<BLOCK
$MARKER_BEGIN
export SSH_AUTH_SOCK="$SOCKET_PATH"
$MARKER_END
BLOCK
)

if rg -F "$MARKER_BEGIN" "$RC_FILE" >/dev/null 2>&1; then
  TMP_FILE="$(mktemp)"
  awk -v begin="$MARKER_BEGIN" -v end="$MARKER_END" -v block="$BLOCK" '
    $0 == begin { print block; inblock=1; next }
    $0 == end { inblock=0; next }
    !inblock { print }
  ' "$RC_FILE" > "$TMP_FILE"
  mv "$TMP_FILE" "$RC_FILE"
  echo "Updated SSH_AUTH_SOCK block in $RC_FILE"
else
  {
    echo
    echo "$BLOCK"
  } >> "$RC_FILE"
  echo "Added SSH_AUTH_SOCK block to $RC_FILE"
fi

echo "Current socket path: $SOCKET_PATH"
