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
# Scoped helper setup: do not override regular SSH/Git agent globally.
export TOUCHID_AGENT_SOCKET="\${TOUCHID_AGENT_SOCKET:-$SOCKET_PATH}"

with_touchid_agent() {
  if [[ \$# -eq 0 ]]; then
    echo "usage: with_touchid_agent <command> [args...]" >&2
    return 1
  fi
  SSH_AUTH_SOCK="\${TOUCHID_AGENT_SOCKET}" "\$@"
}

touchid_ssh() {
  ssh -o IdentityAgent="\${TOUCHID_AGENT_SOCKET}" "\$@"
}

touchid_ssh_add() {
  SSH_AUTH_SOCK="\${TOUCHID_AGENT_SOCKET}" ssh-add "\$@"
}
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
  echo "Updated touchid helper block in $RC_FILE"
else
  {
    echo
    echo "$BLOCK"
  } >> "$RC_FILE"
  echo "Added touchid helper block to $RC_FILE"
fi

echo "Default Touch ID socket path: $SOCKET_PATH"
