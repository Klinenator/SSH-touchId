#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  test-agent-login.sh <user@host> [remote-command ...]
  test-agent-login.sh <host> <username> [remote-command ...]

Example:
  test-agent-login.sh your-user@your-server.example.com
  test-agent-login.sh your-server.example.com your-user
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 1
fi

if [[ "$1" == *"@"* ]]; then
  TARGET="$1"
  shift
elif [[ $# -ge 2 ]]; then
  HOST="$1"
  USER_NAME="$2"
  TARGET="${USER_NAME}@${HOST}"
  shift 2
else
  echo "error: expected <user@host> or <host> <username>" >&2
  usage >&2
  exit 1
fi

SOCKET_PATH="${TOUCHID_AGENT_SOCKET:-$HOME/.ssh/touchid-agent.sock}"

exec ssh -vv -F /dev/null \
  -o IdentityAgent="$SOCKET_PATH" \
  -o PreferredAuthentications=publickey \
  -o KbdInteractiveAuthentication=no \
  "$TARGET" "$@"
