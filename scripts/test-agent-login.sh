#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  cat >&2 <<'EOF'
Usage:
  test-agent-login.sh <host> <username>

Example:
  test-agent-login.sh your-server.example.com your-user
EOF
  exit 1
fi

HOST="$1"
USER_NAME="$2"
SOCKET_PATH="${TOUCHID_AGENT_SOCKET:-$HOME/.ssh/touchid-agent.sock}"

exec ssh -vv -F /dev/null \
  -o IdentityAgent="$SOCKET_PATH" \
  -o PreferredAuthentications=publickey \
  -o KbdInteractiveAuthentication=no \
  "${USER_NAME}@${HOST}"
