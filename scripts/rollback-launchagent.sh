#!/usr/bin/env bash
set -euo pipefail

LABEL="com.touchidsshagent.agent"
DOMAIN="gui/$(id -u)"
SERVICE="$DOMAIN/$LABEL"
PLIST_PATH="$HOME/Library/LaunchAgents/${LABEL}.plist"
SOCKET_PATH="${TOUCHID_AGENT_SOCKET:-$HOME/.ssh/touchid-agent.sock}"

launchctl bootout "$SERVICE" 2>/dev/null || true
launchctl remove "$LABEL" 2>/dev/null || true

if [[ "${1:-}" == "--delete-plist" ]]; then
  rm -f "$PLIST_PATH"
  echo "Deleted plist: $PLIST_PATH"
fi

rm -f "$SOCKET_PATH"

echo "Stopped $LABEL"
echo "Removed socket: $SOCKET_PATH"
echo "Optional shell rollback: remove the touchid helper block from your shell rc file"
