#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

LABEL="com.touchidsshagent.agent"
TEMPLATE_PATH="$PROJECT_ROOT/launchd/${LABEL}.plist.template"
PLIST_PATH="$HOME/Library/LaunchAgents/${LABEL}.plist"
BINARY_PATH="${TOUCHID_AGENT_BINARY:-$PROJECT_ROOT/.build/debug/touchid-ssh-agent}"
SOCKET_PATH="${TOUCHID_AGENT_SOCKET:-$HOME/.ssh/touchid-agent.sock}"
REASON="${TOUCHID_AGENT_REASON:-Authorize SSH signature}"
KEY_ID="${TOUCHID_AGENT_KEY_ID:-}"

if [[ ! -f "$TEMPLATE_PATH" ]]; then
  echo "error: missing template at $TEMPLATE_PATH" >&2
  exit 1
fi

if [[ ! -x "$BINARY_PATH" ]]; then
  echo "Building touchid-ssh-agent..."
  swift build --product touchid-ssh-agent --package-path "$PROJECT_ROOT"
fi

mkdir -p "$HOME/Library/LaunchAgents" "$HOME/Library/Logs" "$(dirname "$SOCKET_PATH")"

python3 - <<'PY' "$TEMPLATE_PATH" "$PLIST_PATH" "$BINARY_PATH" "$SOCKET_PATH" "$REASON" "$HOME" "$KEY_ID"
import pathlib
import sys

template_path = pathlib.Path(sys.argv[1])
plist_path = pathlib.Path(sys.argv[2])
binary_path = sys.argv[3]
socket_path = sys.argv[4]
reason = sys.argv[5]
home = sys.argv[6]
key_id = sys.argv[7]

text = template_path.read_text()
text = text.replace("__BINARY_PATH__", binary_path)
text = text.replace("__SOCKET_PATH__", socket_path)
text = text.replace("__REASON__", reason)
text = text.replace("__HOME__", home)
text = text.replace("__KEY_ID__", key_id)
plist_path.write_text(text)
PY

DOMAIN="gui/$(id -u)"
SERVICE="$DOMAIN/$LABEL"

launchctl bootout "$SERVICE" 2>/dev/null || true
launchctl bootstrap "$DOMAIN" "$PLIST_PATH"
launchctl kickstart -k "$SERVICE"

echo
echo "Installed and started $LABEL"
echo "LaunchAgent plist: $PLIST_PATH"
echo "Agent binary:      $BINARY_PATH"
echo "Agent socket:      $SOCKET_PATH"
if [[ -n "$KEY_ID" ]]; then
  echo "Pinned key id:     $KEY_ID"
fi
echo
echo "Recommended (scoped; does not override regular SSH/Git):"
echo "$PROJECT_ROOT/scripts/configure-shell-env.sh"
echo
echo "After reloading your shell, use:"
echo "touchid_ssh_add -L"
echo "touchid_ssh your-user@your-server.example.com"
