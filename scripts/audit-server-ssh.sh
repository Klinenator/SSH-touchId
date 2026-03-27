#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-your-server.example.com}"
KEY_PATH="${2:-$HOME/.ssh/your-ssh-key.pem}"
USER_NAME="${3:-your-user}"
CLIENT_IP="${4:-}"

if [[ ! -f "$KEY_PATH" ]]; then
  echo "error: key not found at $KEY_PATH" >&2
  exit 1
fi

SSH=(ssh -i "$KEY_PATH" -o IdentitiesOnly=yes "${USER_NAME}@${HOST}")

echo "== Basic reachability =="
"${SSH[@]}" "hostname && whoami && date"

echo

echo "== sshd_config (relevant directives) =="
"${SSH[@]}" "sudo grep -nE 'AuthenticationMethods|ChallengeResponseAuthentication|KbdInteractiveAuthentication|PasswordAuthentication|PubkeyAuthentication|PermitRootLogin|UsePAM|MaxAuthTries|AllowUsers' /etc/ssh/sshd_config"

echo

echo "== Effective sshd config =="
if [[ -n "$CLIENT_IP" ]]; then
  "${SSH[@]}" "sudo sshd -T -C user=${USER_NAME},addr=${CLIENT_IP},host=${HOST} | grep -E 'authenticationmethods|kbdinteractiveauthentication|challengeresponseauthentication|passwordauthentication|pubkeyauthentication|permitrootlogin|usepam|maxauthtries'"
else
  "${SSH[@]}" "sudo sshd -T | grep -E 'authenticationmethods|kbdinteractiveauthentication|challengeresponseauthentication|passwordauthentication|pubkeyauthentication|permitrootlogin|usepam|maxauthtries'"
fi

echo

echo "== fail2ban sshd =="
"${SSH[@]}" "sudo fail2ban-client status sshd 2>/dev/null || echo 'fail2ban not installed or sshd jail unavailable'"
"${SSH[@]}" "sudo fail2ban-client get sshd ignoreip 2>/dev/null || true"

echo

echo "== sshd backups =="
"${SSH[@]}" "ls -1t /etc/ssh/sshd_config.bak.* 2>/dev/null | head -n 5 || echo 'no backups found'"
