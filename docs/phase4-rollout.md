# Phase 4 Rollout Notes

## Status Snapshot (2026-03-26)

- Custom Touch ID SSH agent is installed and running via LaunchAgent.
- Managed key (`managed-key@local`) is visible through `ssh-add -L` when using `~/.ssh/touchid-agent.sock`.
- `your-server.example.com` now accepts the managed ECDSA key and Touch ID-backed signing succeeds.
- SSH server auth policy for this rollout was updated to key-only:
  - `AuthenticationMethods publickey`
  - `ChallengeResponseAuthentication no`
  - `KbdInteractiveAuthentication no`
- `your-server.example.com` currently resolves to `203.0.113.20`, but the live target instance is reachable at `203.0.113.45`.
- `staging-server.example.com` was used as a surrogate rollout host:
  - Managed ECDSA key added to `~/.ssh/authorized_keys`.
  - Server accepted managed key offer.
  - Signing failed in this automation context because LocalAuthentication returned fallback/denied (`LAError -3`).
- Managed ECDSA key was also added to the live target host via `203.0.113.45`.

## Command Set For your-server.example.com (when port 22 is back)

1. Verify DNS and SSH reachability:

```bash
dig +short your-server.example.com
nc -vz your-server.example.com 22
```

2. Add managed key to authorized keys:

```bash
KEY_LINE='ecdsa-sha2-nistp256 <YOUR_MANAGED_PUBLIC_KEY_BASE64> managed-key@local'
ssh -i ~/.ssh/your-ssh-key.pem -o IdentitiesOnly=yes your-user@your-server.example.com \
  "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && \
   grep -qxF '$KEY_LINE' ~/.ssh/authorized_keys || printf '%s\\n' '$KEY_LINE' >> ~/.ssh/authorized_keys"
```

3. Validate agent-only auth path:

```bash
ssh -vv -F /dev/null \
  -o IdentityAgent=~/.ssh/touchid-agent.sock \
  -o PreferredAuthentications=publickey \
  -o KbdInteractiveAuthentication=no \
  your-user@your-server.example.com
```

Or use the helper script:

```bash
~/src/emulator/touchid-ssh-agent/scripts/test-agent-login.sh your-server.example.com your-user
```

If DNS has not been updated yet, use the temporary direct-IP path:

```bash
~/src/emulator/touchid-ssh-agent/scripts/test-agent-login.sh 203.0.113.45 your-user
```

Expected behavior in an interactive Terminal session:
- Touch ID prompt appears for signing.
- If approved, SSH public key auth succeeds.

## Policy Recommendation

During rollout, keep `keyboard-interactive` enabled server-side as fallback until:
- interactive Touch ID sign success is verified on the target host,
- and at least one rollback-tested session is confirmed.

## Rollback Commands

Unload custom agent:

```bash
~/src/emulator/touchid-ssh-agent/scripts/rollback-launchagent.sh
```

If you previously set a global `SSH_AUTH_SOCK` export, remove that line from your shell rc file.
