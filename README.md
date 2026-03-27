# touchid-ssh-agent

Touch ID-gated SSH agent prototype for macOS.

## Phase 3 Quickstart

Build:

```bash
cd ~/src/emulator/touchid-ssh-agent
swift build
```

Install and start LaunchAgent:

```bash
~/src/emulator/touchid-ssh-agent/scripts/install-launchagent.sh
```

Install scoped shell helpers (recommended; does not change regular SSH/Git behavior):

```bash
~/src/emulator/touchid-ssh-agent/scripts/configure-shell-env.sh
```

Open a new terminal (or `source ~/.zshrc`) and verify Touch ID-managed identity visibility:

```bash
touchid_ssh_add -L
```

Run an agent-only SSH test:

```bash
~/src/emulator/touchid-ssh-agent/scripts/test-agent-login.sh your-server.example.com your-user
```

Run release push flow (tests + push to `origin/main`):

```bash
~/src/emulator/touchid-ssh-agent/scripts/release.sh
```

Dry-run release (no push):

```bash
~/src/emulator/touchid-ssh-agent/scripts/release.sh --dry-run
```

## Files

- `launchd/com.touchidsshagent.agent.plist.template`: LaunchAgent template used by install script.
- `scripts/install-launchagent.sh`: Installs/reloads LaunchAgent and starts the daemon.
- `scripts/configure-shell-env.sh`: Adds or updates an idempotent scoped helper block in your shell rc file (no global `SSH_AUTH_SOCK` override).
- `scripts/rollback-launchagent.sh`: Stops/unloads LaunchAgent and removes the agent socket.
- `scripts/test-agent-login.sh`: Runs an agent-only SSH login test against a host.
- `scripts/release.sh`: Runs tests, validates repo state, and pushes release branch.
- `docs/phase4-rollout.md`: Phase 4 rollout, policy, and rollback notes.
- `scripts/audit-server-ssh.sh`: Audits server SSH/fail2ban posture over SSH.
- `docs/production-hardening-checklist.md`: Production hardening status and rollback checklist.

## Optional Environment Overrides

- `TOUCHID_AGENT_BINARY`: binary path (default: `.build/debug/touchid-ssh-agent`)
- `TOUCHID_AGENT_SOCKET`: unix socket path (default: `~/.ssh/touchid-agent.sock`)
- `TOUCHID_AGENT_REASON`: Touch ID prompt reason text
