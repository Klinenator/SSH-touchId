# Production Hardening Checklist

## Current Verified State (2026-03-26 EDT)

- SSH key-only auth is enforced on `your-server.example.com`.
- `AuthenticationMethods publickey` is active.
- `KbdInteractiveAuthentication no` is active.
- `ChallengeResponseAuthentication no` is active.
- `PasswordAuthentication no` is active.
- `PermitRootLogin no` is active.
- `MaxAuthTries 4` is active.
- Fail2ban `sshd` jail is running.
- Home IP `203.0.113.10` is in fail2ban `ignoreip`.
- SSH config backup exists at `/etc/ssh/sshd_config.bak.2026-03-26-225119`.

## One-Command Server Audit

Run from your Mac:

```bash
~/src/touchid-ssh-agent/scripts/audit-server-ssh.sh \
  your-server.example.com \
  ~/.ssh/your-ssh-key.pem \
  your-user \
  203.0.113.10
```

## Recommended Ongoing Controls

1. Keep security group SSH source restricted to your trusted client IP (for example `203.0.113.10/32`).
2. Keep at least one active shell open while changing SSH config.
3. Keep timestamped `/etc/ssh/sshd_config.bak.*` backups before each change.
4. Re-run the audit script after any SSH, PAM, or fail2ban change.
5. Test both:
   - classic key login (`ssh -i ~/.ssh/your-ssh-key.pem your-user@your-server.example.com`)
   - Touch ID agent login (`test-agent-login.sh`).

## Rollback

If needed on server:

```bash
sudo cp /etc/ssh/sshd_config.bak.2026-03-26-225119 /etc/ssh/sshd_config
sudo sshd -t && sudo systemctl reload ssh
```

If needed on Mac (stop custom agent):

```bash
~/src/touchid-ssh-agent/scripts/rollback-launchagent.sh
```

If you previously set a global `SSH_AUTH_SOCK` export, remove that line from your shell rc file.
