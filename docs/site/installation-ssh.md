# Installation — SSH

Operator detail: [SETUP_GUIDE.md §2](../SETUP_GUIDE.md) (keys, `~/.ssh/config`).

From the Mac, key-based SSH to the SIEM host should work with **no password prompt**.

Example `~/.ssh/config` (fill placeholders from [`LAB_LOCAL.md`](../LAB_LOCAL.md.example)):

```sshconfig
Host <ssh-alias>
  HostName <SIEM_HOST>
  User <ssh-user>
  IdentityFile ~/.ssh/id_ed25519
  IdentitiesOnly yes
```

Smoke test:

```bash
ssh -o BatchMode=yes -o ConnectTimeout=8 <ssh-alias> 'hostname && whoami'
```

Next: [Installation — Wazuh](installation-wazuh.md).
