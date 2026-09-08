# Installation — SSH

Operator detail: [SETUP_GUIDE.md §2](../SETUP_GUIDE.md).

From the Mac, key-based SSH to the laptop should work with **no password prompt**.

1. Authorize your public key for `admin@<POP_LAN_IP>`.
2. Add an alias to `~/.ssh/config`:

```sshconfig
Host soc
  HostName 192.168.50.254
  User admin
  IdentityFile ~/.ssh/id_ed25519
  IdentitiesOnly yes
```

3. Test:

```bash
ssh -o BatchMode=yes -o ConnectTimeout=8 soc 'hostname && whoami'
```

You should see the laptop hostname and `admin`.

Next: [Installation — Wazuh](installation-wazuh.md).
