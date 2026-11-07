# Docker listener (SIEM-host agent)

Reliable container events need three host pieces beyond enabling the wodle in
[`../agent-groups/linux/agent.conf`](../agent-groups/linux/agent.conf).

## 1. Python Docker SDK

On the SIEM host, as root:

```bash
pip3 install docker==7.1.0 urllib3==1.26.20 requests==2.32.2 \
  --break-system-packages --ignore-installed
```

`--ignore-installed` avoids Debian `urllib3` RECORD conflicts on Ubuntu 24.04-class hosts.

## 2. Import-order patch (required)

`/var/ossec/wodles/docker/DockerListener` inserts `wodles/` on `sys.path` **before**
`import docker`. That makes Python load the local `wodles/docker` directory as a
namespace package instead of the pip SDK. `from_env()` then fails forever; the
script reconnect-spams stdout until modulesd logs `String limit reached`.

Patch: import the SDK **before** the `sys.path.insert`. Stock backup on the host:
`/var/ossec/wodles/docker/DockerListener.stock-4.14.10`.

See [`DockerListener.import.patch`](DockerListener.import.patch). Re-apply after
every `wazuh-agent` package upgrade (the package overwrites this file).

## 3. docker.sock access

```bash
usermod -aG docker wazuh
systemctl restart wazuh-agent
```

## Verify

```bash
docker create --name wazuh-dl-verify alpine:latest true
docker start wazuh-dl-verify; docker rm -f wazuh-dl-verify
# Indexer: rule.groups=docker, location=Wazuh-Docker, agent name = your SIEM-host agent
```
