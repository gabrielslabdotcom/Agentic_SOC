#!/bin/sh
# Wazuh active response: isolate this Linux host.
# Keeps loopback, the Wazuh manager, and SSH from ALLOWED_MGMT_IPS.
# Install: /var/ossec/active-response/bin/network-isolation.sh
# Config:  /var/ossec/etc/isolation.conf  (see isolation.conf.example)
# Never bind this command to an alert rule. Manual API / HITL only.

set -u

LOG=/var/ossec/logs/active-responses.log
MARKER=/var/ossec/logs/agentic-isolation.state

log() {
  echo "$(date '+%Y/%m/%d %H:%M:%S') network-isolation: $*" >>"$LOG" 2>/dev/null || true
}

# Wazuh writes one JSON message and closes stdin. Drain it so the pipe cannot stall.
if [ ! -t 0 ]; then
  cat >/dev/null || true
fi

load_conf() {
  conf=""
  for candidate in /var/ossec/etc/isolation.conf "$(dirname "$0")/isolation.conf"; do
    if [ -f "$candidate" ]; then
      conf=$candidate
      break
    fi
  done
  if [ -z "$conf" ]; then
    log "missing isolation.conf — refusing to change the firewall"
    exit 1
  fi
  # shellcheck disable=SC1090
  set -a
  # shellcheck disable=SC1090
  . "$conf"
  set +a
}

iptables_bin() {
  if command -v iptables >/dev/null 2>&1; then
    command -v iptables
    return 0
  fi
  return 1
}

add_v4_chain() {
  tables=$1
  chain=$2
  hook=$3
  "$tables" -N "$chain" 2>/dev/null || "$tables" -F "$chain"
  "$tables" -F "$chain"
  if [ "$hook" = "INPUT" ]; then
    "$tables" -A "$chain" -i lo -j ACCEPT
    "$tables" -A "$chain" -s "$WAZUH_MANAGER_IP" -j ACCEPT
    for ip in $ALLOWED; do
      "$tables" -A "$chain" -p tcp -s "$ip" --dport "$SSH_PORT" -j ACCEPT
    done
  else
    "$tables" -A "$chain" -o lo -j ACCEPT
    "$tables" -A "$chain" -d "$WAZUH_MANAGER_IP" -j ACCEPT
    for ip in $ALLOWED; do
      "$tables" -A "$chain" -p tcp -d "$ip" --sport "$SSH_PORT" -j ACCEPT
    done
  fi
  "$tables" -A "$chain" -j DROP
  if ! "$tables" -C "$hook" -j "$chain" 2>/dev/null; then
    "$tables" -I "$hook" 1 -j "$chain" || exit 1
  fi
}

add_v6_drop() {
  tables=$1
  chain=$2
  hook=$3
  loflag=$4
  if ! command -v "$tables" >/dev/null 2>&1; then
    return 0
  fi
  "$tables" -N "$chain" 2>/dev/null || "$tables" -F "$chain"
  "$tables" -F "$chain"
  "$tables" -A "$chain" "$loflag" lo -j ACCEPT
  "$tables" -A "$chain" -j DROP
  if ! "$tables" -C "$hook" -j "$chain" 2>/dev/null; then
    "$tables" -I "$hook" 1 -j "$chain" || exit 1
  fi
}

load_conf

WAZUH_MANAGER_IP=${WAZUH_MANAGER_IP:-}
SSH_PORT=${SSH_PORT:-22}
ALLOWED=$(printf '%s' "${ALLOWED_MGMT_IPS:-}" | tr ',' ' ')

if [ -z "$WAZUH_MANAGER_IP" ]; then
  log "WAZUH_MANAGER_IP is empty — refusing to change the firewall"
  exit 1
fi

IPT=$(iptables_bin) || {
  log "iptables not on PATH — refusing to change the firewall"
  exit 1
}

add_v4_chain "$IPT" AGENTIC_ISO_IN INPUT
add_v4_chain "$IPT" AGENTIC_ISO_OUT OUTPUT
add_v6_drop ip6tables AGENTIC_ISO6_IN INPUT -i
add_v6_drop ip6tables AGENTIC_ISO6_OUT OUTPUT -o

date '+%Y/%m/%d %H:%M:%S' >"$MARKER" 2>/dev/null || true
log "isolated (manager $WAZUH_MANAGER_IP, ssh port $SSH_PORT)"
exit 0
