#!/bin/sh
# Wazuh active response: remove host isolation installed by network-isolation.sh.
# Install: /var/ossec/active-response/bin/network-deisolation.sh

set -u

LOG=/var/ossec/logs/active-responses.log
MARKER=/var/ossec/logs/agentic-isolation.state

log() {
  echo "$(date '+%Y/%m/%d %H:%M:%S') network-deisolation: $*" >>"$LOG" 2>/dev/null || true
}

if [ ! -t 0 ]; then
  cat >/dev/null || true
fi

drop_jump() {
  tables=$1
  hook=$2
  chain=$3
  if ! command -v "$tables" >/dev/null 2>&1; then
    return 0
  fi
  while "$tables" -D "$hook" -j "$chain" 2>/dev/null; do
    :
  done
  "$tables" -F "$chain" 2>/dev/null || true
  "$tables" -X "$chain" 2>/dev/null || true
}

IPT=iptables
if ! command -v iptables >/dev/null 2>&1; then
  log "iptables not on PATH"
  exit 1
fi

drop_jump "$IPT" INPUT AGENTIC_ISO_IN
drop_jump "$IPT" OUTPUT AGENTIC_ISO_OUT
drop_jump ip6tables INPUT AGENTIC_ISO6_IN
drop_jump ip6tables OUTPUT AGENTIC_ISO6_OUT

rm -f "$MARKER" 2>/dev/null || true
log "de-isolated"
exit 0
