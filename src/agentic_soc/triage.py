"""Deterministic triage helpers: IOC extraction, scoring, dispositions, case gating."""

from __future__ import annotations

import re
from typing import Any, Optional

from agentic_soc.enrichment import detect_ioc_type

# Private / lab-local ranges we usually skip for VT noise
_PRIVATE_IP_RE = re.compile(
    r"^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[0-1])\.|0\.|255\.|224\.|239\.)"
)

_INTERNAL_DOMAIN_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".lan",
    ".home",
    ".corp",
    ".manager",
    ".indexer",
    ".dashboard",
)

_SKIP_DOMAINS = {
    "localhost",
    "localdomain",
    "wazuh.manager",
    "wazuh.indexer",
    "wazuh.dashboard",
}

_IPV4_FIND = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_HASH_FIND = re.compile(r"\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b")
_URL_FIND = re.compile(r"https?://[^\s\"'<>]+", re.I)
_DOMAIN_FIND = re.compile(
    r"\b(?!(?:\d+\.){3}\d+)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}\b"
)
_SRC_IP_RE = re.compile(
    r"(?:SRC|src)=(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
    r"|(?:from|source)\s+(?P<ip2>(?:\d{1,3}\.){3}\d{1,3})",
    re.I,
)

# Lab custom UFW / port-scan rules (see docs/SETUP_GUIDE.md §8.1)
RULE_UFW_BLOCK = "100100"
RULE_PORT_SCAN_MULTI = "100101"
RULE_PORT_SCAN_LAB = "100102"
PORT_SCAN_AGGREGATE_RULES = frozenset({RULE_PORT_SCAN_MULTI, RULE_PORT_SCAN_LAB})

# Common Wazuh sshd/PAM auth-failure rule ids (often level 5)
AUTH_FAILURE_RULE_IDS = frozenset({"5710", "5712", "5716", "5720", "5503", "5551"})
AUTH_FAILURE_GROUPS = frozenset({"authentication_failed", "authentication_failures"})

# Descriptions / rule groups that are usually benign lab noise
_BENIGN_PATTERNS = (
    "pam: login session opened",
    "pam: login session closed",
    "sshd: authentication success",
    "user logged in",
    "user logged out",
    "new host information",
    "agent started",
    "agent connected",
    "agent disconnected",
)

# Wazuh agent backlog / drop signals (flood side-effect, not an attack)
_AGENT_CAPACITY_PATTERNS = (
    "agent event queue is full",
    "event queue is full",
    "events may be lost",
)

_SUSPICIOUS_PATTERNS = (
    "failed",
    "invalid",
    "brute",
    "attack",
    "malware",
    "exploit",
    "rootkit",
    "webshell",
    "privilege",
    "sudo: ",
    "illegal",
    "denied",
    "scan",
    "port scan",
    "trojan",
    "ransomware",
)

# Minimum sibling UFW BLOCKs (same source) before a lone 100100 may open a case
UFW_BLOCK_CLUSTER_MIN = 5
# Informational / FP alerts at or above this level can still open cases
DEFAULT_OPEN_LEVEL_THRESHOLD = 10
NOISE_DISPOSITIONS = frozenset({"false_positive", "informational"})


def _walk_strings(obj: Any, out: list[str], depth: int = 0) -> None:
    if depth > 6:
        return
    if isinstance(obj, str):
        if obj.strip():
            out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _walk_strings(v, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _walk_strings(v, out, depth + 1)


def _rule_id(alert: dict[str, Any]) -> str:
    rid = alert.get("rule_id")
    if rid is not None and str(rid).strip():
        return str(rid).strip()
    raw = alert.get("raw") or {}
    if isinstance(raw, dict):
        rule = raw.get("rule") or {}
        if isinstance(rule, dict) and rule.get("id") is not None:
            return str(rule["id"]).strip()
    return ""


def _rule_groups(alert: dict[str, Any]) -> list[str]:
    raw = alert.get("raw") or {}
    rule = raw.get("rule") if isinstance(raw, dict) else {}
    if isinstance(rule, dict):
        return [str(g).lower() for g in (rule.get("groups") or [])]
    return []


def _description(alert: dict[str, Any]) -> str:
    return (alert.get("description") or "").lower()


def extract_source_ip(alert: dict[str, Any]) -> Optional[str]:
    """Best-effort attacker/source IP from UFW-style full_log or raw data."""
    raw = alert.get("raw")
    if isinstance(raw, dict):
        data = raw.get("data")
        if isinstance(data, dict):
            for k in ("srcip", "src_ip", "source_ip"):
                if data.get(k):
                    return str(data[k]).strip()

    blobs: list[str] = []
    for key in ("full_log", "description"):
        val = alert.get(key)
        if isinstance(val, str):
            blobs.append(val)
    if isinstance(raw, dict):
        _walk_strings(raw, blobs)

    for blob in blobs:
        m = _SRC_IP_RE.search(blob)
        if m:
            ip = (m.group("ip") or m.group("ip2") or "").strip()
            if ip and not ip.startswith("224."):
                return ip
    return None


def extract_iocs(alert: dict[str, Any], *, include_private_ips: bool = False) -> list[dict[str, str]]:
    """Pull IPs/domains/URLs/hashes from alert text fields."""
    blobs: list[str] = []
    for key in ("full_log", "description"):
        val = alert.get(key)
        if isinstance(val, str):
            blobs.append(val)
    raw = alert.get("raw")
    if isinstance(raw, dict):
        _walk_strings(raw, blobs)

    found: dict[tuple[str, str], dict[str, str]] = {}

    def add(value: str) -> None:
        value = value.strip().rstrip(".,;:)")
        kind = detect_ioc_type(value)
        if kind == "unknown":
            return
        if kind == "ip" and not include_private_ips and _PRIVATE_IP_RE.match(value):
            return
        if kind == "domain":
            low = value.lower()
            if low in _SKIP_DOMAINS or any(low.endswith(sfx) for sfx in _INTERNAL_DOMAIN_SUFFIXES):
                return
            # Require a plausible public TLD (skip host.manager style lab names)
            tld = low.rsplit(".", 1)[-1]
            if tld not in {
                "com", "net", "org", "io", "co", "edu", "gov", "info", "biz",
                "dev", "app", "cloud", "ai", "xyz", "me", "us", "uk", "de",
                "ru", "cn", "br", "in", "fr", "jp", "au", "ca", "nl", "se",
                "ch", "it", "es", "tv", "cc", "to", "gg", "ly", "sh", "so",
            }:
                return
        found[(kind, value.lower())] = {"ioc": value, "ioc_type": kind}

    for blob in blobs:
        for m in _URL_FIND.findall(blob):
            add(m)
        for m in _IPV4_FIND.findall(blob):
            add(m)
        for m in _HASH_FIND.findall(blob):
            add(m)
        for m in _DOMAIN_FIND.findall(blob):
            if m.count(".") >= 1:
                add(m)

    return list(found.values())


def is_compliance_noise(alert: dict[str, Any]) -> bool:
    desc = _description(alert)
    groups = _rule_groups(alert)
    if "cis" in desc or "sca" in desc:
        return True
    if any(g in {"sca", "pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc"} for g in groups):
        return True
    return False


def is_agent_capacity_noise(alert: dict[str, Any]) -> bool:
    """True for agent backlog/drop alerts (e.g. queue full during a flood)."""
    desc = _description(alert)
    if any(p in desc for p in _AGENT_CAPACITY_PATTERNS):
        return True
    full = (alert.get("full_log") or "").lower()
    if any(p in full for p in _AGENT_CAPACITY_PATTERNS):
        return True
    return False


def is_auth_failure(alert: dict[str, Any]) -> bool:
    desc = _description(alert)
    groups = _rule_groups(alert)
    if any(
        p in desc
        for p in (
            "authentication failed",
            "user login failed",
            "missed the password",
            "failed password",
            "invalid user",
            "non-existent user",
            "attempt to login using a non-existent",
        )
    ):
        return True
    if "authentication_failed" in groups or "authentication_failures" in groups:
        return True
    full = (alert.get("full_log") or "").lower()
    blob = f"{desc} {full}"
    if any(
        p in blob
        for p in (
            "not in the sudoers",
            "attempt to run sudo by unauthorized",
            "incorrect password attempt",
        )
    ):
        return True
    return False


def is_successful_sudo(alert: dict[str, Any]) -> bool:
    """True for routine sudo command logs, not sudoers denials or auth failures."""
    if is_auth_failure(alert):
        return False
    desc = _description(alert)
    full = (alert.get("full_log") or "").lower()
    blob = f"{desc} {full}"
    if any(
        p in blob
        for p in (
            "not in the sudoers",
            "incorrect password",
            "authentication failure",
            "command not allowed",
            "unauthorized user",
        )
    ):
        return False
    return any(
        p in blob
        for p in ("sudo:", "successful sudo", "sudo executed")
    )


def is_port_scan_aggregate(alert: dict[str, Any]) -> bool:
    rid = _rule_id(alert)
    if rid in PORT_SCAN_AGGREGATE_RULES:
        return True
    desc = _description(alert)
    return "port scan" in desc and "ufw firewall block event" not in desc


def is_lone_ufw_block(alert: dict[str, Any]) -> bool:
    rid = _rule_id(alert)
    if rid == RULE_UFW_BLOCK:
        return True
    desc = _description(alert)
    return "ufw firewall block" in desc and not is_port_scan_aggregate(alert)


def ufw_block_cluster_size(
    alert: dict[str, Any],
    sibling_alerts: Optional[list[dict[str, Any]]] = None,
) -> int:
    """Count same-source UFW BLOCK alerts in the current batch (including self)."""
    siblings = sibling_alerts or []
    src = extract_source_ip(alert)
    if src is None:
        return 1 if is_lone_ufw_block(alert) else 0
    count = 0
    for other in siblings:
        if not is_lone_ufw_block(other):
            continue
        if extract_source_ip(other) == src:
            count += 1
    return max(count, 1 if is_lone_ufw_block(alert) else 0)


def should_open_case(
    alert: dict[str, Any],
    judgment: dict[str, Any],
    *,
    sibling_alerts: Optional[list[dict[str, Any]]] = None,
    open_level_threshold: int = DEFAULT_OPEN_LEVEL_THRESHOLD,
) -> dict[str, Any]:
    """
    Shared gate used by agent_triage and eval harness.

    Prefer aggregated port-scan rules (100101/100102). Lone UFW BLOCK (100100)
    floods are skipped unless the batch shows a same-source cluster.
    Agent queue-full / capacity alerts never open cases (flood side-effect).
    """
    disposition = str(judgment.get("disposition") or "")
    try:
        level_i = int(alert.get("rule_level") or 0)
    except (TypeError, ValueError):
        level_i = 0

    # Agent backlog under load — never page Discord / open a case
    if is_agent_capacity_noise(alert):
        return {
            "open": False,
            "reason": "agent_capacity_noise",
            "cluster_size": None,
        }

    # Prefer aggregate rules; demote raw UFW BLOCK floods
    if is_lone_ufw_block(alert) and not is_port_scan_aggregate(alert):
        cluster = ufw_block_cluster_size(alert, sibling_alerts)
        if cluster < UFW_BLOCK_CLUSTER_MIN:
            return {
                "open": False,
                "reason": "lone_ufw_block_prefer_aggregate",
                "cluster_size": cluster,
            }
        # Clustered blocks: still only open if scoring raised them above noise
        if disposition in ("false_positive", "informational") and level_i < open_level_threshold:
            return {
                "open": False,
                "reason": "ufw_block_cluster_still_under_threshold",
                "cluster_size": cluster,
            }

    if disposition in ("false_positive", "informational") and level_i < open_level_threshold:
        return {
            "open": False,
            "reason": "benign_or_informational",
            "cluster_size": None,
        }

    return {"open": True, "reason": "open", "cluster_size": None}


def is_auto_close_noise(
    alert: dict[str, Any],
    judgment: dict[str, Any],
    *,
    enrichments: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Limited auto-close of lab noise (Phase D). Never containment.

    Suspicious and true_positive always stay HITL. Malicious VT hits stay HITL.
    """
    del alert  # reserved for future rule-id allowlists
    disp = str(judgment.get("disposition") or "")
    if disp not in NOISE_DISPOSITIONS:
        return {"close": False, "reason": "not_noise_disposition"}
    for item in enrichments or []:
        try:
            mal = int(item.get("malicious") or 0)
        except (TypeError, ValueError):
            mal = 0
        if mal > 0:
            return {"close": False, "reason": "enrichment_malicious"}
    return {"close": True, "reason": "heuristic_noise"}


def score_alert(alert: dict[str, Any], enrichments: Optional[list[dict[str, Any]]] = None) -> dict[str, Any]:
    """
    Return triage judgment:
      disposition: true_positive | suspicious | false_positive | informational
      confidence: 0.0–1.0
      severity: low|medium|high|critical
    """
    level = alert.get("rule_level")
    try:
        level_i = int(level) if level is not None else 0
    except (TypeError, ValueError):
        level_i = 0
    desc = _description(alert)
    groups = _rule_groups(alert)
    rid = _rule_id(alert)
    reasons: list[str] = []

    score = float(level_i)  # base on Wazuh level (0–15 typically)

    # --- High-priority specialized paths ---------------------------------
    if is_agent_capacity_noise(alert):
        score -= 6
        reasons.append("agent capacity / event-queue backlog (flood side-effect, not an attack)")
        disposition = "informational"
        if level_i <= 7:
            disposition = "false_positive"
            reasons.append("low/mid-level agent capacity noise treated as false_positive")
        confidence = 0.85
        severity = "low"
        action = _recommend_action(disposition, level_i, 0)
        return {
            "disposition": disposition,
            "confidence": confidence,
            "severity": severity,
            "score": round(max(score, 0.0), 2),
            "reasons": reasons,
            "recommended_action": action,
        }

    if is_port_scan_aggregate(alert) or rid in PORT_SCAN_AGGREGATE_RULES:
        score += 6
        reasons.append(f"aggregated port-scan / UFW correlation rule ({rid or 'desc'})")
        if rid == RULE_PORT_SCAN_MULTI or level_i >= 10:
            disposition = "true_positive"
            confidence = 0.8
        else:
            disposition = "suspicious"
            confidence = 0.7
        severity = _severity_from(level_i, disposition)
        action = _recommend_action(disposition, level_i, 0)
        return {
            "disposition": disposition,
            "confidence": confidence,
            "severity": severity,
            "score": round(score, 2),
            "reasons": reasons,
            "recommended_action": action,
        }

    if is_lone_ufw_block(alert):
        # Raw individual UFW BLOCKs are low-value without aggregation
        score -= 4
        reasons.append(
            f"lone UFW BLOCK (rule {rid or 'n/a'}); prefer aggregate rules "
            f"{RULE_PORT_SCAN_MULTI}/{RULE_PORT_SCAN_LAB}"
        )
        disposition = "informational"
        confidence = 0.75
        severity = "low"
        action = _recommend_action(disposition, level_i, 0)
        return {
            "disposition": disposition,
            "confidence": confidence,
            "severity": severity,
            "score": round(max(score, 0.0), 2),
            "reasons": reasons,
            "recommended_action": action,
        }

    if is_compliance_noise(alert):
        score -= 4
        reasons.append("compliance/SCA/CIS-style finding")
        disposition = "informational"
        if level_i <= 5:
            disposition = "false_positive"
            reasons.append("low-level compliance noise treated as false_positive")
        confidence = 0.7
        severity = _severity_from(level_i, disposition)
        # Cap compliance severity — these are not incidents
        if severity in ("high", "critical"):
            severity = "medium"
        action = _recommend_action(disposition, level_i, 0)
        return {
            "disposition": disposition,
            "confidence": confidence,
            "severity": severity,
            "score": round(max(score, 0.0), 2),
            "reasons": reasons,
            "recommended_action": action,
        }

    if is_auth_failure(alert):
        score += 4
        reasons.append("explicit authentication failure signal")
        if "authentication_failed" in groups or "authentication_failures" in groups:
            score += 2
            reasons.append(f"rule groups suggest auth failure: {groups[:5]}")
        disposition = "suspicious"
        confidence = 0.7
        if level_i >= 10 or "missed the password more than one time" in desc:
            confidence = 0.75
        severity = _severity_from(level_i, disposition)
        action = _recommend_action(disposition, level_i, 0)
        return {
            "disposition": disposition,
            "confidence": confidence,
            "severity": severity,
            "score": round(score, 2),
            "reasons": reasons,
            "recommended_action": action,
        }

    if is_successful_sudo(alert) and level_i < 7:
        score -= 3
        reasons.append("successful sudo command log (lab noise unless denied)")
        disposition = "informational"
        confidence = 0.7
        severity = "low"
        action = _recommend_action(disposition, level_i, 0)
        return {
            "disposition": disposition,
            "confidence": confidence,
            "severity": severity,
            "score": round(max(score, 0.0), 2),
            "reasons": reasons,
            "recommended_action": action,
        }

    # --- Generic heuristics ----------------------------------------------
    if any(p in desc for p in _BENIGN_PATTERNS):
        score -= 4
        reasons.append("matches common benign/lab auth noise pattern")

    if any(p in desc for p in _SUSPICIOUS_PATTERNS):
        score += 3
        reasons.append("description matches suspicious keyword")

    if "attack" in groups or "intrusion_attempt" in groups:
        score += 2
        reasons.append(f"rule groups suggest attack: {groups[:5]}")

    malicious_hits = 0
    for e in enrichments or []:
        if e.get("error"):
            continue
        mal = int(e.get("malicious") or 0)
        sus = int(e.get("suspicious") or 0)
        if mal > 0:
            malicious_hits += mal
            score += min(8, 2 + mal)
            reasons.append(f"VirusTotal malicious={mal} for {e.get('ioc')}")
        elif sus > 2:
            score += 2
            reasons.append(f"VirusTotal suspicious={sus} for {e.get('ioc')}")

    if level_i >= 12 or malicious_hits >= 3:
        disposition = "true_positive"
        confidence = 0.75 if malicious_hits else 0.65
    elif score >= 10 or (level_i >= 7 and any(p in desc for p in _SUSPICIOUS_PATTERNS)):
        disposition = "suspicious"
        confidence = 0.6
    elif score <= 3 or (level_i <= 4 and any(p in desc for p in _BENIGN_PATTERNS)):
        disposition = "false_positive"
        confidence = 0.7
        reasons.append("low residual score after benign heuristics")
    elif level_i <= 5 and not any(p in desc for p in _SUSPICIOUS_PATTERNS):
        disposition = "informational"
        confidence = 0.55
    else:
        disposition = "suspicious"
        confidence = 0.5
        reasons.append("elevated level without strong benign match")

    severity = _severity_from(level_i, disposition)
    action = _recommend_action(disposition, level_i, malicious_hits)
    return {
        "disposition": disposition,
        "confidence": round(confidence, 2),
        "severity": severity,
        "score": round(score, 2),
        "reasons": reasons,
        "recommended_action": action,
    }


def _severity_from(level_i: int, disposition: str) -> str:
    if disposition in ("informational", "false_positive") and level_i < 10:
        if level_i >= 7:
            return "medium"
        if level_i >= 4:
            return "low"
        return "low"
    if level_i >= 12:
        return "critical"
    if level_i >= 7 or disposition == "true_positive":
        return "high"
    if level_i >= 4 or disposition == "suspicious":
        return "medium"
    return "low"


def _recommend_action(disposition: str, level: int, malicious_hits: int) -> str:
    if disposition == "true_positive" or malicious_hits > 0:
        return "investigate_and_document"
    if disposition == "suspicious":
        return "investigate_and_document"
    if disposition == "false_positive":
        return "close_as_benign_lab_noise"
    return "monitor_only"


def build_summary(alert: dict[str, Any], judgment: dict[str, Any], enrichments: list[dict[str, Any]]) -> str:
    lines = [
        f"Auto-triage disposition={judgment['disposition']} "
        f"confidence={judgment['confidence']} score={judgment['score']}",
        f"rule_id={alert.get('rule_id')} level={alert.get('rule_level')} "
        f"agent={alert.get('agent')} ts={alert.get('timestamp')}",
        f"description={alert.get('description')}",
    ]
    if judgment.get("reasons"):
        lines.append("reasons: " + "; ".join(judgment["reasons"]))
    if enrichments:
        for e in enrichments:
            if e.get("error"):
                lines.append(f"enrichment error for {e.get('ioc')}: {e.get('error')}")
            else:
                lines.append(
                    f"VT {e.get('ioc_type')} {e.get('ioc')}: "
                    f"malicious={e.get('malicious')} suspicious={e.get('suspicious')} "
                    f"found={e.get('found')}"
                )
    else:
        lines.append("enrichment: none (no external IOCs or skipped)")
    lines.append("NOTE: containment disabled — human approval required for response.")
    return "\n".join(lines)
