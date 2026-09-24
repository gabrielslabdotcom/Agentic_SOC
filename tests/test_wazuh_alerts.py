"""OpenSearch query body for list_alerts (since + sort order)."""

from agentic_soc.wazuh_client import build_alerts_search_body


def test_default_sort_desc_no_since() -> None:
    body = build_alerts_search_body(limit=40, min_level=8)
    assert body["size"] == 40
    assert body["sort"] == [{"@timestamp": {"order": "desc"}}]


def test_since_sorts_asc_and_filters() -> None:
    body = build_alerts_search_body(
        limit=40,
        min_level=8,
        since="2026-09-08T12:00:00.000Z",
        exclude_rule_ids=["100100"],
        agent_name="pop-os-native",
    )
    assert body["sort"] == [{"@timestamp": {"order": "asc"}}]
    must = body["query"]["bool"]["must"]
    assert {"range": {"@timestamp": {"gt": "2026-09-08T12:00:00.000Z"}}} in must
    assert {"range": {"rule.level": {"gte": 8}}} in must
    assert {"match": {"agent.name": "pop-os-native"}} in must
    assert body["query"]["bool"]["must_not"] == [{"terms": {"rule.id": ["100100"]}}]


def test_blank_agent_name_does_not_filter() -> None:
    body = build_alerts_search_body(min_level=8, agent_name="")
    must = body["query"]["bool"]["must"]
    assert {"range": {"rule.level": {"gte": 8}}} in must
    assert not any("agent.name" in str(clause) for clause in must)


def test_comma_separated_agents_use_terms() -> None:
    body = build_alerts_search_body(
        agent_name="pop-os-native,HYDRA-DC,SPIDERMAN",
    )
    must = body["query"]["bool"]["must"]
    assert {"terms": {"agent.name": ["pop-os-native", "HYDRA-DC", "SPIDERMAN"]}} in must


def test_blank_since_treated_as_absent() -> None:
    body = build_alerts_search_body(since="  ")
    assert body["sort"] == [{"@timestamp": {"order": "desc"}}]
    assert body["query"] == {"match_all": {}}


def test_auth_or_query_keeps_min_level() -> None:
    from agentic_soc.triage import AUTH_FAILURE_GROUPS, AUTH_FAILURE_RULE_IDS

    body = build_alerts_search_body(
        limit=40,
        min_level=8,
        include_auth_min_level=5,
    )
    must = body["query"]["bool"]["must"]
    or_clause = None
    for clause in must:
        inner = clause.get("bool") or {}
        if "should" in inner:
            or_clause = inner
            break
    assert or_clause is not None
    should = or_clause["should"]
    assert {"range": {"rule.level": {"gte": 8}}} in should
    auth = next(c for c in should if c != {"range": {"rule.level": {"gte": 8}}})
    auth_must = auth["bool"]["must"]
    assert {"range": {"rule.level": {"gte": 5}}} in auth_must
    auth_should = auth_must[1]["bool"]["should"]
    assert {"terms": {"rule.groups": sorted(AUTH_FAILURE_GROUPS)}} in auth_should
    assert {"terms": {"rule.id": sorted(AUTH_FAILURE_RULE_IDS)}} in auth_should
    # Global floor stays 8 — no lone gte:5 at the top-level must.
    assert {"range": {"rule.level": {"gte": 5}}} not in must
