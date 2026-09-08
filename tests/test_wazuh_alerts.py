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


def test_blank_since_treated_as_absent() -> None:
    body = build_alerts_search_body(since="  ")
    assert body["sort"] == [{"@timestamp": {"order": "desc"}}]
    assert body["query"] == {"match_all": {}}
