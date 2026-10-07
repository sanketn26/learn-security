"""Detections, playbooks, and the agent's catalog must agree with each other."""

from __future__ import annotations

import re

import yaml

from tests.conftest import LABS, load_module

RULES = yaml.safe_load((LABS / "detections" / "rules.yaml").read_text(encoding="utf-8"))["rules"]
OWASP_ID = re.compile(r"^(A(0[1-9]|10):2025|API(10|[1-9]):2023)$")


def test_rule_ids_are_unique_and_sequential():
    ids = [r["id"] for r in RULES]
    assert ids == [f"DET-{n:03d}" for n in range(1, len(ids) + 1)]


def test_every_rule_has_a_playbook_file():
    for rule in RULES:
        assert (LABS / "soc-lite" / "playbooks" / rule["playbook"]).is_file(), rule["id"]


def test_every_rule_carries_valid_owasp_tags():
    for rule in RULES:
        tags = rule.get("owasp")
        assert tags, f"{rule['id']} has no owasp tag"
        assert all(OWASP_ID.match(t) for t in tags), (rule["id"], tags)


def test_every_rule_has_an_attack_mapping_and_regexes_compile():
    for rule in RULES:
        assert rule["attack"]["technique_id"].startswith("T1"), rule["id"]
        if "match_regex" in rule:
            re.compile(rule["match_regex"])
            assert rule.get("match_field"), rule["id"]


def test_agent_catalog_matches_rules():
    agent = load_module("agent_consistency", LABS / "agentic-soc" / "agent.py")
    for rule in RULES:
        mapping = agent.TECHNIQUE_CATALOG[rule["id"]]
        assert mapping["technique_id"] == rule["attack"]["technique_id"], rule["id"]
        assert agent.PLAYBOOK_BY_RULE[rule["id"]] == rule["playbook"], rule["id"]
