"""Tests for the rule engine. Run with:  pytest   (no Scapy or Flask needed)"""
import pytest
from firewall.engine import evaluate, find_shadowed
from firewall.rules import Rule, RuleStore, default_rules


def pkt(src="8.8.8.8", dst="192.168.1.1", proto="TCP", dport=443):
    return {"src": src, "dst": dst, "proto": proto, "dport": dport}


def test_first_match_wins():
    rules = [Rule(1, "ALLOW", protocol="TCP", dst_port=22), Rule(2, "BLOCK", protocol="TCP", dst_port=22)]
    assert evaluate(pkt(dport=22), rules)["rule_id"] == 1


def test_order_changes_outcome():
    rules = [Rule(1, "BLOCK", protocol="TCP", dst_port=22), Rule(2, "ALLOW", protocol="TCP", dst_port=22)]
    assert evaluate(pkt(dport=22), rules)["verdict"] == "BLOCK"


def test_default_policy_when_nothing_matches():
    result = evaluate(pkt(dport=9999), default_rules())
    assert result["verdict"] == "BLOCK" and result["rule_id"] is None


def test_cidr_matching():
    rule = Rule(1, "ALLOW", src_ip="192.168.1.0/24")
    assert rule.matches(pkt(src="192.168.1.200"))
    assert not rule.matches(pkt(src="192.168.2.1"))


def test_icmp_never_matches_port_rule():
    assert not Rule(1, "ALLOW", dst_port=80).matches(pkt(proto="ICMP", dport=None))


def test_starter_policy_scenarios():
    rules = default_rules()
    assert evaluate(pkt(src="192.168.1.10", dport=22), rules)["verdict"] == "ALLOW"   # LAN SSH
    assert evaluate(pkt(src="45.33.32.156", dport=22), rules)["verdict"] == "BLOCK"   # outside SSH
    assert evaluate(pkt(src="203.0.113.5", dport=443), rules)["rule_id"] == 1         # blocklist beats HTTPS


def test_shadowed_rule_detected():
    rules = [Rule(1, "BLOCK", protocol="TCP"), Rule(2, "ALLOW", protocol="TCP", dst_port=443)]
    assert find_shadowed(rules) == {2: 1}


def test_validation_rejects_bad_input():
    store = RuleStore()
    with pytest.raises(ValueError):
        store.add({"action": "MAYBE"})
    with pytest.raises(ValueError):
        store.add({"action": "BLOCK", "src_ip": "not-an-ip"})
    with pytest.raises(ValueError):
        store.add({"action": "BLOCK", "protocol": "TCP", "dst_port": 70000})


def test_move_rule():
    store = RuleStore(default_rules())
    store.move(2, "up")
    assert [r.id for r in store.rules][:2] == [2, 1]
