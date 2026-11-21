"""
engine.py - the brain. One function decides every packet.

    evaluate(packet, rules)  ->  verdict + the rule responsible + the reasoning

How it works (this is how iptables / real firewalls behave):
  1. Walk the rules from TOP to BOTTOM.
  2. The FIRST rule that matches decides the verdict. Stop immediately.
  3. If nothing matches, use the DEFAULT POLICY.
     Default-deny (BLOCK) is the secure choice: "if I didn't explicitly allow it, drop it."

This file knows nothing about Scapy or Flask. It only sees plain dicts,
which makes it easy to test and easy to understand.
"""
import ipaddress


def evaluate(pkt: dict, rules: list, default: str = "BLOCK") -> dict:
    checked = []  # rule ids we looked at - the UI uses this to show the "walk"
    for rule in rules:
        checked.append(rule.id)
        if rule.matches(pkt):
            label = f" ({rule.description})" if rule.description else ""
            return {
                "verdict": rule.action,
                "rule_id": rule.id,
                "reason": f"Matched rule #{rule.id}{label}: {rule.summary()}. "
                          f"First match wins, so later rules were not checked.",
                "checked": checked,
            }
    return {
        "verdict": default,
        "rule_id": None,
        "reason": f"No rule matched, so the default policy applies: {default}.",
        "checked": checked,
    }


def _covers(a, b) -> bool:
    """True if rule `a` matches EVERYTHING rule `b` could match (a is at least as broad)."""
    def ip_covers(x, y):
        if x == "any":
            return True
        if y == "any":
            return False
        return ipaddress.ip_network(y, strict=False).subnet_of(ipaddress.ip_network(x, strict=False))

    return (
        (a.protocol == "any" or a.protocol == b.protocol)
        and (a.dst_port is None or a.dst_port == b.dst_port)
        and ip_covers(a.src_ip, b.src_ip)
        and ip_covers(a.dst_ip, b.dst_ip)
    )


def find_shadowed(rules: list) -> dict:
    """Spot 'dead' rules: a rule that can never fire because an earlier rule already
    catches every packet it would catch.   Returns {shadowed_rule_id: earlier_rule_id}."""
    shadowed = {}
    for i, rule in enumerate(rules):
        for earlier in rules[:i]:
            if _covers(earlier, rule):
                shadowed[rule.id] = earlier.id
                break
    return shadowed
