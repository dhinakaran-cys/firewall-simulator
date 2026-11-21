"""
rules.py - WHAT a rule is, and where the rules live.

A firewall rule is a sentence:  "If a packet looks like THIS, then do THAT."
  - THIS  = match conditions (source IP, destination IP, protocol, port)
  - THAT  = action (ALLOW or BLOCK)

A condition left as "any" (or None for the port) means "don't care".
"""
from dataclasses import dataclass, asdict
import ipaddress

VALID_ACTIONS = ("ALLOW", "BLOCK")
VALID_PROTOCOLS = ("any", "TCP", "UDP", "ICMP")


def _network(value):
    """Turn '192.168.1.0/24' or '8.8.8.8' into an ip_network object.
    A single address becomes a /32 network (a network containing just that one IP)."""
    return ipaddress.ip_network(value, strict=False)


@dataclass
class Rule:
    id: int
    action: str                  # "ALLOW" or "BLOCK"
    src_ip: str = "any"          # "any", "10.0.0.5", or CIDR like "192.168.1.0/24"
    dst_ip: str = "any"
    protocol: str = "any"        # "any", "TCP", "UDP", "ICMP"
    dst_port: int | None = None  # None = any port
    description: str = ""

    # ---- matching -------------------------------------------------------
    def matches(self, pkt: dict) -> bool:
        """Return True only if EVERY condition in the rule matches the packet.
        One failed condition is enough to say 'this rule does not apply'."""
        if self.protocol != "any" and self.protocol != pkt["proto"]:
            return False
        # ICMP packets have no port, so a rule that demands a port can't match them.
        if self.dst_port is not None and self.dst_port != pkt["dport"]:
            return False
        if self.src_ip != "any" and ipaddress.ip_address(pkt["src"]) not in _network(self.src_ip):
            return False
        if self.dst_ip != "any" and ipaddress.ip_address(pkt["dst"]) not in _network(self.dst_ip):
            return False
        return True

    # ---- human-readable text (used in the "why" explanation) ------------
    def summary(self) -> str:
        proto = "any protocol" if self.protocol == "any" else self.protocol
        port = "" if self.dst_port is None else f" port {self.dst_port}"
        return f"{proto}{port} from {self.src_ip} to {self.dst_ip}"

    def to_dict(self) -> dict:
        return asdict(self)

    # ---- validation (never trust data coming from a web form) -----------
    @classmethod
    def from_input(cls, rule_id: int, data: dict) -> "Rule":
        action = str(data.get("action", "")).upper()
        if action not in VALID_ACTIONS:
            raise ValueError("Action must be ALLOW or BLOCK.")

        protocol = str(data.get("protocol") or "any")
        protocol = "any" if protocol.lower() == "any" else protocol.upper()
        if protocol not in VALID_PROTOCOLS:
            raise ValueError("Protocol must be any, TCP, UDP or ICMP.")

        ips = {}
        for field in ("src_ip", "dst_ip"):
            value = str(data.get(field) or "any").strip()
            if value.lower() != "any":
                try:
                    _network(value)
                except ValueError:
                    raise ValueError(f"'{value}' is not a valid IP or CIDR range.")
            ips[field] = "any" if value.lower() == "any" else value

        port = data.get("dst_port")
        port = None if port in (None, "", "any") else int(port)
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")
        if port is not None and protocol == "ICMP":
            raise ValueError("ICMP has no ports. Leave the port empty.")

        return cls(rule_id, action, ips["src_ip"], ips["dst_ip"], protocol, port,
                   str(data.get("description", "")).strip()[:120])


class RuleStore:
    """Holds the ORDERED list of rules. Order matters: first match wins."""

    def __init__(self, rules=None):
        self.rules: list[Rule] = list(rules or [])
        self._next_id = max((r.id for r in self.rules), default=0) + 1

    def add(self, data: dict) -> Rule:
        rule = Rule.from_input(self._next_id, data)
        self._next_id += 1
        self.rules.append(rule)          # new rules go to the bottom of the list
        return rule

    def delete(self, rule_id: int) -> bool:
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.id != rule_id]
        return len(self.rules) < before

    def move(self, rule_id: int, direction: str) -> bool:
        """Swap a rule with its neighbour. Moving a rule changes the firewall's behaviour!"""
        i = next((n for n, r in enumerate(self.rules) if r.id == rule_id), None)
        if i is None:
            return False
        j = i - 1 if direction == "up" else i + 1
        if 0 <= j < len(self.rules):
            self.rules[i], self.rules[j] = self.rules[j], self.rules[i]
        return True


def default_rules() -> list[Rule]:
    """A small, realistic starter policy. Read it top to bottom, like the engine does."""
    return [
        Rule(1, "BLOCK", src_ip="203.0.113.0/24", description="Known-bad network (blocklist goes FIRST)"),
        Rule(2, "ALLOW", protocol="TCP", dst_port=443, description="Allow HTTPS"),
        Rule(3, "ALLOW", protocol="TCP", dst_port=80, description="Allow HTTP"),
        Rule(4, "ALLOW", protocol="UDP", dst_port=53, description="Allow DNS lookups"),
        Rule(5, "ALLOW", src_ip="192.168.1.0/24", protocol="TCP", dst_port=22,
             description="Allow SSH from the office LAN only"),
        Rule(6, "BLOCK", protocol="TCP", dst_port=22, description="Block SSH from everyone else"),
        Rule(7, "BLOCK", protocol="TCP", dst_port=23, description="Block Telnet (insecure)"),
        Rule(8, "ALLOW", src_ip="192.168.1.0/24", protocol="ICMP", description="Allow ping from the LAN"),
    ]
