"""
logger.py - remembers every decision so the dashboard can show what was blocked and WHY.
Kept in memory (a bounded deque). Swap for SQLite later if you want history to survive restarts.
"""
from collections import Counter, deque
from datetime import datetime


class DecisionLog:
    def __init__(self, max_entries=1000):
        self.entries = deque(maxlen=max_entries)  # oldest entries fall off automatically

    def add(self, pkt: dict, decision: dict) -> dict:
        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "src": pkt["src"], "dst": pkt["dst"],
            "proto": pkt["proto"], "dport": pkt["dport"],
            "verdict": decision["verdict"],
            "rule_id": decision["rule_id"],
            "reason": decision["reason"],
        }
        self.entries.append(entry)
        return entry

    def query(self, verdict=None, proto=None, src=None, limit=200) -> list:
        rows = list(self.entries)[::-1]  # newest first
        if verdict:
            rows = [r for r in rows if r["verdict"] == verdict.upper()]
        if proto:
            rows = [r for r in rows if r["proto"] == proto.upper()]
        if src:
            rows = [r for r in rows if r["src"].startswith(src)]
        return rows[:limit]

    def clear(self):
        self.entries.clear()

    def stats(self) -> dict:
        rows = list(self.entries)
        blocked = [r for r in rows if r["verdict"] == "BLOCK"]
        return {
            "total": len(rows),
            "allowed": len(rows) - len(blocked),
            "blocked": len(blocked),
            "top_blocked_ports": Counter(r["dport"] for r in blocked if r["dport"]).most_common(5),
            "top_blocked_sources": Counter(r["src"] for r in blocked).most_common(5),
            # which rule made the decision most often (None = default policy)
            "rule_hits": Counter(r["rule_id"] for r in rows).most_common(),
        }
