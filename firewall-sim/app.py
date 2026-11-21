"""
app.py - Flask glue. It wires the pieces together and exposes them as a JSON API.

  browser  <-->  Flask routes  <-->  packets.py (Scapy) -> engine.py (decision) -> logger.py

Run:  python app.py     then open http://127.0.0.1:5000
"""
import os
import tempfile

from flask import Flask, jsonify, render_template, request

from firewall import packets
from firewall.engine import evaluate, find_shadowed
from firewall.logger import DecisionLog
from firewall.rules import RuleStore, default_rules

app = Flask(__name__)
store = RuleStore(default_rules())   # the ordered rule list
log = DecisionLog()                  # every decision ever made
DEFAULT_POLICY = "BLOCK"             # default-deny


def process(pkt: dict) -> dict:
    """The whole pipeline for one parsed packet: decide, log, return."""
    decision = evaluate(pkt, store.rules, DEFAULT_POLICY)
    log.add(pkt, decision)
    return decision


@app.errorhandler(ValueError)
def bad_input(err):
    return jsonify(error=str(err)), 400


@app.get("/")
def index():
    return render_template("index.html")


# ---------------- rules ----------------
@app.get("/api/rules")
def list_rules():
    shadowed = find_shadowed(store.rules)
    rules = [dict(r.to_dict(), shadowed_by=shadowed.get(r.id)) for r in store.rules]
    return jsonify(rules=rules, default_policy=DEFAULT_POLICY)


@app.post("/api/rules")
def add_rule():
    rule = store.add(request.get_json(force=True))
    return jsonify(rule.to_dict()), 201


@app.delete("/api/rules/<int:rule_id>")
def delete_rule(rule_id):
    return ("", 204) if store.delete(rule_id) else (jsonify(error="No such rule"), 404)


@app.post("/api/rules/<int:rule_id>/move")
def move_rule(rule_id):
    direction = request.get_json(force=True).get("direction")
    if direction not in ("up", "down") or not store.move(rule_id, direction):
        return jsonify(error="Cannot move that rule"), 400
    return ("", 204)


# ---------------- simulation ----------------
@app.post("/api/simulate")
def simulate():
    """Form values -> real Scapy packet -> parse back to a dict -> firewall decision."""
    d = request.get_json(force=True)
    proto = str(d.get("proto", "TCP")).upper()
    port = int(d["dport"]) if d.get("dport") not in (None, "") and proto != "ICMP" else None
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    try:
        scapy_pkt = packets.build(d.get("src", ""), d.get("dst", ""), proto, port)
    except Exception:
        raise ValueError("Source and destination must be valid IPv4 addresses.")
    pkt = packets.parse(scapy_pkt)
    decision = process(pkt)
    return jsonify(packet=pkt, scapy=scapy_pkt.summary(), **decision)


@app.post("/api/generate")
def generate():
    count = max(1, min(int((request.get_json(silent=True) or {}).get("count", 20)), 200))
    results = [process(packets.random_packet()) for _ in range(count)]
    return jsonify(count=count, blocked=sum(r["verdict"] == "BLOCK" for r in results))


@app.post("/api/pcap")
def replay_pcap():
    """Upload a .pcap file; every IP packet inside is run through the firewall."""
    upload = request.files.get("file")
    if not upload:
        raise ValueError("Choose a .pcap file first.")
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        upload.save(tmp.name)
    try:
        parsed = packets.read_pcap(tmp.name)
    except Exception:
        raise ValueError("That file could not be read as a pcap.")
    finally:
        os.unlink(tmp.name)
    results = [process(p) for p in parsed]
    return jsonify(count=len(results), blocked=sum(r["verdict"] == "BLOCK" for r in results))


# ---------------- logs & stats ----------------
@app.get("/api/logs")
def logs():
    q = request.args
    return jsonify(logs=log.query(q.get("verdict"), q.get("proto"), q.get("src")))


@app.post("/api/logs/clear")
def clear_logs():
    log.clear()
    return ("", 204)


@app.get("/api/stats")
def stats():
    return jsonify(log.stats())


if __name__ == "__main__":
    app.run(debug=True)
