# Firewall Simulator

A small web app that shows **what a firewall would block, and why**. Built with Python, Scapy and Flask.
It never touches your real network: it only *decides* what would happen to each packet.

```
Scapy packet  ->  parse()  ->  evaluate(rules)  ->  log  ->  Flask API  ->  browser
 (packets.py)    (packets.py)    (engine.py)     (logger.py)  (app.py)    (templates/static)
```

## Run it

**Windows (PowerShell):** run the lines one at a time.
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```
If activation says scripts are disabled, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first.
If `python` is not found, use `py` instead.

**Mac / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000 in your browser.

Other commands:
```
pytest                       # run the tests
python make_sample_pcap.py   # optional: creates sample.pcap to replay in the UI
```

---

# Notes: the concepts, in plain language

## 1. What is a firewall?
A firewall is a **bouncer with a list**. Each packet arrives, the bouncer checks the list, and the answer is
`ALLOW` or `BLOCK`. In code, it is one function:

```
decide(packet) -> (ALLOW | BLOCK, reason)
```

## 2. What is a packet?
Data on a network travels in small chunks called packets. A firewall only needs the *headers* (the label on the envelope):

| Field | Example | Meaning |
|---|---|---|
| Source IP | `45.33.32.156` | who sent it |
| Destination IP | `192.168.1.50` | who it is for |
| Protocol | `TCP` | the "language": TCP (reliable), UDP (fast), ICMP (ping) |
| Destination port | `22` | which service on the target (22=SSH, 80=HTTP, 443=HTTPS, 53=DNS, 23=Telnet) |

ICMP (ping) has **no port**, which is why a rule with a port never matches ICMP.

## 3. What is Scapy for?
Scapy builds and reads real packets. Layers stack with `/`:

```python
IP(src="1.2.3.4", dst="5.6.7.8") / TCP(dport=22)
```

We use it to (a) build a real packet from your form input, (b) parse it back into the four fields above,
(c) read `.pcap` files recorded by tools like Wireshark. **Only `packets.py` imports Scapy**, so the rest of the code stays simple.

## 4. What is a rule?
A rule is: *"if the packet looks like THIS, do THAT."*

```
BLOCK   TCP   port 22   from any   to any      "Block SSH from everyone else"
```

`any` means "I don't care". A rule matches only if **every** condition matches.

## 5. CIDR: matching a whole range of IPs
`192.168.1.0/24` means "every address from 192.168.1.0 to 192.168.1.255". The `/24` says the first 24 bits (the first three numbers) are fixed.
Python's `ipaddress` module does the work: `ip_address("192.168.1.9") in ip_network("192.168.1.0/24")` is `True`.

## 6. First match wins (the most important idea)
The engine reads rules **top to bottom** and stops at the first match.

```
1. ALLOW  TCP 22 from 192.168.1.0/24     <- office LAN may SSH
2. BLOCK  TCP 22 from any                <- everyone else may not
```

Swap them and the LAN is locked out too, because rule 2 matches first. **Order is part of the policy.**
Try it in the UI: use the arrows to reorder, then re-send the "SSH from the LAN" example.

## 7. Default policy
If no rule matches, the default applies. We use **default-deny (BLOCK)**: anything not explicitly allowed is dropped.
It is safer than default-allow, because forgetting a rule fails *closed* instead of *open*.

## 8. Shadowed rules (dead rules)
If an earlier rule already catches everything a later rule would, the later rule can never fire.
`find_shadowed()` in `engine.py` detects this and the UI shows "Never reached". Example: a `BLOCK TCP` (any port)
placed above `ALLOW TCP 443` makes the HTTPS rule dead.

## 9. Why "simulate" instead of really blocking?
Real enforcement needs root/admin and kernel hooks (iptables, nftables, NFQUEUE), and a mistake can lock you out of your own machine.
A simulator teaches the same logic with zero risk. The decision function is identical; only the last step (dropping the packet) is missing.

---

# How the code maps to the concepts

| File | Concept | Read it to learn |
|---|---|---|
| `firewall/rules.py` | Rule, matching, CIDR, validation, ordered list | sections 4, 5 |
| `firewall/engine.py` | `evaluate()`, first-match-wins, default policy, shadow detection | sections 6, 7, 8 |
| `firewall/packets.py` | Scapy build / parse / pcap / random traffic | sections 2, 3 |
| `firewall/logger.py` | Decision log and statistics | the "why" history |
| `app.py` | Flask routes that connect everything | the API below |
| `templates/`, `static/` | The dashboard | the rule-chain "walk" |
| `tests/test_engine.py` | Proof that each concept works | run `pytest` |

**Suggested reading order:** `rules.py` -> `engine.py` -> `tests/test_engine.py` -> `packets.py` -> `app.py` -> `static/app.js`.

## What happens when you click "Send packet"
1. Browser sends `{src, dst, proto, dport}` to `POST /api/simulate`.
2. `packets.build()` makes a real Scapy packet; `packets.parse()` turns it back into a dict.
3. `engine.evaluate()` walks the rules and returns verdict, rule id, reason, and which rules it checked.
4. `logger.add()` records it.
5. The page colors the rule chain: matched rule highlighted, checked rules dimmed, rules below the match faded.

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/rules` | list rules (with `shadowed_by` warnings) |
| `POST /api/rules` | add a rule |
| `DELETE /api/rules/<id>` | delete a rule |
| `POST /api/rules/<id>/move` | `{"direction": "up"|"down"}` |
| `POST /api/simulate` | test one packet |
| `POST /api/generate` | run N random packets |
| `POST /api/pcap` | upload a pcap and replay it |
| `GET /api/logs?verdict=&proto=&src=` | filtered log |
| `GET /api/stats` | totals, top blocked ports/sources, hits per rule |

---

# Project structure

```
firewall-sim/
|-- app.py                  Flask routes (the API)
|-- firewall/
|   |-- rules.py            Rule class, matching, validation, rule list
|   |-- engine.py           evaluate() and shadowed-rule detection
|   |-- packets.py          Scapy: build, parse, read pcap, random traffic
|   `-- logger.py           decision log and stats
|-- templates/index.html    dashboard page
|-- static/                 style.css and app.js
|-- docs/monitor.html       standalone live monitoring page (open it in a browser)
|-- tests/test_engine.py    pytest tests
|-- make_sample_pcap.py     creates sample.pcap
|-- requirements.txt
`-- README.md
```

# Live monitoring page

`docs/monitor.html` is a single file that needs no server. Double-click it to open it in your browser.
It simulates traffic every second and shows: totals, a 30-second traffic chart, port-scan alerts,
a live log with the reason for each decision, top blocked ports and sources, and decisions per rule.
Press **Simulate port scan** to see an alert appear.

What to monitor in a real firewall:
- a sudden jump in the block rate (scan, attack, or a rule changed by mistake)
- one source blocked on many ports in a short time (port scan)
- blocked ports 22, 23 and 3389 (probing for remote access)
- rules with zero hits (dead rules) or far more hits than the rest

# Put it on GitHub

```
git init
git branch -M main
git add .
git commit -m "Initial commit: firewall simulator"
git remote add origin https://github.com/YOUR-USERNAME/firewall-sim.git
git push -u origin main
```
Create an empty repository on GitHub first, with no README, .gitignore or license ticked.
To publish the monitor page for free, copy `docs/monitor.html` to `docs/index.html`, then in GitHub open
Settings, then Pages, choose the `main` branch and the `/docs` folder.

---

# Exercises (do these to really learn it)

1. Send "SSH from the internet". Which rule blocks it? Why did the engine not stop at rule 5?
2. Move rule 6 (Block SSH) **above** rule 5. Re-send "SSH from the LAN". What changed, and why?
3. Add `BLOCK TCP any port` at the top. Which rules now show "Never reached"?
4. Send "HTTPS from a bad network". Why is it blocked even though HTTPS is allowed? (Hint: rule order.)
5. Generate 20 random packets and check "Decisions per rule". Which rule works hardest? Which never fires?
6. Write a new pytest for a rule you invented.

# Stretch ideas
- **Stateful tracking:** allow replies to connections that started inside (a table of active connections).
- **Port-scan detection:** flag one source hitting many ports quickly.
- **SQLite log** so history survives restarts.
- **Import/export rules** as JSON.
- **Source-port and TCP-flag matching**, or **IPv6**.
- **Real enforcement on Linux** with `NetfilterQueue` (advanced, root only).

# Limitations (honest notes)
Stateless only, IPv4 only, state lives in memory, and rules reset when the app restarts.
