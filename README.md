# AI-Driven Network IDS, Fault Diagnosis and Automated Response (Mininet + Wireshark)

> **This project now also has a real-time, 80-host dynamic layer**: a full network (4 routers, 8
> switches, 10 hosts/switch) with real external hosts (you, a friend) able to join, a live animated
> diagram, a traffic injection panel (normal/known-attack/custom/unknown), a contention/"traffic"
> dataset, a scheduler + response window for requests reaching your own host, and automatic retraining.
> See **HOW_TO_RUN_DYNAMIC.md** for the full guide to that part; the rest of this README (below) covers
> the original, smaller 4-host IDS/fault-diagnosis build that it's layered on top of. New modules:
> `netplan.py`, `realnet_controller.py`, `sniffer.py`, `flowtracker.py`, `netmonitor.py`, `netroutes.py`,
> `datasets.py`, `kdd_loader.py`, `injection.py`, `scheduler.py`, `auto_train.py`, `dynamicroutes.py`.

## Folder layout
```
ids_project/
├── app.py                 Flask back end: auth, pages, all APIs
├── config.py  db.py       settings, SQLite schema/helpers
├── monitor.py             live loop: tshark window -> features -> detector -> DB -> auto-block
├── feature_extractor.py   tshark capture + 36 packet-level features (same code for training and live)
├── detector.py            rules + ML agreement, threat score, key drivers, fault root-cause table
├── response_engine.py     block / unblock (iptables on h3 via lab API), whitelist, expiry
├── lab_controller.py      Mininet topology + control API (attacks, faults, normal traffic, block)
├── collect_data.py        auto-labelled dataset builder  -> data/flows.csv
├── train_models.py        Model B (live flows)  -> models/
├── train_nslkdd.py        Model A (NSL-KDD)     -> models/nsl/
├── nslkdd_model.py        Model A runtime: manual 12-field + CSV prediction
├── templates/             base, home, login, register, dashboard, lab, capture, monitor,
│                          faults, predict, upload, reports, blocked, admin
├── static/css, static/js  style.css, app.js (fetch helper with CSRF, charts, tabs)
├── data/ models/ captures/ generated files (db, csv, pkl, pcap)
├── requirements.txt  HOW_TO_RUN.txt
```

## Pages and what the buttons do
| Page | Role | Buttons -> function |
|---|---|---|
| Home | all | Login / Register |
| Register / Login | all | Register (first user = admin, password hashed); Login (5 tries/min limit) |
| Dashboard | user | auto-refresh cards, traffic line, distribution donut, recent detections, PDF link |
| Lab | admin | Start/Stop Topology (needs sudo); Reset; Start/Stop Normal Traffic; Launch/Stop Attack (syn/udp/icmp flood, port scan, brute force); Inject Fault (dns_down/up, nxdomain, web_down/up, missing_page, loss, drop) |
| Capture | admin | Start Capture (tshark -> .pcap); file list; View with Wireshark display filter; Download for Wireshark GUI |
| Live Monitor | user (admin controls) | Start/Stop Monitoring; verdict banner; evidence, cause, fix, key drivers; Block Source; Ignore; Download PDF |
| Fault Diagnosis | user (admin runs) | Run Diagnosis (captures one window); manual fault form (DNS/TCP/HTTP/RTT/loss); history; error catalogue; Export CSV |
| Prediction | user | 1-click scenarios; choose RF/DT/KNN; Execute Intrusion Analysis; Reset; threat score, iptables suggestion, drivers, PDF |
| CSV Upload | user | NSL-KDD rows (Model A) or lab window features (Model B); Start Analysis; Export Results |
| Reports | user | filters (category, label, source, dates, IP); stats; chart; pagination; Export Full CSV; per-row PDF |
| Blocked IPs | user (admin acts) | Block manually; Unblock; whitelist and history |
| Admin | admin | upload kdd_train.csv + preview + Train A; Train B; performance tables/charts; user roles/delete; settings (interface, window, auto-block, threshold, TTL, whitelist) |

## Detection logic
`window features -> Model B probability + rule check -> agree: high confidence | disagree: needs_review -> threat score (0-100) -> optional auto-block`
Attacks take priority over faults (a SYN flood also causes timeouts). Faults: dns_nxdomain, dns_down, conn_refused, conn_timeout, http_404, http_5xx, high_latency_loss.

## Security measures built in
CSRF tokens on every POST, hashed passwords, login rate limit, role checks on every admin API, input validation (IPs, interface names, setting ranges, form ranges), no shell with user text (argv lists only), pcap path traversal guard, CSV-injection guard on export, secrets from a generated key file, auto-block only with ML+rule agreement, whitelist and expiry.

## Known limits (state these in your report)
- Accuracy on NSL-KDD or on your own lab data is measured on a split of the same data; collect a second run on another day to test honestly.
- HTTPS hides HTTP status codes; 404/5xx detection works on plain HTTP (lab) or from server logs.
- Model A uses 12 inputs and fills 29 features with dataset medians.
- Mininet traffic is cleaner than the real internet; thresholds in detector.py need tuning on your captures.
- `http_5xx` has no collector scenario (the simple Python server cannot return 500); add one if you want that class trained.
