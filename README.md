# 42027 SDN-based Enterprise Network

OpenFlow-based SDN network for an enterprise environment, implemented with Mininet and Ryu.

## Network Topology

```
          Server (10.0.0.11)
              |  1 Gbps
             sw5 ── mgmt (10.0.0.254)
            /    \   10 Mbps
       1Gbps      1Gbps
          /          \
        sw3           sw4
       /   \         /   \
   100M  100M     100M  100M
     /       \   /       \
   sw1        X          sw2
    |       /   \         |
  10Mbps 100M  100M    10Mbps
    |                    |
   h1 (10.0.0.1)     h2 (10.0.0.2)
```

### Host / IP / MAC Table

| Host   | IP             | MAC               |
|--------|---------------|-------------------|
| h1     | 10.0.0.1/24   | 00:00:00:00:00:01 |
| h2     | 10.0.0.2/24   | 00:00:00:00:00:02 |
| mgmt   | 10.0.0.254/24 | 00:00:00:00:00:03 |
| server | 10.0.0.11/24  | 00:00:00:00:00:04 |

### Traffic Paths

- **h1 → server:** h1 – sw1 – sw3 – sw5 – server
- **h2 → server:** h2 – sw2 – sw4 – sw5 – server *(separate core link for traffic engineering)*
- **mgmt → server:** mgmt – sw5 – server

---

## Requirements

- [Mininet](http://mininet.org/) 2.3+
- [Ryu SDN Framework](https://ryu.readthedocs.io/) 4.34+
- Open vSwitch (OVS) with OpenFlow 1.3 support
- Python 3.x
- `iperf` (for traffic generation in B3)

---

## Running

### 1. Start the Ryu controller

```bash
ryu-manager controller.py
```

### 2. Start the Mininet topology (in a separate terminal)

```bash
sudo python3 topology.py
```

STP is enabled automatically on all OVS bridges to prevent forwarding loops.

---

## Controller Overview (`controller.py`)

### Flow Rule Policy (B1)

Flow rules are installed **proactively** when each switch connects, based on full topology knowledge. This avoids the latency and complexity of reactive (packet-in) learning.

| Traffic | Action |
|---------|--------|
| TCP/UDP/ICMP — h1, h2, mgmt ↔ server | Forwarded on the correct port |
| ARP | Flooded (priority 10) |
| Everything else | Dropped (table-miss, priority 0) |

Separate flow entries are used for TCP (`ip_proto=6`), UDP (`ip_proto=17`), and ICMP (`ip_proto=1`) at priority 100.

### Traffic Monitoring on sw5 (B2)

A background daemon thread polls sw5 every **10 seconds** using `OFPFlowStatsRequest`. On each reply:

- TCP and UDP byte/packet counts are stored in `self.flow_stats` — a Python dict keyed by `(ip_src, ip_dst, proto_str)`.
- Each entry is appended to **`stats.csv`** with columns: `timestamp`, `flow_match`, `byte_count`, `packet_count`.

### Traffic Engineering — UDP Rate Limiting (B4)

Controlled by the `ENABLE_B4` flag at the top of `controller.py`:

```python
ENABLE_B4 = True   # True = rate-limit UDP; False = baseline (no TE)
```

When enabled, an OpenFlow **meter** (ID 1, drop band at `UDP_RATE_KBPS = 50000 kbps`) is installed on sw5. All UDP flows on sw5 reference this meter via `OFPInstructionMeter`, capping aggregate UDP throughput at **50 Mbps** and preventing UDP from starving competing TCP flows on the shared 100 Mbps edge links.

To compare before/after:
1. Set `ENABLE_B4 = False` → restart controller → run B3 iperf tests → save `stats.csv`
2. Set `ENABLE_B4 = True` → restart controller → repeat iperf tests → compare CSVs

---

## Traffic Generation (B3)

Run iperf tests from the Mininet CLI after starting both the controller and topology.

### Run 1 — Moderate UDP Load

```
mininet> h1 iperf -c 10.0.0.11 -t 60 &
mininet> h2 sleep 20 && iperf -c 10.0.0.11 -u -b 1M -t 20 &
```

### Run 2 — High UDP Load

```
mininet> h1 iperf -c 10.0.0.11 -t 60 &
mininet> h2 sleep 20 && iperf -c 10.0.0.11 -u -b 2G -t 20 &
```

Use `-i 5` on the iperf server side for per-interval throughput reporting.

---

## File Structure

```
.
├── controller.py   # Ryu application — flow rules, monitoring, traffic engineering
├── topology.py     # Mininet topology — 4 hosts, 5 switches, TCLink with BW/delay
├── stats.csv       # Generated at runtime — per-flow byte/packet counts from sw5
└── README.md
```