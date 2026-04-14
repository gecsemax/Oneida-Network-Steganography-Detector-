```markdown
# Oneida v4.2 – Network Steganography Detector


> A high-performance, 12-channel network covert channel detector written in C.  
> Designed for live traffic analysis and PCAP replay on Linux and macOS.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Detection Channels](#detection-channels)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Build](#build)
- [Usage](#usage)
- [Output Formats](#output-formats)
- [Configuration Reference](#configuration-reference)
- [Signals](#signals)
- [Performance Tuning](#performance-tuning)
- [Version History](#version-history)
- [License](#license)

---

## Overview

**Oneida** passively monitors network traffic and scores every TCP, UDP, and ICMP flow across 12 independent statistical channels. When the weighted composite score of a flow exceeds a configurable threshold, an alert is emitted — either as human-readable text or as a JSON record suitable for SIEM ingestion.

Oneida detects:

- **Timing-based covert channels** — inter-packet delay modulation
- **Size-based covert channels** — fixed or patterned packet lengths
- **Header covert channels** — TCP flag abuse, TTL manipulation, IP-ID modulation
- **DNS tunnels** — iodine, dnscat2, dns2tcp (label encoding + query rate + record type)
- **Payload covert channels** — high-entropy payloads hidden inside normal-looking flows
- **Burst-pattern channels** — timer-driven injectors with regular IPD spacing
- **Directional covert channels** — extreme traffic asymmetry

---

## How It Works

```
NIC / PCAP file
      │
      ▼
┌─────────────┐    memcpy    ┌──────────────────────┐
│ pcap_loop   │ ──────────► │  Lock-free ring buffer│  65 536 slots
│ (capture    │              │  (SPSC, atomic head/  │  64 MB kernel ring
│  thread)    │              │   tail)               │
└─────────────┘              └──────────┬───────────┘
                                        │ sem_post (capped)
                                        ▼
                             ┌──────────────────────┐
                             │   Worker thread       │
                             │  process_one()        │
                             │  ├─ parse_packet()    │
                             │  ├─ flow lookup/alloc │  per-bucket rwlock
                             │  ├─ retrans check     │  O(1) SEQ hash set
                             │  ├─ DNS decode        │
                             │  ├─ window slot write │  256-slot circular
                             │  ├─ compute_scores()  │  dirty flag / N=64
                             │  └─ emit_alert()      │
                             └──────────────────────┘
                                        │
                             ┌──────────▼───────────┐
                             │   Cleanup thread      │  every 30 s
                             │   expires idle flows  │  safe lock ordering
                             └──────────────────────┘
```

Each flow is tracked using a bidirectional canonical key (`min(src,dst)` always first), so `A→B` and `B→A` packets update the same flow record. A pre-allocated slab pool of 32 768 flow structs avoids dynamic allocation on the hot path.

---

## Detection Channels

| Ch | Name | What it measures | Suspicious pattern |
|----|------|------------------|--------------------|
| 0 | **IPD CoV** | Inter-packet delay Coefficient of Variation | CoV < 0.10 → timer-driven (score 0.85) |
| 1 | **Length Std Dev** | Standard deviation of packet lengths | Std < 2.0 → fixed-size encoding (score 0.85) |
| 2 | **Protocol Entropy** | Shannon entropy of L4 protocol field | Unexpected protocol diversity |
| 3 | **TCP Flag Entropy** | Entropy of observed TCP flag combinations | Unusual flag patterns / covert flag abuse |
| 4 | **SEQ Variance** | Variance of TCP sequence numbers | Low variance = suspiciously predictable SEQ |
| 5 | **IP-ID Delta** | Delta between consecutive IP Identification fields | Static or tiny-range modulation = covert channel |
| 6 | **Window Variance** | TCP receive window size variance | Constant window = possible encoding |
| 7 | **TTL Variance** | Variance of IP Time-To-Live values | High variance = TTL manipulation |
| 8 | **Payload Entropy + DNS** | Shannon entropy of payload bytes; DNS tunnel heuristics | High entropy = encrypted carrier; DNS rate/charset/type |
| 9 | **Directional Asymmetry** | `|bytes_fwd/total − 0.5| × 2` | > 0.85 → one-way-only flow |
| 10 | **Burst Regularity** | CoV of inter-packet delays (burst view) | CoV < 0.10 → equal-spacing = timer injector |
| 11 | **Retransmit Rate** | Retransmissions / total packets | Unusually high retransmit rate |

### Weighted Composite Score

```text
score = Σ(channel_score[i] × weight[i]) / Σ(weight[i])
```

Default weights: Timing×2, Length×2, Flags×1.5, Payload×2, Burst×2, Asymmetry×1.5, IP-ID×1.5, rest×1.

Alert fires when `score > threshold` (default **0.45**) after at least 30 packets, with per-flow cooldown (default **5 s**).

---

### DNS Tunnel Detection (Ch 8 sub-scorer)

Oneida decodes DNS query names from UDP port 53 traffic and applies four independent heuristics:

| Heuristic | Score contribution | Targets |
|-----------|-------------------|---------|
| Query rate > 10/10 s | +0.40 | All tunnels |
| TXT or NULL record type | +0.30 | iodine, dnscat2 |
| Base32/Base64 charset in label | +0.35 | iodine, dns2tcp |
| Label length > 40 chars | +0.25 | All tunnels |

DNS score replaces the payload entropy score when higher.

---

### IP-ID Covert Channel (Ch 5)

| Delta pattern | Score | Interpretation |
|--------------|-------|----------------|
| Std < 1.0 (static) | 0.55 | ID frozen — deliberate hiding |
| Std < 8, mean < 8 | 0.60 | Tiny-range modulation |
| Std < 3, mean 0.5–5 | 0.10 | Normal kernel counter |
| Otherwise | 0.05 | Randomised (modern OS) |

---

## Architecture

### Threading Model

| Thread | Role | CPU pin flag |
|--------|------|-------------|
| Main / pcap | `pcap_loop`, `capture_callback` | (default) |
| Worker | Dequeues ring, runs scoring pipeline | `-W <core>` |
| Cleanup | Expires idle/old flows every 30 s | `-C <core>` |

### Flow Table

- **8 192 hash buckets**, each with a `pthread_rwlock_t`
- Lookups (hot path) take only a **read lock** on one bucket
- Double-check on write-lock insertion (no TOCTOU race)
- Per-flow `pthread_mutex_t` for slot writes and scoring
- **Safe cleanup:** bucket write-lock is released before taking the per-flow mutex to avoid deadlocks

### Memory

- **Pre-allocated slab pool** of 32 768 `flow_t` structs
- Zero dynamic allocation after startup
- Pool uses `uint32_t` free-list counters (safe for long runs)

### Ring Buffer

- **65 536 slots**, single-producer/single-consumer
- Lock-free head/tail with atomics
- `sem_post` is **capped** with `sem_getvalue` — no semaphore runaway at high PPS
- 64 MB kernel ring buffer via `pcap_set_buffer_size`

---

## Requirements

| Dependency | Version | Notes |
|-----------|---------|-------|
| `libpcap` | ≥ 1.5 | `libpcap-dev` / `libpcap-devel` |
| GCC or Clang | GCC ≥ 9, Clang ≥ 11 | C11 required |
| Linux kernel | ≥ 3.10 | `AF_PACKET`, CPU affinity |
| macOS | ≥ 10.15 | BPF, no CPU affinity |

```bash
# Debian / Ubuntu
sudo apt install libpcap-dev gcc make

# RHEL / Fedora
sudo dnf install libpcap-devel gcc make

# macOS
brew install libpcap
```

---

## Build

```bash
# Standard build
gcc -O2 -std=c11 -Wall -Wextra -o oneida oneida.c -lpcap -lm -lpthread

# Compile-time overrides
gcc -O2 -std=c11 -DMAX_FLOWS=65536 -DWINDOW_SIZE=512 \
    -o oneida oneida.c -lpcap -lm -lpthread

# Debug build
gcc -O0 -g -fsanitize=address,undefined -std=c11 \
    -o oneida_dbg oneida.c -lpcap -lm -lpthread
```

---

## Usage

### Live capture (root required)

```bash
sudo ./oneida eth0
sudo ./oneida enp3s0
```

### PCAP file replay

```bash
./oneida capture.pcap
./oneida capture.pcapng
```

### Common options

```bash
# Lower threshold (more sensitive), 10 s cooldown
sudo ./oneida -t 0.35 -a 10 eth0

# Nanosecond timestamps, verbose
sudo ./oneida -n -v eth0

# JSON output, pipe to jq
sudo ./oneida -j eth0 | jq 'select(.score > 0.6)'

# Pin threads, disable promiscuous mode
sudo ./oneida -W 2 -C 3 -p eth0

# Full options
sudo ./oneida -t 0.40 -a 5 -i 120 -l 1800 -n -v -W 2 -C 3 eth0
```

---

## Output Formats

### Plain text (default)

```text
🚨 STEG ALERT [0.623] 10.0.0.5:54321 -> 8.8.8.8:53 | UDP | pkts=412 frags=0 icmp=0
  Timing=0.85 Len=0.85 Flags=0.05 Payload=0.75 Burst=0.85 Asym=0.25 TTL=0.05 Retrans=0.05
  DNS tunnel score=0.70 qrate=14 txt/null=3 b32b64=5
```

### JSON (`-j`)

```json
{
  "alert": true,
  "score": 0.6231,
  "flow_id": "a3f2c1d490e87b12",
  "src": "10.0.0.5",
  "dst": "8.8.8.8",
  "sport": 54321,
  "dport": 53,
  "proto": "UDP",
  "pkts": 412,
  "bytes_fwd": 38204,
  "bytes_rev": 12800,
  "frags": 0,
  "icmp": 0,
  "dns_score": 0.700,
  "ipid_var": 0.000,
  "ch": [0.850, 0.850, 0.050, 0.050, 0.100, 0.050,
         0.100, 0.050, 0.750, 0.250, 0.850, 0.050]
}
```

### SIEM integration

```bash
# Write to file
sudo ./oneida -j eth0 >> /var/log/oneida/alerts.jsonl

# Pipe to Elasticsearch
sudo ./oneida -j eth0 | \
  while read line; do
    curl -s -X POST "http://localhost:9200/oneida/_doc" \
         -H 'Content-Type: application/json' -d "$line" > /dev/null
  done
```

---

## Configuration Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-t <float>` | `0.45` | Alert threshold (0.0–1.0) |
| `-a <sec>` | `5` | Per-flow alert cooldown seconds |
| `-i <sec>` | `300` | Idle flow expiry seconds |
| `-l <sec>` | `3600` | Maximum flow lifetime seconds |
| `-j` | off | JSON output mode |
| `-p` | off | Disable promiscuous mode |
| `-n` | off | Nanosecond timestamp precision |
| `-W <core>` | off | Pin worker thread to CPU core N |
| `-C <core>` | off | Pin cleanup thread to CPU core N |
| `-v` | off | Verbose: print feature values on alert |
| `-h` | — | Print help and exit |

### Compile-time constants

| Macro | Default | Description |
|-------|---------|-------------|
| `MAX_FLOWS` | 32768 | Maximum concurrent tracked flows |
| `FLOW_HASH_SIZE` | 8192 | Hash table buckets (power of 2) |
| `WINDOW_SIZE` | 256 | Sliding window packets per flow |
| `RING_CAPACITY` | 65536 | Ring buffer slots (power of 2) |
| `KERNEL_RING_BYTES` | 64 MB | libpcap kernel ring buffer size |
| `RESCORE_INTERVAL` | 64 | Re-score every N packets |
| `DNS_RATE_THRESH` | 10 | DNS queries/10 s to flag as tunnel |

---

## Signals

| Signal | Effect |
|--------|--------|
| `SIGINT` / `SIGTERM` | Graceful shutdown, drain ring, print stats |
| `SIGUSR1` | Print live stats without interrupting capture |

```bash
# Live stats
kill -USR1 $(pgrep oneida)

# Example output
[stats] active_flows=1423 dropped=0 alerts=7
```

---

## Performance Tuning

### High-traffic environments (> 1 Mpps)

```bash
# Pin threads to isolated cores
sudo ./oneida -W 4 -C 5 eth0

# Increase flow table at compile time
gcc -O3 -DMAX_FLOWS=131072 -DFLOW_HASH_SIZE=32768 \
    -o oneida oneida.c -lpcap -lm -lpthread

# Use AF_PACKET ring (Linux)
sudo ethtool -G eth0 rx 4096

# Increase socket buffer
sudo sysctl -w net.core.rmem_max=134217728
```

### Low-latency PCAP replay

```bash
./oneida -n -t 0.35 large_capture.pcapng
```

### Threshold tuning guide

| Environment | Recommended `-t` |
|-------------|-----------------|
| Lab / testing | 0.35 |
| Corporate LAN | 0.45 (default) |
| Internet-facing | 0.55 |
| High-noise datacenter | 0.65 |

---

## Version History

| Version | Key changes |
|---------|-------------|
| **v4.2** | TTL direction fix, slot_valid usage, deadlock fix, uint32_t pool counters, stat() detection, capped sem_post, ICMP support, dirty-flag rescoring, SIGUSR1 stats, IP-ID channel, DNS tunnel charset/rate/type, alert counter |
| **v4.1** | Flag entropy direction, stale score reset, retrans before slot write, O(1) SEQ hash set, semaphore-driven worker, slab pool, 64 MB kernel ring, per-flow alert cooldown, nanosecond timestamps, IPv4 fragment detection |
| **v4.0** | Per-bucket rwlocks, lock-free SPSC ring, CPU affinity, bidirectional flow keys, CoV-based IPD, payload entropy, burst regularity, directional asymmetry, TCP retransmit rate |

---

## Known Limitations

- **IPv4 only** — IPv6 packets are silently dropped at the parser
- **Single worker thread** — scoring is single-threaded; at very high PPS consider sharding by flow hash range
- **No persistence** — flow state is in-memory only; a restart clears all flow history
- **Encrypted traffic** — high-entropy payloads from TLS/QUIC may produce elevated Ch 8 scores on legitimate flows; tune threshold accordingly
- **Fragmented flows** — reassembly is not implemented; fragments increment a counter but are excluded from feature scoring

---

## License

MIT License — see `LICENSE` for details.

```text
Copyright (c) 2026 Max Gecse
```
```

