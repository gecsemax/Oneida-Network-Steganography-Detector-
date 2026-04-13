# Oneida v4.0 — Network Steganography Detector

A high-performance, single-file C11 tool for **real-time detection of network steganography and covert channels** in IPv4/TCP/UDP traffic. It uses a 12-channel ML-style feature pipeline, a lock-free packet ring buffer, and a per-bucket RW-locked flow hash table to run efficiently on live interfaces or PCAP files.

***

## Features

### Detection Engine

- **12-channel scoring pipeline** — each channel targets a distinct statistical anomaly:

| Ch | Feature | What it detects |
|----|---------|-----------------|
| 0 | IPD Coefficient of Variation | Highly periodic inter-packet timing (timer-driven stego injectors) |
| 1 | Packet length std deviation | Fixed-size packets suggesting hidden payload padding |
| 2 | Protocol entropy | Abnormal protocol distribution within a flow |
| 3 | TCP flag entropy | Unusual or repetitive flag patterns |
| 4 | TCP sequence variance | Low SEQ variability (SEQ-space covert channels) |
| 5 | TCP ACK variance | Low ACK variability (ACK-space covert channels) |
| 6 | TCP window variance | Anomalously stable window sizes |
| 7 | TTL variance | TTL manipulation / spoofed hops |
| 8 | Payload byte entropy | Very high entropy payload → encrypted/compressed carrier |
| 9 | Directional asymmetry | One-way-only flows (exfiltration patterns) |
| 10 | Burst regularity score | Equal-spaced bursts detected via IPD CoV |
| 11 | TCP retransmission rate | Abnormal retransmit rates as secondary covert channel indicator |

- **Weighted composite score** — timing, length, payload entropy, and burst regularity weighted 2×; protocol entropy down-weighted to 0.5×.
- **Graduated scoring curves** — multi-tier curves replace hard binary thresholds (e.g. IPD CoV < 0.10 → 0.85, < 0.25 → 0.55, < 0.50 → 0.25, else → 0.05).
- **Real payload entropy** — computed from actual captured payload bytes, not estimated from headers.
- **Bidirectional flow tracking** — canonical flow key (`min(src,dst)` ordering) ensures A→B and B→A accumulate into the same flow record.
- **Directional byte counters** — `bytes_fwd` and `bytes_rev` tracked separately for asymmetry scoring.
- **TCP retransmission detection** — sliding-window SEQ scan flags duplicate sequence numbers.

### Architecture & Performance

- **Lock-free SPSC ring buffer** (65,536 slots) — capture callback does only `memcpy` + atomic store; all parsing and scoring run in a dedicated worker thread.
- **Per-bucket `pthread_rwlock_t`** — 8,192 independent RW locks instead of one global mutex; lookups take a read lock on a single bucket only.
- **TOCTOU-safe flow creation** — existence re-checked inside the write lock to prevent duplicate allocation.
- **RCU-style safe flow expiry** — `deleting` tombstone flag + mutex barrier before `free()` prevents use-after-free.
- **CPU affinity** — worker and cleanup threads can be pinned to specific cores via `-W` / `-C` flags.
- **O(1) sliding window** — fixed-size circular array (default 256 packets), indexed by `pkt_count % WINDOW_SIZE`.

### Input / Output

- **Live capture** on any interface via `pcap_open_live`.
- **Offline replay** from `.pcap` / `.pcapng` files via `pcap_open_offline`.
- **BPF pre-filter** (`tcp or udp`) applied automatically.
- **Plain-text alerts** with human-readable `src:port → dst:port` tuples and per-channel scores.
- **JSON output mode** (`-j`) — newline-delimited JSON per alert, pipeable to `jq`, Elasticsearch, Splunk, or any SIEM.
- **Verbose mode** (`-v`) — prints `ipd_cvar`, `len_std`, `ttl_var`, `payload_H`, `asym` per alert.

### Reliability & Usability

- **Graceful shutdown** — `SIGINT`/`SIGTERM` calls `pcap_breakloop`, drains the ring, joins threads, prints final stats.
- **Full CLI** — all parameters runtime-configurable, no recompilation needed.
- **Compile-time overrides** — `MAX_FLOWS`, `FLOW_HASH_SIZE`, `WINDOW_SIZE` overridable via `-D`.
- **IPv6 graceful skip** — non-IPv4 packets silently dropped, no crash.
- **Zero-warning build** — clean under `gcc -Wall -Wextra -std=c11`.

***

## CLI Options

```
Usage: oneida [options] <interface|pcap_file>

  -t <thresh>    Composite alert threshold     (default: 0.45)
  -i <sec>       Idle flow timeout in seconds  (default: 300)
  -l <sec>       Max flow lifetime in seconds  (default: 3600)
  -j             JSON output mode
  -p             Disable promiscuous mode
  -W <core>      Pin worker thread to CPU core
  -C <core>      Pin cleanup thread to CPU core
  -v             Verbose logging
  -h             Help
```

***

## Build

```bash
# Ubuntu / Debian
sudo apt install libpcap-dev

# macOS
brew install libpcap

# Compile
gcc -O2 -std=c11 -Wall -Wextra -o oneida oneida_v4.c -lpcap -lm -lpthread

# With compile-time overrides
gcc -O2 -std=c11 -o oneida oneida_v4.c -lpcap -lm -lpthread \
    -DMAX_FLOWS=65536 -DFLOW_HASH_SIZE=16384 -DWINDOW_SIZE=512
```

***

## Usage

```bash
# Live capture
sudo ./oneida eth0

# Lower threshold + JSON output
sudo ./oneida -t 0.40 -j eth0

# Replay a PCAP file
./oneida capture.pcapng

# Pin threads to cores, verbose
sudo ./oneida -W 2 -C 3 -v eth0

# Pipe JSON to jq
sudo ./oneida -j eth0 | jq '{flow: .flow_id, score: .score, src: .src, dst: .dst}'
```

**Plain-text alert:**
```
🚨 STEG ALERT [score=0.631] 10.0.0.5:54321 -> 93.184.216.34:443 | TCP | pkts=142
  Timing=0.85 Len=0.85 Flags=0.50 Payload=0.60 Burst=0.85 Asym=0.25 TTL=0.40 Retrans=0.05
```

**JSON alert (`-j`):**
```json
{"alert":true,"score":0.6312,"flow_id":"a1b2c3d4e5f60011",
 "src":"10.0.0.5","dst":"93.184.216.34","sport":54321,"dport":443,"proto":"TCP",
 "pkts":142,"bytes_fwd":20480,"bytes_rev":4096,
 "ch":[0.85,0.85,0.05,0.50,0.40,0.40,0.10,0.40,0.60,0.25,0.85,0.05]}
```

***

## Architecture Overview

```
pcap_loop (capture thread)
  └─ capture_callback()          <- lock-free memcpy into ring buffer
       └─ atomic_store -> ring_t

worker_thread (separate core)
  └─ process_one()
       ├─ parse_packet()          <- manual byte-level IPv4/TCP/UDP parser
       ├─ flow_lookup_or_create() <- per-bucket RW lock, TOCTOU-safe
       ├─ compute_scores()        <- 12-channel weighted scoring
       └─ emit_alert()            <- plain text or JSON

cleanup_thread (separate core)
  └─ every 30s: expire idle/old flows
       └─ RCU tombstone + mutex barrier before free()
```

***

## Known Limitations

- **IPv4 only** — IPv6 support is the most impactful pending addition.
- **No IP fragment reassembly** — fragmented flows dropped at the parser.
- **Retransmission detection is O(n)** — a Bloom filter would be more efficient at scale.
- **Scoring weights are empirical** — calibrating against a labeled dataset (e.g. CAIDA, CIC-IDS2017) would improve precision.
- **Single worker thread** — SPSC ring supports one consumer; MPMC queue needed for multi-worker.
- **IPID predictability** — Ch 8 currently filled by payload entropy; dedicated IPID delta tracker pending.

***

## License

MIT

Sources
