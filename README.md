# Oneida Network Steganography Detector

Author: **Max Gecse**  
License: **MIT**

Oneida is a network steganography and covert‑channel detector.  
It began as a heuristic IPv4/TCP tool focused on subtle anomalies in IPID behavior, TCP timestamps, and inter‑packet timing, and has evolved into a multi‑protocol, multi‑channel, near real‑time detector designed for both research and production‑style experimentation.

> Status: Advanced research tool with a production‑style core. Use with care in high‑security environments.

---

## What Oneida Does

- **Steganography & covert‑channel detection**
  - Aims to catch timing‑based, header‑based, and pattern‑based covert channels
  - Focus on low‑signal, high‑subtlety anomalies rather than only obvious scans

- **Protocol‑agnostic core (design)**
  - IPv4/IPv6 aware
  - Handles TCP/UDP and structured to be extended for QUIC, DNS, TLS metadata, and ICMP

- **Multi‑channel anomaly engine**
  - Per‑flow sliding window of packets
  - Multiple feature “channels”, including:
    - Inter‑packet delay (IPD) statistics
    - Packet length patterns
    - Protocol‑mix entropy
    - Header/state behaviors

- **Real‑time oriented**
  - Per‑flow scoring as packets arrive
  - Idle‑timeout and cleanup for long‑running captures
  - Suitable as a building block for <100 ms alerting pipelines

- **ML‑ready feature extraction**
  - Computes per‑flow statistics that can be fed into:
    - Autoencoders
    - Isolation Forest / clustering
    - Other unsupervised anomaly detectors

- **Extensible core**
  - Single‑file C implementation, easy to:
    - Wrap with plugins or scripting layers
    - Integrate with external ML pipelines
    - Feed into visualization / forensics tools

---

## Original Heuristic Focus (Research Roots)

- **IPID + timing analysis**
  - Wrap‑around aware IPID delta variance
  - Inter‑arrival time variance using a monotonic clock (on supported platforms) for stable IPDs

- **TCP timestamp analysis**
  - TSval increment variance and LSB‑bias detection
  - Short‑range autocorrelation on TSvals to spot structured timing patterns

- **Timing entropy and low‑order patterns**
  - Shannon entropy over IPD histograms
  - Corrected conditional entropy (CCE) for symbol patterns
  - Chi‑square goodness‑of‑fit against baseline IPD distributions

- **Per‑flow tracking**
  - Sliding windows keyed by 5‑tuple (src/dst IP, src/dst port, protocol)
  - Flow idle‑timeout and cleanup

- **Multithread‑friendly design**
  - Per‑packet analysis loop written to be compatible with worker‑thread/job‑queue architectures
  - Easy to embed into a larger multi‑threaded system

- **Offline and live capture (via libpcap)**
  - Analyze `.pcap` traces
  - Attach to live interfaces for real traffic

- **Output**
  - Human‑readable alerts on stdout
  - Easy to adapt to JSON or structured logging for SIEM/SOC integration

---

## Build Instructions

### Dependencies

- C compiler
  - macOS: `clang` (default)  
  - Linux: `gcc` or `clang`
- libpcap (development headers + library)
- pthreads (POSIX threads; part of the standard C library on macOS/Linux)
- libm (math library, usually `-lm`)

### macOS Setup

Install libpcap with Homebrew:

```bash
brew install libpcap
```

Build using the provided `Makefile`:

```bash
make
```

This produces the `oneida` binary.

### Linux Setup

On Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install build-essential libpcap-dev
make
```

---

## Usage Examples

### Live Capture (macOS)

List interfaces:

```bash
ifconfig | grep -E '^[a-z]+[0-9]+:' | cut -d: -f1
```

Typical usage:

```bash
sudo ./oneida lo0   # Loopback
sudo ./oneida en0   # Wi‑Fi
```

### Live Capture (Linux)

```bash
sudo ./oneida eth0
```

### Offline PCAP

```bash
sudo ./oneida capture.pcap
```

When anomalies are detected, Oneida prints alerts similar to:

```text
🚨 STEG ALERT [0.67] 1a2b3c4d5e6f7890 | 12345→443 | Pkts:127
   Timing:0.82 Len:0.45 Proto:0.31
```

---

## Roadmap Ideas

These are natural next steps on top of the core detector:

- Plugin / module system for custom detectors
- Python or Lua scripting interface
- Integrated ML‑based scoring (autoencoders, Isolation Forest, clustering)
- Visualization and forensics UI (timing graphs, entropy plots, state diagrams)
- Benchmark suite with synthetic covert‑channel generators and labeled datasets

---

## License (MIT)

Copyright (c) 2026 Max Gecse

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```
