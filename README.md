# Oneida-Network-Steganography-Detector

Author: **Max Gecse**

***

## Overview

**Oneida Network Steganography Detector** is a C-based passive tool for detecting **network steganography and covert channels**. It analyzes live network traffic and flags suspicious behavior in packet headers and timing that may indicate hidden communication.

This updated version improves robustness and performance while keeping the original heuristics:

- Abnormal use of **IP ID** and **packet timing**  
- Covert channels in **TCP timestamp (TSval)** fields  
- **Timing-based** covert channels via entropy, corrected conditional entropy (CCE), and chi-square tests  

Oneida is intended as a research and educational prototype, not a drop‑in replacement for a production IDS.

***

## Features

1. **IP Header Anomaly Detection**
   - Tracks IP ID sequences per source using a **ring buffer**.
   - Computes standard deviation of IP ID differences with explicit 16‑bit wrap‑around handling.
   - Monitors inter-packet arrival times and their variance.
   - Flags sources with unusual IP ID behavior or overly regular timing.

2. **TCP Timestamp Covert Channel Detection**
   - Parses TCP options and extracts **TSval** (RFC 7323).
   - Tracks TSval sequences per source in a ring buffer.
   - Checks:
     - TSval increment variance.
     - **Per-window** bias in TSval least significant bit (LSB), so recent anomalies aren’t diluted by long history.
     - Autocorrelation of TSval to reveal periodic patterns.
   - Flags suspected use of TSvals as a covert channel.

3. **Timing Covert Channel Detection**
   - Builds inter-packet delay (IPD) sequences per source.
   - Computes:
     - Shannon entropy of an IPD histogram.
     - **Corrected Conditional Entropy (CCE)** over IPD symbol sequences (pattern lengths 1..3).
     - **Chi-square goodness-of-fit** against a baseline IPD distribution.
   - Raises alerts when entropy/CCE are low or chi-square is high, suggesting shaped timing.

4. **Improved Robustness and Performance**
   - **Ring buffers** for IPID, timestamps, and TS LSBs (no per-packet array shifts).
   - Safer numerical handling in entropy (clamping probabilities to avoid `log(0)`).
   - More robust IP parsing with total-length checks.
   - Support for multiple link-layer types via `pcap_datalink()`:
     - Ethernet (`DLT_EN10MB`), including single 802.1Q VLAN tag.
     - Linux cooked capture (`DLT_LINUX_SLL`, e.g. `any` interface).
     - BSD loopback (`DLT_NULL`).

***

## Architecture

- Written in **C**, using:
  - **libpcap** for packet capture.
  - Standard C library and `<math.h>` for statistics.

- Passive sniffer:
  - Captures packets from a network interface (e.g., SPAN/mirror port or TAP).
  - Maintains per-source state in memory using fixed-size ring buffers.
  - Prints alerts to stdout when heuristics detect anomalies.

Core components:

- **Packet capture loop**
  - Opens an interface, queries the link-layer type via `pcap_datalink()`, sets the appropriate L2 header length.
  - Applies a BPF filter (`ip and tcp`).
  - Invokes a packet handler callback for each captured packet.

- **Per-host tracking**
  - Keyed by source IP address.
  - For each host:
    - Ring buffer of IP IDs and arrival timestamps.
    - Ring buffer of TCP TSvals.
    - Per-window counts of TSval LSBs (0/1) that track only the active window.

- **Analysis functions**
  - IPID/timing statistics (standard deviation over ring-window differences).
  - TSval statistics (stddev, LSB bias, autocorrelation).
  - IPD entropy, CCE, and chi-square against a configurable baseline.

***

## Requirements

- Operating system: Linux or another Unix-like OS with libpcap.
- Tools:
  - C compiler (e.g., `gcc` or `clang`).
  - libpcap development headers and library installed.
  - Math library (`-lm`).

Example on Debian/Ubuntu:

```bash
sudo apt-get install build-essential libpcap-dev
```

***

## Building

Assuming the updated source file is named `oneida_updated.c` and you want the binary to be called `oneida`:

```bash
gcc -O2 -Wall oneida_updated.c -lpcap -lm -o oneida
```

If libpcap is installed in a non-standard path, add the appropriate `-I` and `-L` flags.

***

## Running

Oneida must see live traffic, typically from a SPAN/mirror port, TAP, or a host interface.

Basic usage:

```bash
sudo ./oneida <interface>
```

Examples:

```bash
# Monitor a physical interface
sudo ./oneida eth0

# Monitor all interfaces via Linux cooked capture (DLT_LINUX_SLL)
sudo ./oneida any

# If you omit the interface, the program will try to pick a default one
sudo ./oneida
```

While running, Oneida prints alerts like:

```text
[ALERT] IPID/timing anomaly from 10.0.0.5
        IPID std(diff): 712.34, time std(diff): 0.010000
[ALERT] TCP timestamp anomaly from 192.168.1.10
        TSval std(diff): 8200.25, LSB(1) fraction: 0.810
[ALERT] Timing anomaly (entropy/CCE/chi-square) from 172.16.0.3
        H: 2.100 bits, CCE: 1.200 bits, chi^2: 45.50
```

***

## Deployment Notes

- **SPAN / Mirror Port**
  - Configure your switch to mirror traffic (ports or VLANs) to the interface where Oneida is connected.
  - Ensure the mirrored bandwidth does not exceed the monitoring interface capacity; otherwise, libpcap may drop packets silently.

- **Link-layer types**
  - Oneida automatically adapts to:
    - Ethernet (`DLT_EN10MB`) with optional single VLAN tag (0x8100).
    - Linux “cooked” capture (`DLT_LINUX_SLL`), e.g. `any` on Linux.
    - BSD loopback (`DLT_NULL`) for loopback interfaces.
  - Other link-layer types are currently rejected with an error.

- **Permissions**
  - Root privileges are usually required for raw packet capture:
    ```bash
    sudo ./oneida eth0
    ```

- **Performance**
  - Single-threaded, in-process analysis.
  - Ring buffers avoid O(WINDOW_SIZE) shifts on each packet.
  - Suitable for low-to-moderate traffic rates; for high-speed links, consider:
    - Sampling,
    - Offloading pre-filtering to BPF/eBPF,
    - Or integrating Oneida’s logic into a larger, multi-threaded IDS framework.

***

## Configuration & Tuning

Detection thresholds and parameters are defined as macros near the top of the source file:

- **Sliding window sizes**
  - `WINDOW_SIZE` – number of recent packets per host tracked in the ring buffers.
  - `MAX_HOSTS` – maximum number of source IPs tracked concurrently.

- **IPID / timing**
  - `STD_IPID_THRESHOLD`
  - `STD_TIME_THRESHOLD`
  - `ALERT_MIN_PACKETS`

- **TCP timestamps**
  - `ALERT_MIN_TS_SAMPLES`
  - `STD_TSVAL_THRESHOLD`
  - `LSB_BIAS_THRESHOLD`
  - `MAX_LAG` (autocorrelation) / `ACF_THRESHOLD`

- **Timing entropy / CCE**
  - `ENTROPY_BIN_COUNT`
  - `ENTROPY_MIN_SAMPLES`
  - `ENTROPY_LOW_THRESHOLD`
  - `CCE_MAX_PATTERN_LEN`
  - `CCE_BIN_COUNT`
  - `CCE_MIN_IPD_SAMPLES`
  - `CCE_LOW_THRESHOLD`

- **Chi-square**
  - `CHI_SIG_THRESHOLD`
  - `CHI_MIN_EXPECTED_COUNT`
  - `CHI_BIN_COUNT`
  - `ipd_expected_prob[]` – baseline IPD distribution.

### Recommended workflow

1. Capture a few hours/days of **known-good** traffic.  
2. Run Oneida and observe how often alerts fire and what values typical metrics have.  
3. Adjust thresholds to reduce false positives while still catching clearly manipulated traffic.  
4. Test with lab-generated covert channels (e.g., scripted manipulation of IP ID, TSval LSB, or packet timing) and confirm that Oneida raises alerts.

***

## Limitations

- **Heuristic, not guaranteed detection**  
  Oneida uses statistical heuristics; sophisticated or low-volume covert channels may evade detection, and noisier links may produce false positives.

- **Per-source granularity**  
  The current implementation tracks per source IP. Extending to per-flow (5‑tuple) granularity can reduce mixing of different applications on the same host.

- **IPv4 + TCP only**  
  BPF filter is `ip and tcp`; IPv6 and non-TCP protocols are ignored in this version.

- **Fixed in-memory data structures**  
  `MAX_HOSTS` and `WINDOW_SIZE` are compile-time constants; very large environments may need higher limits and memory considerations.

***

## Possible Extensions

- Per-flow (5-tuple) tracking instead of per-source.
- Offline analysis mode (read from `.pcap` files instead of live capture).
- Export feature vectors to CSV/JSON to train machine-learning-based classifiers.
- Integration as an external sensor for Zeek, Suricata, or other NIDS.
- Additional tests on other header fields (e.g., TCP sequence numbers, IPv6 flow labels) and on new transport protocols (e.g., QUIC).

***

## License

MIT License

```text
Copyright (c) 2026 Max Gecse

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights  
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell  
copies of the Software, and to permit persons to whom the Software is  
furnished to do so, subject to the following conditions:  

The above copyright notice and this permission notice shall be included in  
all copies or substantial portions of the Software.  

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR  
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE  
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER  
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING  
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS  
IN THE SOFTWARE.
```

***

## Contact

For questions, improvements, or contributions related to the **Oneida Network Steganography Detector**, please credit:

**Author**: Max Gecse
