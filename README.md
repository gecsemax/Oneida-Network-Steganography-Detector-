# Oneida-Network-Steganography-Detector
# Oneida Network Steganography Detector

Author: **Max Gecse**

***

## Overview

**Oneida Network Steganography Detector** is a C-based passive tool for detecting **network steganography and covert channels**. It analyzes live network traffic to flag suspicious behavior in packet headers and timing that may indicate hidden communication.

The detector focuses on:

- Abnormal use of **IP ID** and **packet timing**  
- Covert channels in **TCP timestamp (TSval)** fields  
- **Timing-based** covert channels detected via entropy, corrected conditional entropy (CCE), and chi-square tests  

Oneida is intended as a research and educational prototype, not a drop‑in replacement for a production IDS.

***

## Features

1. **IP Header Anomaly Detection**
   - Tracks IP ID sequences per source.
   - Computes standard deviation of IP ID differences.
   - Monitors inter-packet arrival times and their variance.
   - Flags sources with unusual IP ID behavior or overly regular timing.

2. **TCP Timestamp Covert Channel Detection**
   - Parses TCP options and extracts **TSval** (RFC 7323).
   - Tracks TSval sequences per source.
   - Checks:
     - TSval increment variance.
     - Bias in TSval least significant bit (LSB).
     - Autocorrelation of TSval to reveal periodic patterns.

3. **Timing Covert Channel Detection**
   - Builds inter-packet delay (IPD) sequences per source.
   - Computes:
     - Shannon entropy of IPD histogram.
     - **Corrected Conditional Entropy (CCE)** over IPD symbol sequences.
     - **Chi-square goodness-of-fit** against a baseline IPD distribution.
   - Raises alerts when entropy/CCE are low or chi-square is high, suggesting shaped timing.

***

## Architecture

- Written in **C**, using:
  - **libpcap** for packet capture.
  - Standard C library and `<math.h>` for statistics.
- Passive sniffer:
  - Captures packets from a network interface (e.g., connected to a switch SPAN/mirror port).
  - Maintains per-source state in memory (sliding windows).
  - Prints alerts to stdout when heuristics detect anomalies.

Core components:

- **Packet capture loop**: opens an interface, applies a BPF filter (`ip and tcp`), and runs a callback for each packet.
- **Per-host tracking**: for each source IP address:
  - IP IDs and timestamps.
  - TCP TSval values and LSB counts.
- **Analysis functions**:
  - IPID/timing statistics.
  - TSval statistics and autocorrelation.
  - IPD entropy, CCE, and chi-square.

***

## Requirements

- Operating system: Linux or another Unix-like OS with libpcap.
- Tools:
  - C compiler (e.g., `gcc`).
  - libpcap development headers and library installed.

Example on Debian/Ubuntu:

```bash
sudo apt-get install build-essential libpcap-dev
```

***

## Building

Assuming the main source file is named `steg_detect_all.c` and you want the binary to be called `oneida`:

```bash
gcc -O2 -Wall steg_detect_all.c -lpcap -lm -o oneida
```

***

## Running

Oneida must see live traffic, typically from a SPAN/mirror port or TAP.

Basic usage:

```bash
sudo ./oneida <interface>
```

Examples:

```bash
# Use explicit interface
sudo ./oneida eth0

# If you omit the interface, the program will try to pick a default one
sudo ./oneida
```

The program prints alerts such as:

- `IPID/timing anomaly from 10.0.0.5`  
- `TCP timestamp anomaly from 192.168.1.10`  
- `Timing anomaly (entropy/CCE/chi-square) from 172.16.0.3`

***

## Deployment Notes

- **SPAN / Mirror Port**:
  - Configure your switch to mirror traffic (ports or VLANs) to the interface where the Oneida host is connected.[1][2]
  - Ensure the mirrored bandwidth does not exceed the detector interface capacity, or packets may be dropped.[3]
- **Permissions**:
  - Root privileges are usually required for raw packet capture (`sudo`).[4]
- **Performance**:
  - Single-threaded prototype; for high-throughput links, consider sampling, more efficient data structures, or integrating Oneida into a larger IDS framework.[5]

***

## Configuration & Tuning

Detection thresholds are defined as macros at the top of the source file. Tune them based on **baseline traffic** in your environment:

- IPID/timing:
  - `STD_IPID_THRESHOLD`
  - `STD_TIME_THRESHOLD`
- TCP timestamps:
  - `STD_TSVAL_THRESHOLD`
  - `LSB_BIAS_THRESHOLD`
  - `MAX_LAG` / `ACF_THRESHOLD`
- Timing entropy/CCE:
  - `ENTROPY_BIN_COUNT`
  - `ENTROPY_LOW_THRESHOLD`
  - `CCE_MAX_PATTERN_LEN`
  - `CCE_LOW_THRESHOLD`
  - `CCE_MIN_IPD_SAMPLES`
- Chi-square:
  - `CHI_SIG_THRESHOLD`
  - `ipd_expected_prob[]` (baseline IPD distribution)

Recommended workflow:

1. Capture a few hours/days of **known-good** traffic.  
2. Run Oneida in observation mode and log statistics.  
3. Adjust thresholds to reduce false positives on normal traffic.  
4. Test with synthetic or lab-generated covert channels to verify detection.[6][7]

***

## Limitations

- Heuristic and statistical; cannot guarantee detection of all steganography or covert channels.[5]
- Currently keyed on **source IP**; for finer modeling, extend to per-flow tracking (src/dst IP + ports).[6]
- Fixed-size host table and windows; not optimized for very large or high-speed networks.  
- Good performance depends on realistic baseline distributions for your environment.[6]

***

## Possible Extensions

- Per-flow (5-tuple) tracking instead of per-source.  
- Offline analysis mode (read from pcap files).  
- Export features for machine-learning-based classifiers.  
- Integration with existing NIDS frameworks (Zeek, Suricata) as an external sensor.  
- Additional statistical tests and model-based detection for specific covert channel families.[8][9]

***

## License

Add your preferred license here, for example:

```text
MIT License

Copyright (c) 2026 Max Gecse

Permission is hereby granted, free of charge, to any person obtaining a copy
...
```

(Replace with the actual license text you choose.)

***

## Contact

For questions, improvements, or contributions related to the **Oneida Network Steganography Detector**, please credit:

**Author**: Max Gecse
