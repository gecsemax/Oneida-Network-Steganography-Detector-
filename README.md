```markdown
# 🚀 Oneida v3.0 – Network Steganography Detector

Author: **Max Gecse**  
License: **MIT**

Oneida is a network steganography and covert‑channel detector.  
v3.0 is a compact, macOS‑compatible core focused on per‑flow anomaly scoring over IPv4/TCP, designed as a solid base for research and future extensions (ML, plugins, visualization, etc.).

> Status: Advanced research tool with a production‑style core. Use with care in high‑security environments.

---

## ✨ Features (v3.0 core)

- Per‑flow tracking with sliding windows (up to 8192 flows)
- Basic 12‑channel anomaly score (timing, length, proto‑entropy scaffolding)
- Real‑time scoring as packets arrive
- Support for:
  - Live interfaces (e.g., `lo0`, `en0` on macOS)
  - Offline `.pcap` files via libpcap
- macOS‑friendly implementation:
  - `pthread_mutex` (no spinlocks)
  - `tv_sec` + `tv_usec` timestamp handling
  - Correct TCP header field usage (`th_sport` / `th_dport`)

The current `oneida.c` is intentionally a **single self‑contained C file** so it is easy to read, modify, and extend.

---

## 🍎 macOS Quick Start

### 1. Install dependency

```bash
brew install libpcap
```

### 2. Build

```bash
make
```

This produces the `oneida` binary.

### 3. Run on loopback (safe test)

```bash
sudo ./oneida lo0
```

### 4. Run on Wi‑Fi (typical Mac interface)

```bash
sudo ./oneida en0
```

Press `Ctrl + C` to stop capture.

---

## 🐧 Linux Quick Start (if you build there)

```bash
sudo apt-get update
sudo apt-get install build-essential libpcap-dev
make
sudo ./oneida eth0
```

---

## 🔍 Usage Examples

### Live interface

```bash
sudo ./oneida lo0
sudo ./oneida en0
```

### Offline PCAP

```bash
sudo ./oneida capture.pcap
```

When anomalous flows are detected, Oneida prints alerts like:

```text
🚨 STEG ALERT [0.52] 00000000deadbeef | 12345→443 | Pkts:64
   Timing:0.80 Len:0.40 Proto:0.25
```

---

## 🧪 Development Notes

- Core logic is in `oneida.c` (single file).
- Build rules are in `Makefile`.
- `.gitignore` excludes binaries, object files, and local artifacts.
- The design leaves room to:
  - Add more channels to the scoring engine
  - Feed `ml_features_t` into external ML models
  - Integrate a plugin or scripting layer later

---

## 📜 License (MIT)

Copyright (c) 2026 Max Gecse

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```


