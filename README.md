Update it to match your new v3.1 core like this:

```markdown
# 🚀 Oneida v3.1 – Network Steganography Detector

Author: **Max Gecse**  
License: **MIT**

Oneida is a network steganography and covert‑channel detector.  
v3.1 is a compact, macOS‑compatible core focused on per‑flow anomaly scoring over IPv4/TCP/UDP, designed as a solid base for research and future extensions (ML, plugins, visualization, etc.).[web:338][web:332]

> Status: Advanced research tool with a production‑style core. Use with care in high‑security environments.

---

## ✨ Features (v3.1 core)

- Per‑flow tracking with sliding windows (up to 16 384 flows, hash‑indexed)
- 12‑channel anomaly score (timing, length, entropy, header variance scaffold)
- Real‑time scoring as packets arrive
- Support for:
  - Live interfaces (for example `lo0`, `en0` on macOS)
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

## 🔍 Usage examples

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
🚨 STEG ALERT [0.78] 00000000deadbeef | 54321→80 | Pkts:120 | L4:TCP
   Timing:0.90 Len:0.40 Proto:0.25 Flags:0.35 TTL:0.20
```

---

## 🧪 Development notes

- Core logic is in `oneida.c` (single file).
- Build rules are in `Makefile`.
- `.gitignore` excludes binaries, object files, and local artifacts.
- The design leaves room to:
  - Add more channels to the scoring engine
  - Feed feature vectors into external ML models
  - Integrate a plugin or scripting layer later

---

## 📜 License

This project is licensed under the terms of the **MIT** license.  
See the `LICENSE` file for the full text.
```

Then:

```bash
cd ~/oneida-stego-detector/oneida-stego-detector
git add README.md
git commit -m "Update README for Oneida v3.1 core"
git push
```

Sources
