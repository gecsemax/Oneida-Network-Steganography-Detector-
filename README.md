```markdown
# Oneida Network Steganography Detector

Oneida is a heuristic detector for network steganography and covert channels over IPv4/TCP.
It focuses on subtle anomalies in IPID behavior, TCP timestamps, and inter‑packet timing.

> Status: Experimental research tool, not a production IDS.

---

## Features

- IPID + timing analysis  
  - Wrap‑around aware IPID delta variance  
  - Inter‑arrival time variance using a monotonic clock (Linux) for stable IPDs  
- TCP timestamp analysis  
  - TSval increment variance and LSB bias detection  
  - Short‑range autocorrelation on TSvals to spot structured timing patterns  
- Timing entropy and CCE  
  - Shannon entropy over inter‑packet delay histogram  
  - Corrected conditional entropy (CCE) for low‑order symbol patterns in IPDs  
  - Chi‑square goodness‑of‑fit against a baseline IPD distribution  
- Per‑flow tracking  
  - Sliding windows keyed by 5‑tuple (src/dst IP, src/dst port, protocol)  
  - Flow idle‑timeout and cleanup  
- Multithreaded capture and analysis  
  - One libpcap handle + capture thread per interface (safe pattern for libpcap)
  - Shared worker thread pool consuming from a bounded job queue  
- Multi‑interface and offline support  
  - Capture from one or more live interfaces at once  
  - Read and analyze offline `.pcap` files  
- Output  
  - Human‑readable alerts on stdout  
  - Easy to adapt to JSON/structured logging

---

## Build Instructions

### Dependencies

- C compiler (e.g., gcc or clang)
- libpcap (development headers + library) 
- pthreads (POSIX threads; part of glibc on Linux, provided by libc on macOS)
- libm (math library, typically `-lm`)

### Generic build command (Unix‑like)

If libpcap is in standard paths:

```bash
gcc -O2 -pthread -Wall -o oneida oneida.c -lpcap -lm
```

If headers/libraries are in non‑standard locations, add `-I/path/to/include` and `-L/path/to/lib`.

---

### Linux

#### Ubuntu / Debian

Install dependencies:

```bash
sudo apt update
sudo apt install build-essential libpcap-dev
```

Build:

```bash
gcc -O2 -pthread -Wall -o oneida oneida.c -lpcap -lm
```

`libpcap-dev` provides the libpcap headers and library on Debian‑based systems.[web:82][web:92]

#### Fedora

Install dependencies:

```bash
sudo dnf install gcc make libpcap-devel
```

Build:

```bash
gcc -O2 -pthread -Wall -o oneida oneida.c -lpcap -lm
```

`libpcap-devel` is the development subpackage containing `pcap.h` and the library.[web:93][web:85]

#### CentOS / RHEL

Install dependencies (examples):

```bash
sudo yum makecache
sudo yum install gcc make libpcap-devel
# or, on newer releases
sudo dnf makecache
sudo dnf install gcc make libpcap-devel
```

Build:

```bash
gcc -O2 -pthread -Wall -o oneida oneida.c -lpcap -lm
```

`libpcap-devel` is the common RPM name for libpcap development files.[web:86][web:90][web:94]

#### Arch Linux / Manjaro

Install dependencies:

```bash
sudo pacman -S --needed base-devel libpcap
```

Build:

```bash
gcc -O2 -pthread -Wall -o oneida oneida.c -lpcap -lm
```

The `libpcap` package on Arch provides headers and the shared library in the standard include/lib paths.[web:87][web:91]

---

### macOS

macOS ships with libpcap as part of the OS; usually only Xcode’s command‑line tools are needed.[web:109][web:118]

Install tools:

```bash
xcode-select --install
```

(Optional) Install a newer libpcap with Homebrew:

```bash
brew install libpcap
```

Build:

```bash
gcc -O2 -pthread -Wall -o oneida oneida.c -lpcap -lm
```

If Homebrew’s prefix is not on the default search path (e.g. Apple Silicon):

```bash
gcc -O2 -pthread -Wall \
  -I/opt/homebrew/include -L/opt/homebrew/lib \
  -o oneida oneida.c -lpcap -lm
```

> Note: The code is primarily tuned for Linux (e.g., SLL/SLL2 link types). On macOS you may need to add `#ifdef __linux__` guards or trim Linux‑specific branches if you hit build issues.

---

### Windows (Npcap)

On Windows, libpcap functionality is provided by Npcap, the modern replacement for WinPcap.[web:111][web:119][web:129]

1. Install Npcap  

   - Download the installer from https://npcap.com.  
   - Enable “WinPcap API‑compatible mode” so `pcap.h` and `wpcap.dll` are available.[web:114][web:115]

2. Install a compiler / environment  

   - Visual Studio (MSVC), or  
   - MinGW‑w64 / MSYS2

3. Configure include and library paths to the Npcap SDK  

   - Include directory: contains `pcap.h`  
   - Library directory: contains `wpcap.lib` and `Packet.lib`

Example with MinGW‑w64 (paths may differ):

```bash
gcc -O2 -Wall -o oneida.exe oneida.c \
  -I"C:/Program Files/Npcap/Include" \
  -L"C:/Program Files/Npcap/Lib" \
  -lwpcap -lPacket -lws2_32
```

> Important: The current code uses POSIX threads and some Linux‑specific headers. A full Windows port requires replacing pthreads with Win32 threads or C++ `std::thread`, and adjusting includes and linking according to the Npcap developer guide.[web:119][web:111]

---

## Usage

### Live capture on one interface

```bash
sudo ./oneida -i eth0
```

### Live capture on multiple interfaces

Capture on two wired interfaces:

```bash
sudo ./oneida -i eth0 -i eth1
```

Capture on wired + Wi‑Fi:

```bash
sudo ./oneida -i eth0 -i wlan0
```

Capture on loopback and an external interface:

```bash
sudo ./oneida -i lo -i eth0
```

Using a shell variable with multiple interfaces:

```bash
IFACES="eth0 eth1 wlan0"
sudo ./oneida $(for i in $IFACES; do printf -- " -i %s" "$i"; done)
```

Each `-i` creates a separate libpcap handle and capture thread; all packets are fed into a shared worker pool for analysis.[web:44][web:96]

### Offline analysis from a pcap file

```bash
sudo ./oneida traffic.pcap
```

If no `-i` options are given and the last argument is a readable file, Oneida runs in offline mode and processes the capture from disk.

---

## Alerts

Typical alerts look like:

- IPID / timing anomaly:

  ```text
  [ALERT] IPID/timing anomaly 192.0.2.10:43210 -> 198.51.100.5:80
          IPID std(diff): 742.13, time std(diff): 0.012345
  ```

- TCP timestamp anomaly:

  ```text
  [ALERT] TSval autocorrelation anomaly 192.0.2.10:43210 -> 198.51.100.5:80
          max |R(k)| at lag 3: 0.57
  [ALERT] TCP timestamp anomaly 192.0.2.10:43210 -> 198.51.100.5:80
          TSval std(diff): 8123.00, LSB(1) fraction: 0.910
  ```

- Timing entropy / CCE / chi‑square anomaly:

  ```text
  [ALERT] Timing anomaly (entropy/CCE/chi-square) 192.0.2.10:43210 -> 198.51.100.5:80
          H: 1.842 bits, CCE: 1.200 bits, chi^2: 45.73
  ```

Thresholds are compile‑time constants in the source file (`STD_IPID_THRESHOLD`, `ENTROPY_LOW_THRESHOLD`, `CCE_LOW_THRESHOLD`, `CHI_SIG_THRESHOLD`, etc.) and should be tuned per environment.

---

## Limitations

- IPv4 + TCP only (no IPv6 support yet).
- Heuristic detector; expect both false positives and false negatives.
- Static IPD baseline (`ipd_expected_prob`); for serious use, replace with a learned or environment‑specific baseline.
- Linux‑centric implementation (e.g., Linux SLL/SLL2 link types, some headers). Non‑Linux builds may require minor conditional compilation.

---

## Contributing / Notes

- Pull requests for:
  - IPv6 support
  - Configurable thresholds via CLI or config file
  - JSON/NDJSON structured logging
  - Better baseline learning and persistence  
  are welcome.
- When modifying code, keep the MIT license header and attribution to Max Gecse in both `license.txt` and the source file header to comply with the license terms.[web:67][web:125]
```


## Author and License

- Author: Max Gecse  
- License: MIT

MIT License

Copyright (c) <2026> Max Gecse

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice (including the next
paragraph) shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

