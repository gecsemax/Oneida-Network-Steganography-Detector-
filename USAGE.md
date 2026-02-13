## Live steganography detection example

1. **Start Oneida on your Wi‑Fi interface**

```bash
sudo ./oneida en0
```

You should see something like:

```text
=== Oneida v3.0 Enterprise ===
12‑Channel Steganography Detection | macOS‑compatible core

✅ Capturing on en0 | Ctrl+C to stop
Threshold: 0.45 | Max flows: 8192 | Window: 256
```

2. **Generate some normal traffic**

While Oneida runs:

- Browse a few websites.
- Start a video call or stream.
- Run `ping` to a host:

```bash
ping -c 20 8.8.8.8
```

This gives Oneida a baseline of mostly benign flows to score.

3. **Inject suspicious / structured traffic**

Simulate something covert‑channel‑like, for example:

- Use a tool that sends packets with highly regular timing or sizes (e.g., a simple script that sends fixed‑size UDP packets at a constant rate).
- Or replay a prepared pcap that contains known network steganography through `tcpreplay` on a lab interface, while Oneida is listening on that interface.[3][4]

4. **Watch for high‑scoring flows**

As packets arrive, Oneida computes a per‑flow anomaly score; when a flow crosses the internal threshold, you’d expect output along the lines of:

```text
🚨 STEG ALERT [0.78] 00000000deadbeef | 54321→80 | Pkts:120
   Timing:0.90 Len:0.65 Proto:0.30
```

Interpretation:

- The bracketed value `[0.78]` is the overall anomaly score (closer to 1.0 = more suspicious).
- `Timing`, `Len`, and `Proto` sub‑scores hint whether irregular inter‑packet delays, packet lengths, or protocol usage are driving the suspicion.[5][3]

5. **Stop capture and pivot to deeper analysis**

Hit `Ctrl+C` to stop, note down the suspicious flow’s 5‑tuple (src/dst IP/port, protocol), and:

- Filter that flow in Wireshark or `tcpdump` using a display filter or `host` / `port` expressions.
- Compare its patterns (timing, sizes, flags) against nearby “normal” flows to understand what Oneida found unusual.
