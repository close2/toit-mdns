# Hardware End-to-End Tests

These scripts target real ESP32 hardware (via Jaguar) and a PC on the same
Wi-Fi LAN. They are excluded from CTest (`make test`) because they require
physical devices and network access.

## Existing diagnostic scripts

- `esp32-broadcast-test.toit` / `esp32-receive-multicast-test.toit`: Raw UDP
  multicast send/receive sanity checks.
- `esp32-mcast-ping.toit` / `esp32-send-proxy.toit` / `esp32-send-to-pc.toit` /
  `pc-send-multicast-test.toit`: Host-to-ESP32 multicast round-trip helpers.
- `esp32-mdns-device-a.toit` / `esp32-mdns-device-b.toit`: Two-device discovery
  smoke test.

## Planned ESP32 batch (H1–H11)

Scripts for the post-P8 hardware verification batch will be placed here and
output `PASS` / `FAIL` lines so results can be captured with `jag monitor`:

- **H1**: Probe, announce, and resolve from PC (`avahi-resolve` / `dns-sd`).
- **H2**: Hostname conflict between two ESP32s (only one renames).
- **H3**: Service conflict and simultaneous-probe tiebreak (1 s deferral).
- **H4**: Mutual service discovery and TXT-only update without re-probing.
- **H5**: Interop with macOS/iOS, Android NSD, and Linux avahi (including AAAA).
- **H6**: Heap stability under cache-fill and NSEC floods.
- **H7**: Wi-Fi drop recovery, new IP announcement, and zero leaked handles.
- **H8**: Multi-container ownership, `PERMISSION_DENIED`, cleanup on uninstall.
- **H9**: Off-link source filtering and legacy unicast rate limiting.
- **H10**: Multi-packet announcement splitting within MTU.
- **H11**: Shared-answer delay (20–120 ms) and NSEC additional on A responses.
