# SEC 524 OT Forensics — First Run Evidence + Recording Checklist

## First run (do now)

1. Configure both VMs as Internal Network `OTLAB` (disable NAT/bridge before testing); screenshot `S01_VM_NET_SETTINGS.png`.
2. Assign OT-PLC `10.20.30.10/24` and OT-CLIENT `10.20.30.20/24`. Record `ip -br addr` and `ip route` on both; screenshot `S02_IP_CONFIG.png`.
3. From OT-CLIENT: `ping -c 3 10.20.30.10`; screenshot `S03_CONNECTIVITY.png`.
4. Copy **the same `quick_lab.py`** into home directory of both VMs. Install `tcpdump`, `tshark` (and optional Wireshark) *before* isolating the lab.
5. Create unique directory `~/sec524_run1` on OT-PLC. `cd ~/sec524_run1`; run `python3 -u ~/quick_lab.py server | tee plc_console.txt`; screenshot `S04_SERVER_START.png`.
6. On OT-PLC second terminal, `cd ~/sec524_run1`; run `sudo tcpdump -i enp0s8 -s 0 -w baseline.pcap 'tcp port 1502'`. Replace interface with actual `OTLAB` NIC. Capture screenshot `S05_BASELINE_CAPTURE_RUNNING.png`.
7. On OT-CLIENT `python3 ~/quick_lab.py read` three times, 1 sec apart (or the loop below). Screenshot `S06_BASELINE_READS_50.png`. Stop baseline tcpdump with Ctrl+C.
8. On OT-PLC start `sudo tcpdump -i enp0s8 -s 0 -w incident.pcap 'tcp port 1502'`. Screenshot `S07_INCIDENT_CAPTURE_RUNNING.png`.
9. On OT-CLIENT execute `read` then `write 90` then `read`. Screenshot all three outputs `S08_CLIENT_50_90_90.png`. Stop incident tcpdump with Ctrl+C.
10. On OT-PLC screenshot console log line `WRITE_APPLIED`: `S09_PLC_WRITE_APPLIED.png`. Stop server with Ctrl+C, then inspect `grep 'WRITE_APPLIED' plc_audit.jsonl`.
11. On OT-PLC run `tshark -r baseline.pcap -d tcp.port==1502,mbtcp -Y 'modbus.func_code == 6'` (should show nothing), and `tshark -r incident.pcap -d tcp.port==1502,mbtcp -Y 'modbus.func_code == 6' -V`. Screenshot `S10_BASELINE_NEGATIVE_CONTROL.png` and `S11_MODBUS_WRITE_DECODE.png`.
12. On OT-PLC run `sha256sum baseline.pcap incident.pcap plc_audit.jsonl plc_console.txt > SHA256SUMS.txt`; then `sha256sum -c SHA256SUMS.txt`. Screenshot `S12_HASH_VERIFIED.png`.
13. Record all hashes, timestamps, filenames, tool versions, chain of custody, and source paths. Do not edit original evidence files.

## Commands on OT-CLIENT

```bash
for i in 1 2 3; do python3 ~/quick_lab.py read; sleep 1; done

python3 ~/quick_lab.py read
python3 ~/quick_lab.py write 90
python3 ~/quick_lab.py read
```

## Presentation recording (do later)

- Use a **new** run directory `~/sec524_demo` on OT-PLC and OT-CLIENT, so old evidence is never overwritten and the new simulator starts at 50. Keep `~/quick_lab.py` in both home directories.
- Arrange both VM windows side by side or use a host-level screen recorder that can capture switching between VMs; the VirtualBox VM-native recorder normally records one guest display, not both guests together.
- **PRESS START RECORD (VIDEO)** once both VMs are booted, configured, isolated, scripts copied, terminals arranged — but before starting the simulator. Start with 15–30 sec of introduction and the two VM IP configurations.
- Launch simulator; start baseline `tcpdump`, generate reads, stop. Start incident `tcpdump`, perform read/write/read, stop. Show audit JSONL and `tshark` decode, hashes, then limitations. End screen recording.
- **Do not confuse video recording with `tcpdump`**: the packet captures must be started before their respective traffic events.

Note: This captures a software-simulated change, not a physical attack. The IP and Modbus traffic alone cannot identify the human actor or prove authorization.
