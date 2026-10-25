# SEC 524 — VirtualBox OT Forensics Lab

**Experiment:** Reconstruct a controlled, simulated unauthorized Modbus/TCP holding-register change. All traffic is restricted to an isolated VirtualBox Internal Network. No real PLC, actuator, or plant is present.

**Scope:** One in-memory register (zero-based register `16`, initial value `50`), one fictional setpoint. A read (`function 03`) returns its state; a write (`function 06`) can change it. A successful write is acknowledged by echoing its request, consistent with Modbus. The toy server does not provide real PLC control logic, industrial process physics, authentication, or actual safety implications.

## 1. VirtualBox topology

Use lightweight Ubuntu Linux guests. Two VMs are sufficient; a third read-only historian strengthens corroboration.

| VM | Role | IPv4 on `OTLAB` Internal Network |
|---|---|---|
| `OT-PLC` | simulated PLC + packet capture | `10.20.30.10/24` |
| `OT-CLIENT` | mock engineering workstation, generates controlled reads/writes | `10.20.30.20/24` |
| `OT-HIST` (optional) | independent read-only simulated historian | `10.20.30.30/24` |

During initial software installation only, permit **Adapter 1: NAT**. On every VM, add **Adapter 2: Internal Network, name `OTLAB`**, with **Cable connected**. The name must be identical on all VMs. Before testing, disable Adapter 1 (NAT) and any bridged adapters so the lab has no route to physical OT or the Internet.

On all Ubuntu guests with NAT enabled during preparation:

```bash
sudo apt update
sudo apt install -y python3 tcpdump tshark
```

Find the Internal Network device with `ip -br addr` (often `enp0s8`). Assuming `enp0s8`, assign temporary IPs separately:

```bash
# OT-PLC only:
sudo ip link set enp0s8 up
sudo ip addr add 10.20.30.10/24 dev enp0s8

# OT-CLIENT only:
sudo ip link set enp0s8 up
sudo ip addr add 10.20.30.20/24 dev enp0s8

# OT-HIST only (optional):
sudo ip link set enp0s8 up
sudo ip addr add 10.20.30.30/24 dev enp0s8
```

These are temporary addresses lost on reboot. Confirm `ip -br addr` and use `ping -c 3 10.20.30.10` from OT-CLIENT after OT-PLC comes online. Take a clean VirtualBox snapshot before testing. Use Shared Folders or clipboard to move scripts to the VMs *during preparation*; avoid re-enabling NAT while the simulated write test is running.

## 2. Move scripts and launch simulator

- Copy `quick_lab.py` to `OT-PLC` home directory.
- Copy the same `quick_lab.py` to `OT-CLIENT` home directory.
- Optional: copy `historian.py` to `OT-HIST` home directory.

On `OT-PLC`:

```bash
python3 -u quick_lab.py server | tee plc_console.txt
```

Leave running. It binds only to `10.20.30.10:1502` (a non-privileged lab port). It logs JSONL records into `plc_audit.jsonl` and starts register 16 at value 50.

On `OT-CLIENT`, first test the baseline:

```bash
python3 quick_lab.py read
```

Expected `Register 16 = 50`. A failed connection is usually a wrong guest interface/IP, inactive server, or incorrectly named Internal Network.

## 3. Baseline control capture

On `OT-PLC`, open a *second terminal* and start capture **before generating traffic**:

```bash
sudo tcpdump -i enp0s8 -s 0 -w baseline.pcap 'tcp port 1502'
```

On `OT-CLIENT`:

```bash
for i in 1 2 3; do python3 quick_lab.py read; sleep 1; done
```

Stop tcpdump with Ctrl+C. This negative control should contain Modbus reads and corresponding responses, but no function-06 write. Keep the original PCAP.

## 4. Simulated unauthorized change

Define the incident in your case notes: **no change request is approved for register 16 to increase from 50 to 90 during this period**. This is the case scenario; a Modbus frame alone does not establish whether the human action was authorized.

On `OT-PLC`, start a new capture:

```bash
sudo tcpdump -i enp0s8 -s 0 -w incident.pcap 'tcp port 1502'
```

On `OT-CLIENT`, execute these commands in sequence:

```bash
python3 quick_lab.py read
python3 quick_lab.py write 90
python3 quick_lab.py read
```

Expected client output is:

```text
Register 16 = 50
Write acknowledged: 90
Register 16 = 90
```

Stop tcpdump. Then stop the PLC simulator with Ctrl+C so its audit file is complete. **These are expectations, not observations until independently verified in your run.**

## 5. Optional independent historian

Start `historian.py` on a third VM `OT-HIST` before the incident and leave it polling until after the write:

```bash
python3 historian.py
```

It produces `historian.csv`, with UTC timestamp and observed register value. The interval is approximately two seconds. The next successful poll after the write should show the new value. Historian polling adds background reads to the PCAP; that is expected and improves the analysis challenge. For a deliberate timestamp-skew **separate run**, use `HISTORIAN_CLOCK_OFFSET_SECONDS=120 python3 historian.py` and label the file `historian_clock_skew.csv` after the run; this simulates a clock offset without changing the VM system clock. Keep skewed and normal runs clearly separated.

## 6. Offline forensic analysis

Copy the evidence files to an analysis folder **after acquisition**. Stop writers before computing integrity hashes:

```bash
sha256sum baseline.pcap incident.pcap plc_audit.jsonl > SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt
```

For `historian.csv`, hash it at the VM where it was acquired, include that hash in the manifest, and preserve the original. The checksum file itself is an evidence manifest, **not proof of authorization or chain of custody**.

Open PCAP in Wireshark. Because the lab uses TCP 1502 rather than standard 502, use **Analyze > Decode As > TCP port 1502 > Modbus/TCP**, or with tshark:

```bash
tshark -r incident.pcap -d tcp.port==1502,mbtcp -Y 'modbus.func_code == 6' -V
```

Check `source IP`, `destination IP`, `TCP port`, `transaction ID`, `unit ID`, `function code 06`, **zero-based register address 16**, value **90**, and the matching server acknowledgement. Correlate it to `WRITE_APPLIED` and the before/after reads; if `historian.csv` is available, add its next poll timestamp. For read-only baseline:

```bash
tshark -r baseline.pcap -d tcp.port==1502,mbtcp -Y 'modbus.func_code == 6'
```

Expected: no matching packets. You can additionally inspect all packets with `tshark -r incident.pcap -d tcp.port==1502,mbtcp -Y modbus -V`.

**If Wireshark does not decode packets as Modbus**, verify actual TCP traffic with filter `tcp.port == 1502` and re-check Decode As. If the PCAP is empty, capture on the PLC Internal Network interface (`ip -br addr`) rather than its NAT interface.

## 7. Fill the coursework based on actual observations

- Record VM identifiers, software versions, addresses, lab network isolation, and dataset origin (you generated the data).
- Create a chain-of-custody form: evidence ID, collector, collection UTC, original path, bytes, SHA-256, every transfer, and storage.
- Build a timeline comparing client requests, packet timestamps, PLC JSONL records, and optional historian readings. Normalize timestamps to UTC; preserve raw logs.
- Distinguish **observations** (write request, acknowledged response, simulator state) from **inference** (authorization status based on an external approval record) and **unknowns** (human identity behind a client IP).
- State limits honestly: this is a simple simulator, not an actual PLC or process; capture on the PLC VM is endpoint capture, not SPAN/TAP; there is no independent industrial historian unless you deploy the third VM; there is no physical process impact.
- Put original `.pcap`, `.jsonl`, `.csv`, hashes, screenshots of packet decode, executed commands and version output in supporting artifacts. Include screenshots in the report only as illustration.

Suggested screenshots: VirtualBox network isolation settings, IP configuration, PLC first read, the write and response, Wireshark function 06 fields, JSONL audit record, historian value transition (if used), and hash verification.

## 8. Report mapping

- **Part A:** VM architecture, software PLC, mock engineering station, Modbus PDU/MBAP, unauthorized setpoint-change hypothesis.
- **Part B:** volatile in-memory PLC state; missing human identity; clock error; incomplete capture; lack of native authentication; hash/chain-of-custody.
- **Part C:** preserve traffic and logs, prioritize volatile state, verify hashes, timeline/relationship reconstruction, alternative hypotheses, report limits.
- **Part D:** exact lab setup, commands, evidence table, annotated frames, log correlation, independent checks, outcomes, limitations.

## 9. Safety boundaries

This lab is explicitly restricted to simulated target `10.20.30.10` on `OTLAB`, never a physical plant network, industrial device, or corporate OT subnet. Do not bridge the virtual network. Do not aim the sample write command at any real controller. Only the teaching simulator and synthetic data are within scope.

## 10. References

- Modbus Organization, *MODBUS Application Protocol Specification V1.1b3*, sec. 6.3 (FC03) and 6.6 (FC06).
- Oracle VirtualBox, *User Guide*, Internal Networking / Promiscuous Mode.
- Wireshark, *Display Filter Reference: Modbus* and *Modbus/TCP*; `tshark` manual for Decode As.
