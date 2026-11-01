# Six synthetic PCAPs for NetFlow

All six captures were generated locally by `generate.py`. They are deterministic
training examples, not records of real attacks or malware execution. Addresses
and domains are reserved for examples. The HTTP transfer contains inert bytes;
the simulated command-and-control (C2) traffic contains only `PING`/`OK` text.

| PCAP | Packets | What it demonstrates | Expected NetFlow result |
| --- | ---: | --- | --- |
| `01-simulated-ddos-syn-flood.pcap` | 3,600 | 24 sources sending incomplete TCP SYN handshakes to one target | High: possible SYN flood |
| `02-simulated-arp-spoofing.pcap` | 300 | One gateway IP announced with two MAC addresses | Warning: conflicting ARP mapping |
| `03-simulated-dns-spoofing.pcap` | 270 | 30 DNS transactions with a conflicting answer from an unexpected server, plus ordinary lookups | Warning: unexpected server and conflicting replies |
| `04-simulated-ssh-connection-burst.pcap` | 330 | 110 completed TCP handshakes to port 22 | Warning: repeated SSH connection attempts; login outcomes are not observable |
| `05-simulated-http-file-download.pcap` | 261 | HTTP GET and 128 KiB inert binary download | Clear: ordinary file transfer, no configured red flag |
| `06-simulated-malware-c2-beacon.pcap` | 350 | 70 periodic HTTP check-ins resembling a trojan beacon | Warning: regularly repeated TCP connections; no malware attribution |

Upload one `.pcap` file at a time through **Dashboard → Upload a capture**.
Zeek and the local packet analytics must be available for the full website
analysis. These synthetic traces should not be interpreted as proof that the
application can identify every real attack. The DDoS trace is a training
approximation, and the beacon trace does not contain real malware.

To regenerate exactly the same captures with the project's Python dependencies:

```bash
python demo_pcaps/generate.py
```
