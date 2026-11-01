"""Build deterministic, isolated training PCAPs (no attack or malware execution)."""
from pathlib import Path
import socket

import dpkt


HERE = Path(__file__).resolve().parent
BASE = 1_700_000_000.0
CLIENT = b'\x02\x00\x00\x00\x00\x10'
SERVER = b'\x02\x00\x00\x00\x00\x20'


def address(value):
    return socket.inet_aton(value)


def frame(source, target, transport):
    protocol = 6 if isinstance(transport, dpkt.tcp.TCP) else 17 if isinstance(transport, dpkt.udp.UDP) else 1
    ip = dpkt.ip.IP(src=address(source), dst=address(target), p=protocol, ttl=64, data=transport)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=CLIENT, dst=SERVER, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def tcp(source, target, sport, dport, flags, seq=100, ack=0, data=b''):
    packet = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, win=8192, data=data)
    return frame(source, target, packet)


def udp(source, target, sport, dport, data):
    return frame(source, target, dpkt.udp.UDP(sport=sport, dport=dport, data=data))


def save(name, records):
    path = HERE / name
    with path.open('wb') as stream:
        writer = dpkt.pcap.Writer(stream)
        count = 0
        for ts, packet in records:
            writer.writepkt(packet, ts=BASE + ts)
            count += 1
        writer.close()
    print(f'{name}: {count} packets, {path.stat().st_size} bytes')


def ddos():
    victim = '10.0.0.20'
    for index in range(3600):
        source = f'10.0.1.{1 + index % 24}'
        yield index / 3600, tcp(source, victim, 20000 + index, 443, dpkt.tcp.TH_SYN, seq=1000 + index)


def arp_spoof():
    gateway = address('192.168.56.1')
    victim = address('192.168.56.20')
    normal = b'\x02\xaa\x00\x00\x00\x01'
    rogue = b'\x02\xee\x00\x00\x00\x66'
    for index in range(300):
        mac = normal if index % 4 == 0 else rogue
        arp = dpkt.arp.ARP(op=2, spa=gateway, sha=mac, tpa=victim, tha=CLIENT)
        yield index / 5, bytes(dpkt.ethernet.Ethernet(src=mac, dst=CLIENT, type=dpkt.ethernet.ETH_TYPE_ARP, data=arp))


def dns_spoof():
    client, resolver, rogue = '10.0.0.30', '10.0.0.53', '10.0.0.99'
    for index in range(120):
        q = dpkt.dns.DNS.Q(name=f'portal{index}.example.test', type=dpkt.dns.DNS_A)
        identifier = index + 1
        query = dpkt.dns.DNS(id=identifier, qd=[q])
        def reply(ip):
            answer = dpkt.dns.DNS.RR(name=q.name, type=dpkt.dns.DNS_A, ttl=60, rdata=address(ip))
            return dpkt.dns.DNS(id=identifier, qr=1, qd=[q], an=[answer])
        start = index * .2
        port = 30000 + index
        yield start, udp(client, resolver, port, 53, bytes(query))
        yield start + .01, udp(resolver, client, 53, port, bytes(reply('203.0.113.10')))
        if index < 30:
            yield start + .02, udp(rogue, client, 53, port, bytes(reply('203.0.113.99')))


def ssh_connections():
    source, target = '10.0.0.40', '10.0.0.22'
    for index in range(110):
        port, seq, server_seq = 40000 + index, 1000 + index * 10, 5000 + index * 10
        start = index * .1
        yield start, tcp(source, target, port, 22, dpkt.tcp.TH_SYN, seq=seq)
        yield start + .01, tcp(target, source, 22, port, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, seq=server_seq, ack=seq + 1)
        yield start + .02, tcp(source, target, port, 22, dpkt.tcp.TH_ACK, seq=seq + 1, ack=server_seq + 1)


def file_download():
    source, target, port = '10.0.0.50', '203.0.113.50', 45000
    yield 0, tcp(source, target, port, 80, dpkt.tcp.TH_SYN, seq=100)
    yield .01, tcp(target, source, 80, port, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, seq=500, ack=101)
    yield .02, tcp(source, target, port, 80, dpkt.tcp.TH_ACK, seq=101, ack=501)
    request = b'GET /training-dataset.bin HTTP/1.1\r\nHost: downloads.example.test\r\n\r\n'
    yield .03, tcp(source, target, port, 80, dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, seq=101, ack=501, data=request)
    body = bytes(range(256)) * 512  # Inert 128 KiB transfer; no executable or script.
    header = (b'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n'
              b'Content-Disposition: attachment; filename="training-dataset.bin"\r\n'
              + f'Content-Length: {len(body)}\r\n\r\n'.encode())
    sequence = 501
    for index in range(257):
        segment = (header if index == 0 else b'') + body[index * 512:(index + 1) * 512]
        if segment:
            yield .05 + index * .003, tcp(target, source, 80, port, dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK,
                                         seq=sequence, ack=101 + len(request), data=segment)
            sequence += len(segment)
    yield 1, tcp(target, source, 80, port, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK, seq=sequence, ack=101 + len(request))


def malware_beacon_simulation():
    source, target = '10.0.0.60', '198.51.100.60'
    for index in range(70):
        port, seq, server_seq = 50000 + index, 1000 + index * 100, 5000 + index * 100
        start = index * 12
        request = (b'POST /checkin HTTP/1.1\r\nHost: beacon.example.test\r\n'
                   b'Content-Length: 4\r\n\r\nPING')
        response = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK'
        yield start, tcp(source, target, port, 80, dpkt.tcp.TH_SYN, seq=seq)
        yield start + .01, tcp(target, source, 80, port, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, seq=server_seq, ack=seq + 1)
        yield start + .02, tcp(source, target, port, 80, dpkt.tcp.TH_ACK, seq=seq + 1, ack=server_seq + 1)
        yield start + .03, tcp(source, target, port, 80, dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK,
                              seq=seq + 1, ack=server_seq + 1, data=request)
        yield start + .04, tcp(target, source, 80, port, dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK,
                              seq=server_seq + 1, ack=seq + 1 + len(request), data=response)


if __name__ == '__main__':
    save('01-simulated-ddos-syn-flood.pcap', ddos())
    save('02-simulated-arp-spoofing.pcap', arp_spoof())
    save('03-simulated-dns-spoofing.pcap', dns_spoof())
    save('04-simulated-ssh-connection-burst.pcap', ssh_connections())
    save('05-simulated-http-file-download.pcap', file_download())
    save('06-simulated-malware-c2-beacon.pcap', malware_beacon_simulation())
