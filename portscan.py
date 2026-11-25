import argparse
import math
import os
import random
import select
import socket
import struct
import sys
import time

DNS_QUERY = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    return ~(total + (total >> 16)) & 0xFFFF


def local_ip(dst):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((dst, 80))
        addr = s.getsockname()[0]
        return addr


def tcp_packet(src, dst, sport, dport, flags, seq=0):
    hdr = struct.pack("!HHLLBBHHH", sport, dport, seq, 0, 5 << 4, flags, 8192, 0, 0)
    src_bytes = socket.inet_aton(src)
    dst_bytes = socket.inet_aton(dst)
    pseudo = struct.pack("!4s4sBBH", src_bytes, dst_bytes, 0, 6, len(hdr))
    csum = checksum(pseudo + hdr)
    return hdr[:16] + struct.pack("!H", csum) + hdr[18:]


def parse_targets(specs):
    result = []
    for spec in specs:
        proto, sep, ports = spec.partition("/")
        proto = proto.upper()
        if proto not in ("TCP", "UDP"):
            sys.exit(f"Недопустимый протокол: {proto}")
        try:
            values = []
            if not sep or not ports:
                values = range(1, 65536)
            else:
                for part in ports.split(","):
                    if "-" in part:
                        start_str, end_str = part.split("-", 1)
                        a = int(start_str)
                        b = int(end_str)
                        if a > b:
                            raise ValueError
                        values.extend(range(a, b + 1))
                    else:
                        values.append(int(part))
        except ValueError:
            sys.exit(f"Недопустимый диапазон портов: {ports}")
        for p in values:
            if not 1 <= p <= 65535:
                sys.exit(f"Недопустимый порт: {p}")
            result.append((proto, p))
    return result


def read_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            break
        data.extend(part)
    return bytes(data)


def guess(proto, ip, port, timeout):
    http_req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode()
    if proto == "TCP":
        for req, name in [(http_req, "HTTP"), (b"ECHO_PROBE_98765\r\n", "ECHO")]:
            try:
                with socket.create_connection((ip, port), timeout) as s:
                    s.settimeout(timeout)
                    s.sendall(req)
                    reply = s.recv(1024)
                    if (name == "HTTP" and reply.startswith(b"HTTP/1.")) or (name == "ECHO" and reply == req):
                        return name
            except OSError:
                pass
        try:
            with socket.create_connection((ip, port), timeout) as s:
                s.settimeout(timeout)
                s.sendall(struct.pack("!H", len(DNS_QUERY)) + DNS_QUERY)
                header = read_exact(s, 2)
                if len(header) == 2:
                    length = struct.unpack("!H", header)[0]
                    payload = read_exact(s, length)
                    if len(payload) >= 12 and payload[:2] == b"\xaa\xbb" and payload[2] & 128:
                        return "DNS"
        except OSError:
            pass
    else:
        checks = [
            (DNS_QUERY, "DNS", lambda d: len(d) >= 12 and d[:2] == b"\xaa\xbb" and d[2] & 128),
            (b"PING_ECHO_98765", "ECHO", lambda d: d == b"PING_ECHO_98765"),
            (http_req, "HTTP", lambda d: d.startswith(b"HTTP/1.")),
        ]
        for payload, name, check in checks:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    s.sendto(payload, (ip, port))
                    reply, addr = s.recvfrom(1024)
                    if addr[0] == ip and check(reply):
                        return name
            except OSError:
                pass
    return "-"


def drain(sock):
    while True:
        try:
            yield sock.recvfrom(65535)
        except BlockingIOError:
            break


def scan_tcp(src, dst, ports, timeout, limit):
    if not ports:
        return {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setblocking(False)
    poller = select.poll()
    poller.register(sock, select.POLLIN)
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)
    pending = {}
    recent = {}
    opened = {}
    idx = 0
    limit = min(limit, 40000)

    while idx < len(ports) or pending or recent:
        now = time.monotonic()
        while idx < len(ports) and len(pending) < limit:
            sport = random.randint(20000, 60000)
            while sport in pending or sport in recent:
                sport = random.randint(20000, 60000)
            seq = random.randint(1, 0xFFFFFFFF)
            dport = ports[idx]
            pkt = tcp_packet(src, dst, sport, dport, 2, seq)
            sock.sendto(pkt, (dst, 0))
            pending[sport] = (now, dport, seq)
            recent[sport] = (dport, seq, now, now + timeout * 2)
            idx += 1

        for _, event in poller.poll(10):
            if not event & select.POLLIN:
                continue
            for data, addr in drain(sock):
                if addr[0] != dst or len(data) < 40 or data[0] >> 4 != 4 or data[9] != 6:
                    continue
                ihl = (data[0] & 15) * 4
                if ihl < 20 or len(data) < ihl + 20 or data[12:16] != dst_b or data[16:20] != src_b:
                    continue
                t = data[ihl:]
                tcp_hlen = (t[12] >> 4) * 4
                if tcp_hlen < 20 or len(t) < tcp_hlen:
                    continue
                remote, local, _, ack, _, flags = struct.unpack("!HHLLBB", t[:14])
                if local in pending:
                    start, exp_port, exp_seq = pending[local]
                    expected_ack = (exp_seq + 1) & 0xFFFFFFFF
                    if exp_port == remote and ack == expected_ack:
                        pending.pop(local)
                        recent.pop(local, None)
                        if flags & 0x12 == 0x12:
                            opened[remote] = (time.monotonic() - start) * 1000
                            rst_pkt = tcp_packet(src, dst, local, remote, 4, ack)
                            sock.sendto(rst_pkt, (dst, 0))
                elif flags & 0x12 == 0x12 and local in recent:
                    rec_port, rec_seq, sent_at, _ = recent[local]
                    expected_ack = (rec_seq + 1) & 0xFFFFFFFF
                    if rec_port == remote and ack == expected_ack:
                        if remote not in opened:
                            opened[remote] = (time.monotonic() - sent_at) * 1000
                        rst_pkt = tcp_packet(src, dst, local, remote, 4, ack)
                        sock.sendto(rst_pkt, (dst, 0))
                        recent.pop(local, None)

        now = time.monotonic()
        pending = {k: v for k, v in pending.items() if now - v[0] <= timeout}
        recent = {k: v for k, v in recent.items() if v[3] > now}
    sock.close()
    return opened


def scan_udp(src, dst, ports, timeout, limit):
    if not ports:
        return {}
    icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((src, 0))
    icmp.setblocking(False)
    udp.setblocking(False)
    poller = select.poll()
    poller.register(icmp, select.POLLIN)
    poller.register(udp, select.POLLIN)
    local_port = udp.getsockname()[1]
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)
    http_req = f"HEAD / HTTP/1.1\r\nHost: {dst}\r\n\r\n".encode()
    probes = {53: DNS_QUERY, 5353: DNS_QUERY, 7: b"PING_ECHO_98765", 80: http_req, 443: http_req}
    pending = {}
    opened = {}
    idx = 0

    while idx < len(ports) or pending:
        now = time.monotonic()
        while idx < len(ports) and len(pending) < limit:
            p = ports[idx]
            udp.sendto(probes.get(p, b"\0"), (dst, p))
            pending[p] = now
            idx += 1

        for fd, event in poller.poll(10):
            if not event & select.POLLIN:
                continue
            if fd == udp.fileno():
                for _, addr in drain(udp):
                    if addr[0] == dst and addr[1] in pending:
                        start = pending.pop(addr[1])
                        opened[addr[1]] = (time.monotonic() - start) * 1000
            else:
                for data, _ in drain(icmp):
                    if len(data) < 28 or data[0] >> 4 != 4 or data[9] != 1:
                        continue
                    ihl = (data[0] & 15) * 4
                    pos = ihl + 8
                    if ihl < 20 or len(data) < pos + 28 or data[ihl] != 3 or data[pos] >> 4 != 4 or data[pos + 9] != 17:
                        continue
                    inner = (data[pos] & 15) * 4
                    if inner >= 20 and len(data) >= pos + inner + 8 and data[pos + 12:pos + 20] == src_b + dst_b:
                        sport, dport = struct.unpack("!HH", data[pos + inner:pos + inner + 4])
                        if sport == local_port:
                            pending.pop(dport, None)

        now = time.monotonic()
        pending = {k: v for k, v in pending.items() if now - v <= timeout}
    icmp.close()
    udp.close()
    return opened


def main():
    parser = argparse.ArgumentParser(prog="portscan")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("-j", "--num-threads", type=int, default=256)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-g", "--guess", action="store_true")
    parser.add_argument("ip")
    parser.add_argument("targets", nargs="+")
    args = parser.parse_args()

    if not math.isfinite(args.timeout) or args.timeout <= 0 or args.num_threads <= 0:
        sys.exit("Таймаут и распараллеливание должны быть положительными")
    if os.geteuid() != 0:
        sys.exit("Требуются права root")

    dst = socket.gethostbyname(args.ip)
    src = local_ip(dst)
    targets = parse_targets(args.targets)
    tcp_ports = sorted({p for pr, p in targets if pr == "TCP"})
    udp_ports = sorted({p for pr, p in targets if pr == "UDP"})
    tcp = scan_tcp(src, dst, tcp_ports, args.timeout, args.num_threads)
    udp = scan_udp(src, dst, udp_ports, args.timeout, args.num_threads)

    for proto, port in targets:
        table = tcp if proto == "TCP" else udp
        res = table.get(port)
        if res is not None:
            parts = [proto, str(port)]
            if args.verbose:
                parts.append(f"{res:.2f}")
            if args.guess:
                parts.append(guess(proto, dst, port, args.timeout))
            print(" ".join(parts))


if __name__ == "__main__":
    main()