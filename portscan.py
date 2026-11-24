import argparse
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
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    return ~(s + (s >> 16)) & 0xFFFF


def local_ip(dst):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((dst, 80))
        return s.getsockname()[0]


def tcp_packet(src, dst, sport, dport, flags, seq=0):
    hdr = struct.pack("!HHLLBBHHH", sport, dport, seq, 0, 5 << 4, flags, 8192, 0, 0)
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src), socket.inet_aton(dst), 0, 6, len(hdr))
    return hdr[:16] + struct.pack("!H", checksum(pseudo + hdr)) + hdr[18:]


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
                        a, b = map(int, part.split("-", 1))
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
    while len(data) < n and (part := sock.recv(n - len(data))):
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
                if len(h := read_exact(s, 2)) == 2:
                    d = read_exact(s, struct.unpack("!H", h)[0])
                    if len(d) >= 12 and d[:2] == b"\xaa\xbb" and d[2] & 128:
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
    src_b, dst_b = socket.inet_aton(src), socket.inet_aton(dst)
    pending, opened, idx, limit = {}, {}, 0, min(limit, 40000)

    while idx < len(ports) or pending:
        now = time.monotonic()
        while idx < len(ports) and len(pending) < limit:
            while (sport := random.randint(20000, 60000)) in pending:
                pass
            seq = random.randint(1, 0xFFFFFFFF)
            sock.sendto(tcp_packet(src, dst, sport, ports[idx], 2, seq), (dst, 0))
            pending[sport] = (now, ports[idx], seq)
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
                if (t[12] >> 4) * 4 < 20 or len(t) < (t[12] >> 4) * 4:
                    continue
                remote, local, _, ack, _, flags = struct.unpack("!HHLLBB", t[:14])
                if local in pending and pending[local][1] == remote and ack == (pending[local][2] + 1) & 0xFFFFFFFF:
                    start = pending.pop(local)[0]
                    if flags & 0x12 == 0x12:
                        opened[remote] = (time.monotonic() - start) * 1000
                        sock.sendto(tcp_packet(src, dst, local, remote, 4, ack), (dst, 0))

        now = time.monotonic()
        pending = {k: v for k, v in pending.items() if now - v[0] <= timeout}
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
    local_port, src_b, dst_b = udp.getsockname()[1], socket.inet_aton(src), socket.inet_aton(dst)
    http_req = f"HEAD / HTTP/1.1\r\nHost: {dst}\r\n\r\n".encode()
    probes = {53: DNS_QUERY, 5353: DNS_QUERY, 7: b"PING_ECHO_98765", 80: http_req, 443: http_req}
    pending, opened, idx = {}, {}, 0

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
                        opened[addr[1]] = (time.monotonic() - pending.pop(addr[1])) * 1000
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

    if args.timeout <= 0 or args.num_threads <= 0:
        sys.exit("Таймаут и распараллеливание должны быть положительными")
    if os.geteuid() != 0:
        sys.exit("Требуются права root")

    dst = socket.gethostbyname(args.ip)
    src = local_ip(dst)
    targets = parse_targets(args.targets)
    tcp = scan_tcp(src, dst, sorted({p for pr, p in targets if pr == "TCP"}), args.timeout, args.num_threads)
    udp = scan_udp(src, dst, sorted({p for pr, p in targets if pr == "UDP"}), args.timeout, args.num_threads)

    for proto, port in targets:
        res = (tcp if proto == "TCP" else udp).get(port)
        if res is not None:
            parts = [proto, str(port)]
            if args.verbose:
                parts.append(f"{res:.2f}")
            if args.guess:
                parts.append(guess(proto, dst, port, args.timeout))
            print(" ".join(parts))


if __name__ == "__main__":
    main()