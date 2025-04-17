import argparse
import socket
import threading
import time
from scapy.all import IP, TCP, sr1
import traceback



print_lock = threading.Lock()

def banner_grab(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=2) as sock:
            return sock.recv(1024).decode(errors='ignore').strip()
    except:
        return ""

def tcp_connect_scan(ip, port, args):
    try:
        with socket.create_connection((ip, port), timeout=args.timeout):
            service = socket.getservbyport(port, "tcp") if port < 1024 else "unknown"
            banner = banner_grab(ip, port) if args.banner else ""
            with print_lock:
                print(f"[+] Open | {ip}:{port} | Service: {service} | Banner: {banner}")
    except:
        if args.verbose:
            with print_lock:
                print(f"[-] Closed/Filtered | {ip}:{port}")

def syn_scan(ip, port, args):
    pkt = IP(dst=ip)/TCP(dport=port, flags='S')
    resp = sr1(pkt, timeout=args.timeout, verbose=0)
    if resp and resp.haslayer(TCP):
        if resp[TCP].flags == 0x12:  # SYN-ACK
            banner = banner_grab(ip, port) if args.banner else ""
            service = socket.getservbyport(port, "tcp") if port < 1024 else "unknown"
            with print_lock:
                print(f"[+] Open | {ip}:{port} | Service: {service} | Banner: {banner}")
        elif resp[TCP].flags == 0x14 and args.verbose:  # RST-ACK
            with print_lock:
                print(f"[-] Closed | {ip}:{port}")




def scan_worker(ip, port, args):
    try:
        for _ in range(args.retry + 1):
            if args.scan_type == "syn":
                syn_scan(ip, port, args)
            else:
                tcp_connect_scan(ip, port, args)
            break
    except Exception as e:
        with print_lock:
            print(f"[!] Exception scanning {ip}:{port} — {e}")
            traceback.print_exc()


def parse_ip_range(ip_range):
    if '-' in ip_range:
        start, end = ip_range.split('-')
        base = '.'.join(start.split('.')[:-1])
        return [f"{base}.{i}" for i in range(int(start.split('.')[-1]), int(end.split('.')[-1])+1)]
    else:
        return ip_range.split(',')

def parse_ports(port_range):
    if '-' in port_range:
        start, end = map(int, port_range.split('-'))
        return list(range(start, end+1))
    else:
        return list(map(int, port_range.split(',')))

def main():
    parser = argparse.ArgumentParser(description="Python Port Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP(s), e.g. 192.168.1.1 or 192.168.1.1-192.168.1.10")
    parser.add_argument("-p", "--ports", required=True, help="Ports to scan, e.g. 22,80 or 1-1024")
    parser.add_argument("-s", "--scan-type", choices=["connect", "syn"], default="connect", help="Scan type")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="Output to file (txt)")
    parser.add_argument("--banner", action="store_true", help="Enable banner grabbing")
    parser.add_argument("--retry", type=int, default=0, help="Number of retries")
    parser.add_argument("--timeout", type=int, default=2, help="Timeout in seconds")
    parser.add_argument("--exclude", help="IPs or ports to exclude, e.g. 192.168.1.1,443")
    parser.add_argument("-n", "--no-resolve", action="store_true", help="Disable reverse DNS resolution")
    args = parser.parse_args()

    targets = parse_ip_range(args.target)
    ports = parse_ports(args.ports)

    excluded_ips = []
    excluded_ports = []
    if args.exclude:
        for item in args.exclude.split(','):
            if item.isdigit():
                excluded_ports.append(int(item))
            else:
                excluded_ips.append(item)

    threads = []
    for ip in targets:
        if ip in excluded_ips:
            continue
        for port in ports:
            if port in excluded_ports:
                continue
            thread = threading.Thread(target=scan_worker, args=(ip, port, args))
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()

    print("[+] Scan complete.")

if __name__ == "__main__":
    main()
