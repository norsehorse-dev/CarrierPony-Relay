#!/usr/bin/env python3
"""
ponystun - a minimal STUN-only responder (RFC 5389) for a CarrierPony/PonyDirect
relay box. It answers Binding requests with the sender's public ip:port in an
XOR-MAPPED-ADDRESS attribute, so a client behind NAT can learn its server-reflexive
address for UDP hole punching. It does nothing else: no TURN, no relaying, no
authentication, no logging of addresses. Pure standard library, one UDP port.

Run:  python3 ponystun.py [--host 0.0.0.0] [--port 3478]
"""

import argparse
import socket
import struct

MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
ATTR_XOR_MAPPED_ADDRESS = 0x0020


def build_success(transaction_id: bytes, ip: str, port: int) -> bytes:
    # XOR-MAPPED-ADDRESS value: reserved(1) | family(1) | x-port(2) | x-addr(4)
    x_port = port ^ (MAGIC_COOKIE >> 16)
    addr = socket.inet_aton(ip)                      # 4 bytes, network order
    cookie = struct.pack(">I", MAGIC_COOKIE)
    x_addr = bytes(a ^ c for a, c in zip(addr, cookie))
    value = struct.pack(">BBH", 0x00, 0x01, x_port) + x_addr
    attr = struct.pack(">HH", ATTR_XOR_MAPPED_ADDRESS, len(value)) + value
    header = struct.pack(">HHI", BINDING_SUCCESS, len(attr), MAGIC_COOKIE) + transaction_id
    return header + attr


def handle(data, addr):
    # Only answer well-formed IPv4 Binding requests; anything else is ignored so the
    # responder cannot be turned into an amplifier for arbitrary traffic.
    if len(data) < 20:
        return None
    msg_type, msg_len, cookie = struct.unpack(">HHI", data[:8])
    if msg_type != BINDING_REQUEST or cookie != MAGIC_COOKIE:
        return None
    if len(data) < 20 + msg_len:
        return None
    transaction_id = data[8:20]
    ip, port = addr[0], addr[1]
    if ":" in ip:            # IPv6 source; this v1 responder is IPv4-only
        return None
    return build_success(transaction_id, ip, port)


def main() -> None:
    ap = argparse.ArgumentParser(description="Minimal STUN-only responder")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=3478)
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    print(f"ponystun listening on {args.host}:{args.port}/udp", flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(2048)
        except OSError:
            continue
        reply = handle(data, addr)
        if reply is not None:
            try:
                sock.sendto(reply, addr)
            except OSError:
                pass


if __name__ == "__main__":
    main()
