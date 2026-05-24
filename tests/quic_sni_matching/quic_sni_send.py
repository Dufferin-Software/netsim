#!/usr/bin/env python3
# Copyright (c) Dufferin Software

"""
Fire a single real QUIC v1 Initial packet with a chosen SNI.

Deployed onto the netsim client node so that the QUIC SNI matching e2e
tests can exercise the policy-engine BPF tail-call → userspace decryption
→ flow-verdict path with real-on-the-wire QUIC traffic.

Usage:
    quic_sni_send.py <server_ip> <server_port> <sni>

The script uses aioquic to construct a valid client Initial packet
(long header, version v1, DCID, encrypted ClientHello with the supplied
server_name extension) and sends it via a UDP socket.  We do not wait
for a server response — the policy-engine inspector only needs the
Initial to cross ingress.

The script exits 0 on send success, 1 on any failure.  Output is short
and machine-friendly so the test harness can include it on assertion
failure.
"""

import socket
import ssl
import sys
import time

try:
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
except ImportError as e:
    print(f"missing aioquic: {e}", file=sys.stderr)
    sys.exit(1)


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: quic_sni_send.py <server_ip> <server_port> <sni>", file=sys.stderr
        )
        return 1

    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    sni = sys.argv[3]

    config = QuicConfiguration(
        is_client=True,
        server_name=sni,
        verify_mode=ssl.CERT_NONE,
        alpn_protocols=["h3"],
    )
    conn = QuicConnection(configuration=config)

    now = time.time()
    conn.connect((server_ip, server_port), now=now)

    datagrams = conn.datagrams_to_send(now=now)
    if not datagrams:
        print("aioquic produced no datagrams to send", file=sys.stderr)
        return 1

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sent = 0
        for data, addr in datagrams:
            sock.sendto(data, addr)
            sent += len(data)
        print(f"sent {sent} bytes to {server_ip}:{server_port} sni={sni}")
    finally:
        sock.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
