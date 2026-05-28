SNI matching tests live in `tests/sni_matching/` and cover both TCP TLS
(scapy-crafted ClientHellos via `tls_sni_send.py`) and QUIC v1/v2
Initials (aioquic via `quic_sni_send.py`) with real on-the-wire
handshakes.  This is the consolidated home — `tests/quic_sni_matching/`
and `tests/policy_sanity/test_sni_matching.py` are gone.

Cert revocation lives in `tests/rotation/test_tls_revocation.py` and
`tests/rotation/test_multi_node_revocation.py`.
