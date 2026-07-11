SNI matching tests live in `tests/sni_matching/` and cover both TCP TLS
(scapy-crafted ClientHellos via `tls_sni_send.py`) and QUIC v1/v2
Initials (aioquic via `quic_sni_send.py`) with real on-the-wire
handshakes.  This is the consolidated home — `tests/quic_sni_matching/`
and `tests/policy_sanity/test_sni_matching.py` are gone.

Cert revocation lives in `tests/rotation/test_tls_revocation.py` and
`tests/rotation/test_multi_node_revocation.py`.

Topology `packages` supports per-feature package sets: nodes may declare
`packages: features: {vanilla: [...], ips: [...], ipfix: [...],
ips-ipfix: [...]}` and `pytest --feature <name>` (default `vanilla`)
selects which set installs — this is how the general suites run against
the IPS/IPFIX engine builds.  A plain `packages:` list is
feature-agnostic and installs regardless of the flag (used by suites
pinned to one build, e.g. `tests/ips_ids/`, and by controller nodes).
