# Vulture whitelist: names that are NOT dead code but which vulture cannot
# see being used. Vulture parses this file as ordinary usage, so every name
# referenced here is treated as "used". Keep entries minimal and documented —
# anything added here is exempt from dead-code detection.
#
# Run the lint with:  make dead-code

# --- Public API exercised only from examples/ (not scanned by the lint) ---
# examples/conftest.py drives these via libvirt_utils.* / topology.*
preflight  # netsim/libvirt_utils.py
cleanup_leftover_taps  # netsim/libvirt_utils.py
cleanup_leftover_vms  # netsim/libvirt_utils.py
log_vm_count  # netsim/libvirt_utils.py
_.get_node  # netsim/topology.py — Topology.get_node()
_.packages_for  # netsim/topology.py — Node.packages_for(--feature selection)
_.has_packages  # netsim/topology.py — Node.has_packages

# --- Dataclass fields read via attribute access / YAML (de)serialization ---
ipv6_subnet  # netsim/topology.py — Network.ipv6_subnet
version  # netsim/topology.py — Topology.version
package_dir  # netsim/topology.py — Topology.package_dir, read by conftest

# --- ElementTree idiom: `ET.SubElement(...).text = "..."` is a write that
#     vulture sees as an unused attribute; the value is serialized into XML. ---
_.text  # netsim/vm.py — libvirt domain XML construction
