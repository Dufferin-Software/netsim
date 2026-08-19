# NetSim - Network Topology Simulator

Lightweight libvirt/QEMU topology runner with cloud-init user provisioning and automatic networking.

## Features
- YAML-described topologies (networks and nodes)
- Libvirt/QEMU VMs with COW overlays
- Automatic tap/bridge setup per network
- Cloud-init ISO auto-generated (user `netsim`, SSH key from `~/.ssh/id_rsa.pub`)
- SSH port-forwarding per node (2200 + node index)
- Image caching and auto-download

## System Requirements
- Linux with KVM and bridge support
- libvirt daemon running
- Packages (Ubuntu/Debian):
  ```bash
  sudo apt-get install -y \
    libvirt-daemon-system libvirt-clients libvirt-dev \
    qemu-system-x86 \
    python3-libvirt \
    genisoimage \
    bridge-utils \
    swtpm
  ```
- Python 3.9+
- SSH key at `~/.ssh/id_rsa.pub` (generate with `ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa` if missing)

## Project Setup
```bash
poetry install
source .venv/bin/activate
sudo ./setup-user-mode.sh   # adds you to libvirt/kvm and configures sudoers for ip commands
# log out/in for group changes
```

## Quick Start
```bash
# Start example topology (creates bridges/taps, cloud-init ISO, boots VMs)
netsim start examples/two-node-topology.yaml

# Show connection info (SSH ports, status)
netsim connect examples/two-node-topology.yaml

# SSH to node1 (mgmt port 2200)
ssh -p 2200 netsim@localhost

# Stop / resume
netsim stop examples/two-node-topology.yaml
netsim start examples/two-node-topology.yaml

# Destroy (remove VMs, taps, bridges)
netsim destroy examples/two-node-topology.yaml
```

## Topology Basics
- Networks: name, subnet, mtu
- Nodes: name, image (path or {name,url,checksum}), memory, vcpus, networks (list of network names to connect)
- Interfaces: auto-allocated at start time. First network = eth0 (management), additional networks = eth1, eth2, etc.
- IPs: auto-allocated from each subnet starting at .10 (gateway is .1)
- Example: see `examples/two-node-topology.yaml`

## Cloud-Init
- A cached ISO is generated at `~/.netsim/cloud-init/cloud-init-netsim.iso`
- Creates user `netsim` with SSH key from `~/.ssh/id_rsa.pub`
- Attached as SATA CD-ROM to each VM automatically

## Commands
- `netsim start <topology.yaml>`
- `netsim stop <topology.yaml>`
- `netsim status <topology.yaml>`
- `netsim connect <topology.yaml>`
- `netsim destroy <topology.yaml>`
- `netsim image list|download|remove|clear`

## Writing Tests

`netsim.testkit` is a pytest plugin that turns a topology into fixtures: booted
VMs, SSH access, netplan-configured interfaces, and `.deb` installation. Install
it with the extra, then opt in from your project's rootdir `conftest.py`:

```bash
pip install 'netsim[testkit] @ git+ssh://git@github.com/Dufferin-Software/netsim.git@v0.2.0'
```

```python
# conftest.py
pytest_plugins = ["netsim.testkit.plugin"]
```

A suite is a directory holding its topology, named after it — a test in
`tests/mysuite/` loads `tests/mysuite/mysuite.yaml`. From there the fixtures
`topology`, `nodes`, `node_interfaces`, `configure_node_interfaces` and
`install_user_packages` are available, along with the options `--package-dir`,
`--feature`, `--pause-on-failure` and `--tpm`. Inherit `BaseTopologyTests` to
pick up the standard allocation, interface and connectivity assertions.

`tests/two_node_iperf/` is the smallest complete example.

## Troubleshooting
- Permission errors / Operation not permitted: ensure `setup-user-mode.sh` ran, re-login; check `id` for `libvirt` and `kvm` groups; verify `/etc/sudoers.d/netsim` exists.
- Libvirt connection errors: `sudo systemctl start libvirtd`; set `NETSIM_LIBVIRT_URI` if using system libvirt.
- Missing tools: `genisoimage`, `python3-libvirt`, and `qemu-system-x86` must be installed.

## Additional Docs
- Implementation notes: docs/IMPLEMENTATION_SUMMARY.md
- Image management: docs/IMAGE_MANAGEMENT.md
- Visual summary: VISUAL_SUMMARY.txt
