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
    bridge-utils
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
- Nodes: name, image (path or {name,url,checksum}), memory, vcpus, interfaces (name, network, ip)
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

## Troubleshooting
- Permission errors / Operation not permitted: ensure `setup-user-mode.sh` ran, re-login; check `id` for `libvirt` and `kvm` groups; verify `/etc/sudoers.d/netsim` exists.
- Libvirt connection errors: `sudo systemctl start libvirtd`; set `NETSIM_LIBVIRT_URI` if using system libvirt.
- Missing tools: `genisoimage`, `python3-libvirt`, and `qemu-system-x86` must be installed.

## Additional Docs
- Implementation notes: docs/IMPLEMENTATION_SUMMARY.md
- Image management: docs/IMAGE_MANAGEMENT.md
- Visual summary: VISUAL_SUMMARY.txt
