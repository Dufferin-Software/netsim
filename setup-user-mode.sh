#!/bin/bash

# Setup netsim for user (non-root) operation
# Uses libvirt user session mode instead of system mode

echo "====== NetSim User-Mode Setup ======"
echo ""
echo "This setup configures netsim to run without root privileges."
echo ""

# Step 1: Add user to required groups
echo "[1/2] Adding user to required groups..."
sudo usermod -aG libvirt $(whoami)
sudo usermod -aG kvm $(whoami)
echo "✓ User added to libvirt and kvm groups"

# Step 2: Configure sudoers for network commands only
echo "[2/2] Configuring passwordless sudo for network operations..."
sudo tee /etc/sudoers.d/netsim > /dev/null << 'EOF'
# netsim network commands (only what's needed, nothing else)
Cmnd_Alias NETSIM_NET = /usr/bin/ip link *, /sbin/ip link *, /usr/bin/ip addr *, /sbin/ip addr *, /usr/bin/ip tuntap *, /sbin/ip tuntap *

# Allow user to run network commands without password
%sudo ALL=(ALL) NOPASSWD: NETSIM_NET
EOF
sudo chmod 0440 /etc/sudoers.d/netsim
echo "✓ Sudoers configured for network commands"

echo ""
echo "====== Setup Complete ======"
echo ""
echo "⚠️  IMPORTANT: Log out and log back in for group changes to take effect:"
echo "    exit"
echo "    # Log back in"
echo ""
echo "After logging back in, run netsim normally (as your user, no sudo needed):"
echo "    netsim setup examples/two-node-topology.yaml"
echo "    netsim start examples/two-node-topology.yaml"
echo ""
echo "Network operations will automatically use sudo when needed."
