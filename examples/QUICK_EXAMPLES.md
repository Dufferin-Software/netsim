# Quick Examples - Image Management

## Example 1: Basic Local Images

**Topology File: `local-topology.yaml`**
```yaml
name: "local-vms"
version: "1.0"

networks:
  - name: "lan"
    subnet: "10.0.0.0/24"

nodes:
  - name: "router"
    image: "/opt/images/debian13.qcow2"
    memory: 512
    vcpus: 1
    interfaces:
      - name: "eth0"
        network: "lan"
        ip: "10.0.0.1/24"

  - name: "client"
    image: "/opt/images/debian13.qcow2"
    memory: 256
    vcpus: 1
    interfaces:
      - name: "eth0"
        network: "lan"
        ip: "10.0.0.2/24"
```

**Commands:**
```bash
netsim start local-topology.yaml
netsim status local-topology.yaml
netsim cleanup local-topology.yaml
```

## Example 2: Auto-Downloaded Images

**Topology File: `remote-topology.yaml`**
```yaml
name: "remote-vms"
version: "1.0"

networks:
  - name: "testnet"
    subnet: "192.168.1.0/24"

nodes:
  - name: "server"
    image:
      name: "debian13-server"
      url: "https://images.example.com/debian13-4gb.qcow2"
      checksum: "e5fa44f2b31c1fb553b6021e7aab6b74476544c1"
    memory: 1024
    vcpus: 2
    interfaces:
      - name: "eth0"
        network: "testnet"
        ip: "192.168.1.10/24"

  - name: "client"
    image:
      name: "debian13-minimal"
      url: "https://images.example.com/debian13-2gb.qcow2"
      checksum: "1a7b4c2d8e9f0a1b3c4d5e6f7a8b9c0d"
    memory: 512
    vcpus: 1
    interfaces:
      - name: "eth0"
        network: "testnet"
        ip: "192.168.1.20/24"
```

**Commands:**
```bash
# First run - downloads both images
netsim start remote-topology.yaml

# Subsequent runs - uses cached images instantly
netsim start remote-topology.yaml

# Check cache
netsim image list
# Output:
# Cached images (2):
#   debian13-server: 4096.0 MB (modified: 2026-01-25T12:30:45)
#   debian13-minimal: 2048.0 MB (modified: 2026-01-25T12:25:30)
# Total: 6144.0 MB
```

## Example 3: Mixed Images

**Topology File: `mixed-topology.yaml`**
```yaml
name: "mixed-images"
version: "1.0"

networks:
  - name: "net1"
    subnet: "10.1.0.0/24"
  - name: "net2"
    subnet: "10.2.0.0/24"

nodes:
  # Local image (fast, always available)
  - name: "gateway"
    image: "/local/images/gateway-custom.qcow2"
    memory: 512
    vcpus: 1
    interfaces:
      - name: "eth0"
        network: "net1"
        ip: "10.1.0.1/24"
      - name: "eth1"
        network: "net2"
        ip: "10.2.0.1/24"

  # Downloaded image (reused across topologies)
  - name: "app1"
    image:
      name: "debian13-apps"
      url: "https://repo.company.internal/debian13-apps.qcow2"
      checksum: "abc123def456789"
    memory: 512
    vcpus: 1
    interfaces:
      - name: "eth0"
        network: "net1"
        ip: "10.1.0.10/24"

  # Another downloaded image
  - name: "app2"
    image:
      name: "debian13-base"
      url: "https://repo.company.internal/debian13-base.qcow2"
    memory: 256
    vcpus: 1
    interfaces:
      - name: "eth0"
        network: "net2"
        ip: "10.2.0.10/24"
```

**Commands:**
```bash
# Setup and start
netsim start mixed-topology.yaml

# Check what's cached
netsim image list

# Manually download an image before topology starts
netsim image download debian13-extra \
  https://repo.company.internal/debian13-extra.qcow2 \
  --checksum xyz789abc456
```

## Example 4: Image Cache Management

**Download multiple images:**
```bash
netsim image download ubuntu22 \
  https://images.example.com/ubuntu22.qcow2 \
  --checksum hash1

netsim image download debian12 \
  https://images.example.com/debian12.qcow2 \
  --checksum hash2

netsim image download alpine-latest \
  https://images.example.com/alpine.qcow2
```

**View cache:**
```bash
netsim image list
# Cached images (3):
#   ubuntu22: 1024.5 MB (modified: 2026-01-24T08:30:22)
#   debian12: 2048.3 MB (modified: 2026-01-24T09:15:45)
#   alpine-latest: 256.7 MB (modified: 2026-01-24T10:00:11)
# Total: 3329.5 MB
```

**Clean up old images:**
```bash
netsim image remove ubuntu22
netsim image remove alpine-latest

# Or clear everything
netsim image clear
```

## Example 5: Custom Cache Directory

**Using SSD for fast cache:**
```bash
# Setup SSD cache
mkdir -p /mnt/nvme/netsim-cache

# Start topology with custom cache
netsim start topology.yaml --image-cache-dir /mnt/nvme/netsim-cache

# Images stored in /mnt/nvme/netsim-cache/
ls -lh /mnt/nvme/netsim-cache/
```

**Separate caches for different workloads:**
```bash
# Development images - fast local SSD
netsim start dev-topology.yaml --image-cache-dir /mnt/ssd-local/dev-images

# CI/CD images - network storage
netsim start ci-topology.yaml --image-cache-dir /mnt/nfs-storage/ci-images

# Backup images - external drive
netsim start backup-topology.yaml --image-cache-dir /mnt/external-hdd/backup-images
```

## Example 6: Integration with Scripts

**Script: `setup-test-env.sh`**
```bash
#!/bin/bash

TOPOLOGY="test-topology.yaml"
CACHE="/mnt/ssd/netsim-cache"

# Pre-download all images
echo "Preparing images..."
netsim image download test-image1 https://repo/image1.qcow2 \
  --cache-dir "$CACHE" --checksum hash1
netsim image download test-image2 https://repo/image2.qcow2 \
  --cache-dir "$CACHE" --checksum hash2

# Show what we have
echo "Cache status:"
netsim image list --cache-dir "$CACHE"

# Start topology
echo "Starting topology..."
netsim start "$TOPOLOGY" --image-cache-dir "$CACHE"

# Run tests...
echo "Running tests..."

# Cleanup when done
echo "Cleaning up..."
netsim stop "$TOPOLOGY"
netsim cleanup "$TOPOLOGY"
```

**Run the script:**
```bash
chmod +x setup-test-env.sh
./setup-test-env.sh
```

## Example 7: Checksum Generation

**Generate checksums for your images:**
```bash
# Generate SHA256
sha256sum debian13.qcow2
# Output: 5a7c4b2f8e9d1a3c6b2d4f7a9e1c3b5d debian13.qcow2

# Use in topology
netsim image download debian13 \
  https://myrepo.example.com/debian13.qcow2 \
  --checksum 5a7c4b2f8e9d1a3c6b2d4f7a9e1c3b5d
```

## Workflow Examples

### Fast Development
```bash
# 1. Generate or download base images once
netsim image download debian-base https://repo/base.qcow2

# 2. Use in multiple topologies
netsim start dev-topology1.yaml
netsim start dev-topology2.yaml  # Instant
netsim start dev-topology3.yaml  # Instant

# 3. All use same cached image
```

### CI/CD Pipeline
```bash
# 1. Pre-cache images on CI runner
netsim image download ci-image https://internal-repo/ci.qcow2 \
  --cache-dir /ci-cache

# 2. Run multiple test topologies efficiently
for test in test1 test2 test3; do
  netsim start "$test.yaml" --image-cache-dir /ci-cache
  # Run tests...
  netsim cleanup "$test.yaml"
done

# 3. Images already in cache = fast startup
```

### Production Deployment
```bash
# 1. Use local curated images
# 2. Version control topology YAML
# 3. No external downloads needed
netsim start production-topology.yaml
```
