# Image Management - Usage Guide

This document shows how to use NetSim's image caching and auto-download features.

## Overview

NetSim supports two ways to specify VM images in your topology:

1. **Direct paths** - Use local image files
2. **Image references** - Auto-download and cache images from URLs

## Direct Path Images

Specify the full path to your image file:

```yaml
nodes:
  - name: "my-node"
    image: "/opt/images/debian13.qcow2"
```

## Image References (Auto-Download)

Specify image metadata. NetSim will download on first use and cache for reuse:

```yaml
nodes:
  - name: "my-node"
    image:
      name: "debian13-firecracker"
      url: "https://example.com/debian13.qcow2"
      checksum: "abc123def456..."  # Optional SHA256
```

Cache location: `~/.netsim/images/` (configurable)

## Workflow Examples

### Example 1: Using Cached Images

```bash
# First run - downloads image
netsim start topology.yaml --kernel kernel.bin

# Subsequent runs - uses cached image (instant)
netsim start topology.yaml --kernel kernel.bin
```

### Example 2: Custom Cache Directory

```bash
# Use SSD for faster image operations
netsim start topology.yaml --kernel kernel.bin \
  --image-cache-dir /mnt/ssd/netsim-cache
```

### Example 3: Managing Images

```bash
# List all cached images
netsim image list

# Download an image manually
netsim image download debian13 https://example.com/debian13.qcow2 \
  --checksum abc123def456...

# Remove a specific image
netsim image remove debian13

# Clear all images
netsim image clear
```

## Implementation Details

### Image Resolution Flow

When starting a topology:

1. Parse topology YAML
2. For each node:
   - If `image` is a string → use as direct path
   - If `image` is a dict with `name` and `url`:
     - Check local cache at `~/.netsim/images/{name}`
     - If found and valid → use cached copy
     - If not found → download from URL
     - If checksum provided → validate downloaded file
     - Store in cache for future use

### Cache Structure

```
~/.netsim/images/
├── debian13-firecracker
├── ubuntu22-firecracker
└── alpine-latest
```

Each file is named after the `name` field in the image reference.

### Features

- **Fast reuse** - Downloaded images cached locally
- **Checksum validation** - Optional SHA256 validation
- **Flexible storage** - Configurable cache location
- **Simple cleanup** - Easy cache management commands

## Class Reference

### ImageManager

Located in `netsim/images.py`

```python
manager = ImageManager(cache_dir="~/.netsim/images")

# Resolve an image (returns path, downloading if needed)
path = manager.resolve_image({
    "name": "debian13",
    "url": "https://...",
    "checksum": "sha256..."
})

# List cached images
images = manager.list_cached_images()

# Remove/clear cache
manager.remove_cached_image("debian13")
manager.clear_cache()
```

## Tips & Tricks

### Checksum Validation

Generate SHA256 of your image:
```bash
sha256sum debian13.qcow2
```

Add to topology:
```yaml
image:
  name: "debian13"
  url: "https://..."
  checksum: "5a7c4b...d8e9f"  # From sha256sum above
```

### Bandwidth Savings

Host your images on a fast server and reference them:
```yaml
image:
  name: "my-image"
  url: "https://images.company.com/debian13.qcow2"
```

First developer downloads → all others use cache via image sharing or just download once.

### Multiple Cache Locations

Different topologies can use different cache directories:
```bash
# Development images
netsim start dev-topology.yaml --kernel kernel.bin \
  --image-cache-dir /tmp/dev-images

# Testing images  
netsim start test-topology.yaml --kernel kernel.bin \
  --image-cache-dir /mnt/test-images
```

### Persistent Caching

Keep images across runs by storing cache outside `/tmp`:
```bash
mkdir -p ~/netsim-cache
netsim start topology.yaml --kernel kernel.bin \
  --image-cache-dir ~/netsim-cache
```

The cache persists even after VM cleanup.
