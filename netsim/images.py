# Copyright (c) Dufferin Software

"""
Image management and caching.
"""

import hashlib
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass
import urllib.request
import urllib.error
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ImageReference:
    """Reference to a VM image."""

    name: str
    url: str
    checksum: Optional[str] = None  # SHA256 checksum for validation


class ImageManager:
    """Manage VM image caching and downloading."""

    DEFAULT_CACHE_DIR = Path.home() / ".netsim" / "images"

    def __init__(self, cache_dir: Optional[str] = None):
        """
        Initialize image manager.

        Args:
            cache_dir: Directory for caching images. Defaults to ~/.netsim/images
        """
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = self.DEFAULT_CACHE_DIR

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Image cache directory: {self.cache_dir}")

    def resolve_image(self, image_spec: Dict[str, Any] | str) -> str:
        """
        Resolve image specification to a file path.

        Args:
            image_spec: Either a path string or dict with {name, url, checksum}

        Returns:
            Path to image file

        Raises:
            FileNotFoundError: If image not found and cannot be downloaded
            ValueError: If image specification is invalid
        """
        # Handle direct path
        if isinstance(image_spec, str):
            path = Path(image_spec)
            if not path.exists():
                raise FileNotFoundError(f"Image not found: {image_spec}")
            return str(path.resolve())

        # Handle image reference
        if isinstance(image_spec, dict):
            if "name" in image_spec and "url" in image_spec:
                return self._resolve_image_reference(
                    ImageReference(
                        name=image_spec["name"],
                        url=image_spec["url"],
                        checksum=image_spec.get("checksum"),
                    )
                )
            elif "path" in image_spec:
                path = Path(image_spec["path"])
                if not path.exists():
                    raise FileNotFoundError(f"Image not found: {image_spec['path']}")
                return str(path.resolve())

        raise ValueError(f"Invalid image specification: {image_spec}")

    def _resolve_image_reference(self, ref: ImageReference) -> str:
        """Resolve an image reference, downloading if necessary."""
        cached_path = self.cache_dir / ref.name

        # If cached, validate and return
        if cached_path.exists():
            logger.debug(f"Image found in cache: {ref.name}")
            if ref.checksum:
                if self._validate_checksum(cached_path, ref.checksum):
                    return str(cached_path)
                else:
                    logger.warning(f"Cached image has invalid checksum: {ref.name}")
                    cached_path.unlink()
            else:
                return str(cached_path)

        # Download image
        logger.info(f"Downloading image: {ref.name} from {ref.url}")
        self._download_image(ref.url, cached_path)

        # Validate if checksum provided
        if ref.checksum:
            if not self._validate_checksum(cached_path, ref.checksum):
                cached_path.unlink()
                raise RuntimeError(
                    f"Downloaded image failed checksum validation: {ref.name}"
                )

        logger.info(f"Image ready: {ref.name}")
        return str(cached_path)

    def _download_image(self, url: str, dest: Path) -> None:
        """Download image from URL with progress."""
        dest.parent.mkdir(parents=True, exist_ok=True)

        try:
            with urllib.request.urlopen(url) as response:
                total_size = int(response.headers.get("content-length", 0))
                downloaded = 0
                chunk_size = 1024 * 1024  # 1MB chunks

                with open(dest, "wb") as f:
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break

                        f.write(chunk)
                        downloaded += len(chunk)

                        if total_size:
                            percent = (downloaded / total_size) * 100
                            logger.debug(
                                f"Downloaded {percent:.1f}% ({downloaded}/{total_size} bytes)"
                            )

        except urllib.error.URLError as e:
            if dest.exists():
                dest.unlink()
            raise RuntimeError(f"Failed to download image from {url}: {e}")

    def _validate_checksum(self, path: Path, expected_checksum: str) -> bool:
        """Validate file checksum."""
        sha256 = hashlib.sha256()

        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)

        actual = sha256.hexdigest()
        valid = actual.lower() == expected_checksum.lower()

        if valid:
            logger.debug(f"Checksum valid for {path.name}: {actual}")
        else:
            logger.error(
                f"Checksum mismatch for {path.name}:\n"
                f"  Expected: {expected_checksum}\n"
                f"  Got:      {actual}"
            )

        return valid

    def list_cached_images(self) -> Dict[str, Dict[str, Any]]:
        """List all cached images with metadata."""
        images: Dict[str, Dict[str, Any]] = {}

        if not self.cache_dir.exists():
            return images

        for image_file in self.cache_dir.iterdir():
            if image_file.is_file():
                stat = image_file.stat()
                images[image_file.name] = {
                    "path": str(image_file),
                    "size_mb": stat.st_size / (1024 * 1024),
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                }

        return images

    def remove_cached_image(self, name: str) -> bool:
        """Remove an image from cache."""
        image_path = self.cache_dir / name

        if not image_path.exists():
            logger.warning(f"Image not found in cache: {name}")
            return False

        image_path.unlink()
        logger.info(f"Removed image from cache: {name}")
        return True

    def clear_cache(self) -> int:
        """Clear all cached images. Returns count of removed images."""
        if not self.cache_dir.exists():
            return 0

        count = 0
        for image_file in self.cache_dir.iterdir():
            if image_file.is_file():
                image_file.unlink()
                count += 1

        logger.info(f"Cleared {count} images from cache")
        return count

    def get_cache_size(self) -> int:
        """Get total size of cache in bytes."""
        if not self.cache_dir.exists():
            return 0

        total = 0
        for image_file in self.cache_dir.iterdir():
            if image_file.is_file():
                total += image_file.stat().st_size

        return total
