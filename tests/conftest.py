"""Pytest fixtures and test environment setup."""

import sys
from pathlib import Path
import numpy as np
from PIL import Image
import pytest

# Add src to sys.path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))


@pytest.fixture
def sample_image_array():
    """Create a 100x100 RGB synthetic test image array with gradient colors."""
    h, w = 100, 100
    img = np.zeros((h, w, 3), dtype=np.uint8)
    for y in range(h):
        for x in range(w):
            img[y, x] = [x % 256, y % 256, (x + y) % 256]
    return img


@pytest.fixture
def sample_png_file(tmp_path, sample_image_array):
    """Create a temporary PNG image file on disk."""
    png_path = tmp_path / "sample_cover.png"
    img = Image.fromarray(sample_image_array, mode="RGB")
    img.save(png_path, format="PNG")
    return png_path


@pytest.fixture
def sample_bmp_file(tmp_path, sample_image_array):
    """Create a temporary BMP image file on disk."""
    bmp_path = tmp_path / "sample_cover.bmp"
    img = Image.fromarray(sample_image_array, mode="RGB")
    img.save(bmp_path, format="BMP")
    return bmp_path


@pytest.fixture
def sample_secret_file(tmp_path):
    """Create a sample binary secret file."""
    secret_file = tmp_path / "confidential_document.pdf"
    # Write synthetic PDF-like bytes
    content = b"%PDF-1.4\n1 0 obj\n<< /Title (Top Secret Strategy) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
    secret_file.write_bytes(content)
    return secret_file
