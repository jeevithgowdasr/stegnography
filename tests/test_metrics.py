"""Unit tests for PSNR, MSE, and quality metrics."""

import pytest
import numpy as np

from image_stego.utils.metrics import calculate_quality_metrics, generate_difference_map
from image_stego.stego.lsb_encoder import embed_bits
from image_stego.stego.header import pack_header
from image_stego.core.models import PayloadType


def test_metrics_identical_images(sample_image_array):
    metrics = calculate_quality_metrics(sample_image_array, sample_image_array.copy())
    assert metrics.mse == 0.0
    assert metrics.psnr_db >= 900
    assert metrics.total_pixels_modified == 0
    assert metrics.modified_percentage == 0.0


def test_metrics_stego_image(sample_image_array):
    # Embed some payload
    header = pack_header(
        payload_type=PayloadType.TEXT,
        salt=b"\x00" * 16,
        nonce=b"\x00" * 12,
        payload_length=50,
    )
    packet = header + b"A" * 50
    stego_arr = embed_bits(sample_image_array, packet)

    metrics = calculate_quality_metrics(sample_image_array, stego_arr)

    # 1-bit LSB modifications result in very low MSE and very high PSNR (> 70 dB)
    assert metrics.mse > 0.0
    assert metrics.mse < 1.0
    assert metrics.psnr_db > 60.0
    assert metrics.max_pixel_diff <= 1
    assert metrics.total_pixels_modified > 0
    assert metrics.modified_percentage > 0.0


def test_difference_heatmap(sample_image_array):
    stego_arr = sample_image_array.copy()
    # Modify one pixel
    stego_arr[0, 0, 0] ^= 1

    diff_map = generate_difference_map(sample_image_array, stego_arr)
    assert diff_map.shape == sample_image_array.shape
    # Modified pixel should be colored red ([255, 50, 50])
    assert np.array_equal(diff_map[0, 0], [255, 50, 50])
    # Unmodified pixel should be black ([0, 0, 0])
    assert np.array_equal(diff_map[1, 1], [0, 0, 0])
