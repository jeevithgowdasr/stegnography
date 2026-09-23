"""Unit tests for standalone metrics.py module."""

import math
import numpy as np
import pytest
from pathlib import Path
from PIL import Image

import metrics
from metrics import (
    calculate_mse,
    calculate_psnr,
    calculate_ssim,
    evaluate_stego_quality,
    generate_difference_map,
)


@pytest.fixture
def sample_images(tmp_path: Path):
    cover_path = tmp_path / "cover.png"
    stego_path = tmp_path / "stego.png"

    # 128x128 gradient image
    x = np.linspace(0, 255, 128, dtype=np.uint8)
    xx, yy = np.meshgrid(x, x)
    cover_arr = np.dstack((xx, yy, 255 - xx))
    Image.fromarray(cover_arr, mode="RGB").save(cover_path, format="PNG")

    # Stego image with 500 LSB bit flips
    stego_arr = cover_arr.copy()
    np.random.seed(123)
    idx_h = np.random.randint(0, 128, 500)
    idx_w = np.random.randint(0, 128, 500)
    idx_c = np.random.randint(0, 3, 500)
    stego_arr[idx_h, idx_w, idx_c] ^= 1
    Image.fromarray(stego_arr, mode="RGB").save(stego_path, format="PNG")

    return cover_path, stego_path, cover_arr, stego_arr


def test_identical_images_metrics(sample_images):
    cover_path, _, cover_arr, _ = sample_images

    mse = calculate_mse(cover_arr, cover_arr)
    psnr = calculate_psnr(cover_arr, cover_arr)
    ssim = calculate_ssim(cover_arr, cover_arr)

    assert mse == 0.0
    assert psnr == float("inf")
    assert ssim == 1.0

    eval_dict = evaluate_stego_quality(cover_path, cover_path, print_summary=False)
    assert eval_dict["mse"] == 0.0
    assert eval_dict["psnr_db"] == 100.0  # 100.0 dB flag
    assert eval_dict["ssim"] == 1.0
    assert eval_dict["is_imperceptible"] is True


def test_stego_imperceptibility_quality(sample_images):
    cover_path, stego_path, cover_arr, stego_arr = sample_images

    eval_dict = evaluate_stego_quality(cover_path, stego_path, print_summary=False)

    # In LSB steganography, MSE should be very small (< 0.1)
    assert eval_dict["mse"] < 0.1
    # PSNR should be > 50 dB
    assert eval_dict["psnr_db"] > 50.0
    # SSIM should be > 0.999
    assert eval_dict["ssim"] > 0.999
    assert eval_dict["is_imperceptible"] is True
    assert eval_dict["quality_rating"] == "Imperceptible (Excellent)"


def test_shape_mismatch_raises():
    arr1 = np.zeros((100, 100, 3), dtype=np.uint8)
    arr2 = np.zeros((120, 100, 3), dtype=np.uint8)

    with pytest.raises(ValueError, match="Image shape mismatch"):
        calculate_mse(arr1, arr2)

    with pytest.raises(ValueError, match="Image shape mismatch"):
        calculate_psnr(arr1, arr2)

    with pytest.raises(ValueError, match="Image shape mismatch"):
        calculate_ssim(arr1, arr2)


def test_difference_map_generation(sample_images, tmp_path: Path):
    cover_path, stego_path, _, _ = sample_images
    diff_out = tmp_path / "diff.png"

    output_path = generate_difference_map(cover_path, stego_path, diff_out, amplify_factor=25)
    assert Path(output_path).exists()

    diff_arr = np.array(Image.open(diff_out))
    assert np.max(diff_arr) == 25
