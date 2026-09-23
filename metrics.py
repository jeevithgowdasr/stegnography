r"""
Image Quality and Steganographic Imperceptibility Metrics Engine.

This module provides industry-standard metrics (MSE, PSNR, SSIM, BPP) and difference
visualization to quantify the visual imperceptibility and quality retention of steganographic images.

Standards & Formulas:
    - Mean Squared Error (MSE):
      $$MSE = \frac{1}{M \times N \times C} \sum_{i=0}^{M-1} \sum_{j=0}^{N-1} \sum_{k=0}^{C-1} [I_1(i,j,k) - I_2(i,j,k)]^2$$
    - Peak Signal-to-Noise Ratio (PSNR):
      $$PSNR = 10 \cdot \log_{10}\left(\frac{MAX_I^2}{MSE}\right) = 20 \cdot \log_{10}\left(\frac{255}{\sqrt{MSE}}\right)$$
      (Handles MSE = 0 with infinity / 100.0 dB flag).
    - Structural Similarity Index (SSIM):
      Local luminance, contrast, and structural comparison across Gaussian windows.
    - Embedding Rate (bpp):
      Bits Per Pixel embedded across the image carrier.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Dict, Tuple, Union

import cv2
import numpy as np
from PIL import Image


# =====================================================================
# Quality Thresholds
# =====================================================================
PSNR_EXCELLENT_THRESHOLD: float = 40.0   # > 40 dB: Mathematically imperceptible to human eye
PSNR_ACCEPTABLE_THRESHOLD: float = 30.0  # 30-40 dB: High quality, acceptable steganography
SSIM_EXCELLENT_THRESHOLD: float = 0.99   # > 0.99: Preserves complete structural fidelity


# =====================================================================
# Image Loading & Validation
# =====================================================================
def _load_image_array(image_input: Union[str, Path, np.ndarray, Image.Image]) -> np.ndarray:
    """Load and normalize image input into a uint8 NumPy array."""
    if isinstance(image_input, np.ndarray):
        return image_input.astype(np.uint8)

    if isinstance(image_input, Image.Image):
        return np.array(image_input, dtype=np.uint8)

    path_obj = Path(image_input).resolve()
    if not path_obj.is_file():
        raise FileNotFoundError(f"Image not found at path: {path_obj}")

    with Image.open(path_obj) as img:
        img.load()
        if img.mode not in ("RGB", "RGBA", "L"):
            img = img.convert("RGB")
        return np.array(img, dtype=np.uint8)


# =====================================================================
# Core Metric Calculations
# =====================================================================
def calculate_mse(image1: np.ndarray, image2: np.ndarray) -> float:
    """
    Calculate Mean Squared Error (MSE) between two image arrays.

    Args:
        image1: Reference image array.
        image2: Target/Stego image array.

    Returns:
        Mean Squared Error value (0.0 for identical images).
    """
    if image1.shape != image2.shape:
        raise ValueError(f"Image shape mismatch: {image1.shape} vs {image2.shape}")

    diff = image1.astype(np.float64) - image2.astype(np.float64)
    mse_val = float(np.mean(diff ** 2))
    return mse_val


def calculate_psnr(image1: np.ndarray, image2: np.ndarray, max_pixel_val: float = 255.0) -> float:
    """
    Calculate Peak Signal-to-Noise Ratio (PSNR) in decibels (dB).

    Args:
        image1: Reference image array.
        image2: Stego image array.
        max_pixel_val: Maximum possible pixel value (255.0 for 8-bit images).

    Returns:
        PSNR value in decibels (dB). Returns float('inf') if images are identical (MSE = 0).
    """
    mse_val = calculate_mse(image1, image2)
    if mse_val == 0.0:
        return float("inf")

    psnr_db = 10.0 * math.log10((max_pixel_val ** 2) / mse_val)
    return float(psnr_db)


def calculate_ssim(image1: np.ndarray, image2: np.ndarray) -> float:
    """
    Calculate Structural Similarity Index (SSIM) between two images.

    Args:
        image1: Reference image array.
        image2: Stego image array.

    Returns:
        SSIM value between -1.0 and 1.0 (1.0 = identical structure).
    """
    if image1.shape != image2.shape:
        raise ValueError(f"Image shape mismatch: {image1.shape} vs {image2.shape}")

    # Handle multi-channel images by averaging channel-wise SSIM
    if image1.ndim == 3:
        channels = image1.shape[2]
        # If RGBA, calculate across RGB channels (or all 4)
        channel_ssims = [
            _ssim_single_channel(image1[:, :, c], image2[:, :, c])
            for c in range(min(channels, 3))
        ]
        return float(np.mean(channel_ssims))

    return _ssim_single_channel(image1, image2)


def _ssim_single_channel(channel1: np.ndarray, channel2: np.ndarray) -> float:
    """Compute SSIM for a single 2D grayscale channel using Gaussian windowing."""
    c1 = channel1.astype(np.float64)
    c2 = channel2.astype(np.float64)

    h, w = c1.shape[:2]
    # Adapt Gaussian kernel window size for small test images
    win_size = min(11, h, w)
    if win_size % 2 == 0:
        win_size -= 1
    if win_size < 3:
        # Fallback for very small images
        mu1, mu2 = c1.mean(), c2.mean()
        sigma1_sq = np.var(c1)
        sigma2_sq = np.var(c2)
        sigma12 = np.mean((c1 - mu1) * (c2 - mu2))
        k1, k2 = 0.01, 0.03
        l_val = 255.0
        c_1 = (k1 * l_val) ** 2
        c_2 = (k2 * l_val) ** 2
        return float(((2 * mu1 * mu2 + c_1) * (2 * sigma12 + c_2)) /
                     ((mu1**2 + mu2**2 + c_1) * (sigma1_sq + sigma2_sq + c_2)))

    k1 = 0.01
    k2 = 0.03
    l_val = 255.0
    c_1 = (k1 * l_val) ** 2
    c_2 = (k2 * l_val) ** 2

    kernel = cv2.getGaussianKernel(win_size, 1.5)
    window = np.outer(kernel, kernel.transpose())

    mu1 = cv2.filter2D(c1, -1, window)
    mu2 = cv2.filter2D(c2, -1, window)

    mu1_sq = mu1 ** 2
    mu2_sq = mu2 ** 2
    mu1_mu2 = mu1 * mu2

    sigma1_sq = cv2.filter2D(c1 ** 2, -1, window) - mu1_sq
    sigma2_sq = cv2.filter2D(c2 ** 2, -1, window) - mu2_sq
    sigma12 = cv2.filter2D(c1 * c2, -1, window) - mu1_mu2

    ssim_map = ((2 * mu1_mu2 + c_1) * (2 * sigma12 + c_2)) / (
        (mu1_sq + mu2_sq + c_1) * (sigma1_sq + sigma2_sq + c_2)
    )

    return float(np.mean(ssim_map))


# =====================================================================
# Quality Analysis & Reporting Engine
# =====================================================================
def evaluate_stego_quality(
    original_image_path: Union[str, Path, np.ndarray],
    stego_image_path: Union[str, Path, np.ndarray],
    print_summary: bool = True,
) -> Dict[str, Any]:
    """
    Perform a comprehensive quality evaluation between a cover image and stego image.

    Computes:
        - Mean Squared Error (MSE)
        - Peak Signal-to-Noise Ratio (PSNR in dB)
        - Structural Similarity Index (SSIM)
        - Embedding Rate (bits per pixel, bpp)
        - Modified pixel counts and percentage
        - Visual imperceptibility rating

    Args:
        original_image_path: Path or NumPy array of the original cover image.
        stego_image_path: Path or NumPy array of the stego image.
        print_summary: If True, prints a formatted terminal summary report.

    Returns:
        Structured dictionary with all metrics and qualitative evaluations.
    """
    img_orig = _load_image_array(original_image_path)
    img_stego = _load_image_array(stego_image_path)

    if img_orig.shape != img_stego.shape:
        raise ValueError(
            f"Image dimensions do not match: Original {img_orig.shape} vs Stego {img_stego.shape}"
        )

    height, width = img_orig.shape[:2]
    channels = img_orig.shape[2] if img_orig.ndim == 3 else 1
    total_pixels = height * width

    # Calculate Core Metrics
    mse_val = calculate_mse(img_orig, img_stego)
    psnr_val = calculate_psnr(img_orig, img_stego)
    ssim_val = calculate_ssim(img_orig, img_stego)

    # Pixel & Bit Difference Analysis
    diff_mask = np.any(img_orig != img_stego, axis=-1) if img_orig.ndim == 3 else (img_orig != img_stego)
    modified_pixels = int(np.count_nonzero(diff_mask))
    modified_percentage = (modified_pixels / total_pixels) * 100.0 if total_pixels > 0 else 0.0

    # Bit-level difference (embedding rate)
    diff_bits = np.unpackbits(np.bitwise_xor(img_orig[:, :, :3], img_stego[:, :, :3])) if img_orig.ndim == 3 else np.unpackbits(np.bitwise_xor(img_orig, img_stego))
    total_bits_altered = int(np.sum(diff_bits))
    embedding_rate_bpp = total_bits_altered / total_pixels if total_pixels > 0 else 0.0

    # Qualitative Imperceptibility Rating
    if psnr_val == float("inf") or psnr_val >= PSNR_EXCELLENT_THRESHOLD:
        if ssim_val >= SSIM_EXCELLENT_THRESHOLD:
            rating = "Imperceptible (Excellent)"
            is_imperceptible = True
        else:
            rating = "High Quality (Acceptable)"
            is_imperceptible = True
    elif psnr_val >= PSNR_ACCEPTABLE_THRESHOLD:
        rating = "Acceptable (Minor Noise)"
        is_imperceptible = True
    else:
        rating = "Degraded (Visible Artifacts)"
        is_imperceptible = False

    psnr_display = 100.0 if psnr_val == float("inf") else round(psnr_val, 2)

    results: Dict[str, Any] = {
        "dimensions": (width, height, channels),
        "total_pixels": total_pixels,
        "mse": round(mse_val, 6),
        "psnr_db": psnr_display,
        "psnr_raw": psnr_val,
        "ssim": round(ssim_val, 6),
        "embedding_rate_bpp": round(embedding_rate_bpp, 4),
        "modified_pixels": modified_pixels,
        "modified_percentage": round(modified_percentage, 2),
        "total_bits_altered": total_bits_altered,
        "is_imperceptible": is_imperceptible,
        "quality_rating": rating,
    }

    if print_summary:
        print("\n" + "=" * 70)
        print("[*] STEGANOGRAPHY IMAGE QUALITY & IMPERCEPTIBILITY REPORT")
        print("=" * 70)
        print(f"  Dimensions               : {width} x {height} ({channels} channels)")
        print(f"  Total Pixels             : {total_pixels:,}")
        print(f"  Modified Pixels          : {modified_pixels:,} ({results['modified_percentage']}%)")
        print(f"  Embedding Rate (bpp)     : {results['embedding_rate_bpp']} bits/pixel")
        print("-" * 70)
        print(f"  Mean Squared Error (MSE) : {results['mse']:.6f}  (Lower is better, Ideal: 0.0)")
        if psnr_val == float("inf"):
            print(f"  Peak SNR (PSNR)          : Infinity dB [100.0 dB flag] (Lossless / Identical)")
        else:
            print(f"  Peak SNR (PSNR)          : {results['psnr_db']:.2f} dB (Threshold > 30-40 dB)")
        print(f"  Structural Similarity    : {results['ssim']:.6f}  (Range: -1 to 1, Ideal: 1.0)")
        print("-" * 70)
        status_marker = "[PASS] EXCELLENT" if is_imperceptible else "[FAIL] DEGRADED"
        print(f"  Imperceptibility Rating  : {status_marker} - {rating}")
        print("=" * 70 + "\n")

    return results


# =====================================================================
# Visualization & Amplified Difference Map
# =====================================================================
def generate_difference_map(
    original_path: Union[str, Path, np.ndarray],
    stego_path: Union[str, Path, np.ndarray],
    diff_output_path: Union[str, Path],
    amplify_factor: int = 20,
) -> str:
    """
    Generate an amplified visual difference map highlighting altered LSB pixels.

    Args:
        original_path: Reference image path or array.
        stego_path: Stego image path or array.
        diff_output_path: Path to save the amplified difference map (PNG/BMP).
        amplify_factor: Amplification multiplier for LSB pixel deltas (default: 20x).

    Returns:
        Absolute string path to the saved difference map image.
    """
    img_orig = _load_image_array(original_path)
    img_stego = _load_image_array(stego_path)

    if img_orig.shape != img_stego.shape:
        raise ValueError("Image dimensions must match to compute difference map.")

    out_path = Path(diff_output_path).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Compute absolute channel difference
    diff = np.abs(img_orig.astype(np.int16) - img_stego.astype(np.int16))

    # Amplify differences and clip to 8-bit bounds [0, 255]
    amplified = np.clip(diff * amplify_factor, 0, 255).astype(np.uint8)

    # If all black (identical), keep as black
    diff_image = Image.fromarray(amplified)
    diff_image.save(out_path, format="PNG")

    return str(out_path)


# =====================================================================
# Standalone Unit Verification & Demonstration
# =====================================================================
if __name__ == "__main__":
    import shutil
    import tempfile

    print("========================================================================")
    print("[*] GOOGLE ANTIGRAVITY - IMAGE QUALITY METRICS ENGINE")
    print("    Metrics: MSE, PSNR, SSIM, BPP, & Difference Map Visualizer")
    print("========================================================================")

    temp_dir = Path(tempfile.mkdtemp(prefix="metrics_test_"))
    try:
        # 1. Create a rich synthetic gradient image (256x256 RGB)
        img_size = 256
        x = np.linspace(0, 255, img_size, dtype=np.uint8)
        y = np.linspace(0, 255, img_size, dtype=np.uint8)
        xx, yy = np.meshgrid(x, y)
        base_arr = np.dstack((xx, yy, 255 - xx))

        cover_path = temp_dir / "baseline_cover.png"
        Image.fromarray(base_arr, mode="RGB").save(cover_path, format="PNG")

        # 2. Test Identical Images (MSE = 0, PSNR = inf, SSIM = 1.0)
        print("\n[+] Test 1: Evaluating Identical Images")
        metrics_identical = evaluate_stego_quality(cover_path, cover_path, print_summary=False)
        assert metrics_identical["mse"] == 0.0, "MSE for identical images must be 0"
        assert metrics_identical["psnr_raw"] == float("inf"), "PSNR for identical images must be infinity"
        assert metrics_identical["ssim"] == 1.0, "SSIM for identical images must be 1.0"
        print("    - MSE                         : 0.0")
        print("    - PSNR                        : Infinity (100.0 dB flag)")
        print("    - SSIM                        : 1.000000")
        print("    - Status                      : [PASS] IDENTICAL IMAGES VERIFIED")

        # 3. Create a Realistic Stego Image (Flip LSBs for 10% of pixels)
        stego_arr = base_arr.copy()
        np.random.seed(42)
        # Modify 5,000 random pixels by flipping LSB
        h_indices = np.random.randint(0, img_size, 5000)
        w_indices = np.random.randint(0, img_size, 5000)
        c_indices = np.random.randint(0, 3, 5000)
        stego_arr[h_indices, w_indices, c_indices] ^= 1

        stego_path = temp_dir / "stego_simulated.png"
        Image.fromarray(stego_arr, mode="RGB").save(stego_path, format="PNG")

        print("\n[+] Test 2: Evaluating Simulated Stego Image Quality")
        metrics_stego = evaluate_stego_quality(cover_path, stego_path, print_summary=True)

        assert metrics_stego["psnr_db"] > 50.0, f"Expected PSNR > 50 dB for LSB steganography, got {metrics_stego['psnr_db']}"
        assert metrics_stego["ssim"] > 0.999, f"Expected SSIM > 0.999, got {metrics_stego['ssim']}"
        assert metrics_stego["is_imperceptible"] is True, "Stego image must be evaluated as imperceptible"

        # 4. Generate Amplified Difference Map
        print("[+] Test 3: Generating Amplified Difference Map (20x amplification)")
        diff_path = temp_dir / "difference_map.png"
        generate_difference_map(cover_path, stego_path, diff_path, amplify_factor=20)
        assert diff_path.exists(), "Difference map was not created"
        diff_arr = np.array(Image.open(diff_path))
        assert np.max(diff_arr) == 20, f"Amplified delta should be 20, got {np.max(diff_arr)}"
        print(f"    - Saved Difference Map        : {diff_path.name}")
        print(f"    - Max Amplified Pixel Value   : {np.max(diff_arr)}")
        print("    - Status                      : [PASS] DIFFERENCE MAP VERIFIED")

        print("\n" + "=" * 70)
        print("[SUCCESS] ALL METRIC CALCULATIONS AND VERIFICATIONS PASSED!")
        print("=" * 70)

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
