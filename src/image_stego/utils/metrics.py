"""Image quality analysis and steganalysis metrics (PSNR, MSE, Difference Map)."""

from typing import Tuple, Union
from pathlib import Path
import numpy as np

from ..core.models import QualityMetrics
from .image_io import load_image


def calculate_quality_metrics(
    original: Union[np.ndarray, str, Path],
    stego: Union[np.ndarray, str, Path],
) -> QualityMetrics:
    """
    Calculate Mean Squared Error (MSE), Peak Signal-to-Noise Ratio (PSNR),
    and modification distribution between the original and stego images.
    
    Args:
        original: Original cover image array or filepath.
        stego: Stego image array or filepath.
        
    Returns:
        QualityMetrics dataclass instance.
    """
    if not isinstance(original, np.ndarray):
        original, _ = load_image(original)
    if not isinstance(stego, np.ndarray):
        stego, _ = load_image(stego)

    if original.shape != stego.shape:
        raise ValueError(
            f"Image dimension mismatch: Original {original.shape} vs Stego {stego.shape}"
        )

    orig_f = original.astype(np.float64)
    stego_f = stego.astype(np.float64)

    # Calculate MSE
    mse = float(np.mean((orig_f - stego_f) ** 2))

    # Calculate PSNR in decibels (dB)
    if mse == 0.0:
        psnr_db = float("inf")
    else:
        psnr_db = float(20.0 * np.log10(255.0 / np.sqrt(mse)))

    diff = np.abs(original.astype(np.int32) - stego.astype(np.int32))
    max_pixel_diff = int(np.max(diff))

    # Count modified pixels (pixels where any color channel changed)
    pixels_modified_mask = np.any(original != stego, axis=-1)
    total_pixels_modified = int(np.count_nonzero(pixels_modified_mask))
    total_pixels = original.shape[0] * original.shape[1]
    modified_percentage = float((total_pixels_modified / total_pixels) * 100)

    return QualityMetrics(
        mse=round(mse, 6),
        psnr_db=round(psnr_db, 2) if psnr_db != float("inf") else 999.99,
        max_pixel_diff=max_pixel_diff,
        total_pixels_modified=total_pixels_modified,
        total_pixels=total_pixels,
        modified_percentage=round(modified_percentage, 2),
    )


def generate_difference_map(
    original_array: np.ndarray,
    stego_array: np.ndarray,
    amplification: int = 255,
) -> np.ndarray:
    """
    Generate an amplified visual heatmap showing where pixel modifications occurred.
    
    Returns:
        RGB NumPy array with amplified difference values (bright red for modified pixels).
    """
    if original_array.shape != stego_array.shape:
        raise ValueError("Image dimensions must match to compute difference map.")

    # Detect modified pixels
    modified_mask = np.any(original_array != stego_array, axis=-1)

    # Create visual heatmap: dark background, bright cyan/red where bits were altered
    heatmap = np.zeros_like(original_array, dtype=np.uint8)
    heatmap[modified_mask] = [255, 50, 50]  # Bright red for modified coordinates
    
    return heatmap
