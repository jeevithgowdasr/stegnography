"""Lossless image input/output helpers using Pillow and NumPy."""

from pathlib import Path
from typing import Tuple, Union
import numpy as np
from PIL import Image

from ..core.exceptions import ImageValidationError
from .validators import validate_image_path, validate_output_path


def load_image(filepath: Union[str, Path]) -> Tuple[np.ndarray, Tuple[int, int]]:
    """
    Load an image from disk and return as an RGB NumPy array.
    
    Args:
        filepath: Path to the lossless image file.
        
    Returns:
        Tuple of (numpy_uint8_rgb_array, (width, height)).
        
    Raises:
        ImageValidationError: If the image cannot be decoded.
    """
    valid_path = validate_image_path(filepath, must_exist=True)
    try:
        with Image.open(valid_path) as img:
            # Convert to standard RGB to avoid palette or alpha channel ambiguities
            rgb_img = img.convert("RGB")
            width, height = rgb_img.size
            img_array = np.array(rgb_img, dtype=np.uint8)
            return img_array, (width, height)
    except Exception as e:
        raise ImageValidationError(f"Failed to load image '{filepath}': {str(e)}") from e


def save_image(image_array: np.ndarray, output_path: Union[str, Path]) -> Path:
    """
    Save a NumPy array to disk losslessly as PNG or BMP.
    
    Args:
        image_array: NumPy uint8 array of the image (H, W, C).
        output_path: Target destination path.
        
    Returns:
        Path of the saved image.
        
    Raises:
        ImageValidationError: If saving fails.
    """
    valid_path = validate_output_path(output_path)
    try:
        valid_path.parent.mkdir(parents=True, exist_ok=True)
        img = Image.fromarray(image_array, mode="RGB")
        
        # Save losslessly with max compression optimization for PNG
        if valid_path.suffix.lower() == ".png":
            img.save(valid_path, format="PNG", compress_level=9)
        elif valid_path.suffix.lower() == ".bmp":
            img.save(valid_path, format="BMP")
        else:
            img.save(valid_path)
            
        return valid_path
    except Exception as e:
        raise ImageValidationError(f"Failed to save image to '{output_path}': {str(e)}") from e
