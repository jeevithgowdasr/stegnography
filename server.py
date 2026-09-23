"""
Web Server Backend for Image Encryption & Steganography Engine.

Provides high-performance REST APIs powered by FastAPI/Uvicorn, connecting to
crypto.py, stego.py, metrics.py, and pipeline.py.
"""

from __future__ import annotations

import base64
import io
import os
import tempfile
import traceback
from pathlib import Path
from typing import Optional

import numpy as np
from PIL import Image
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import crypto
import stego
import metrics
import pipeline
from pipeline import (
    encrypt_and_hide,
    extract_and_decrypt,
    PipelineError,
    CapacityError,
    AuthenticationError,
    UnsupportedFormatError,
)

app = FastAPI(
    title="Image Encryption & Steganography Engine",
    description="Enterprise REST API for AES-256-GCM + PBKDF2 authenticated encryption & LSB steganography.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(exist_ok=True)


@app.post("/api/capacity")
async def check_capacity(image: UploadFile = File(...)):
    """Calculate maximum payload capacity for an uploaded cover image."""
    try:
        content = await image.read()
        temp_file = tempfile.NamedTemporaryFile(suffix=Path(image.filename or "cover.png").suffix, delete=False)
        temp_file.write(content)
        temp_file.close()

        with Image.open(temp_file.name) as img:
            w, h = img.size
            mode = img.mode
            fmt = img.format or "PNG"

        capacity_bytes = stego.calculate_capacity(temp_file.name)
        os.unlink(temp_file.name)

        return JSONResponse({
            "filename": image.filename,
            "width": w,
            "height": h,
            "mode": mode,
            "format": fmt,
            "capacity_bytes": capacity_bytes,
            "capacity_kb": round(capacity_bytes / 1024, 2),
            "carrier_bits_per_pixel": 3,
        })
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/hide")
async def api_encrypt_and_hide(
    cover: UploadFile = File(...),
    secret_text: str = Form(...),
    passphrase: str = Form(...),
):
    """Encrypt secret text with AES-256-GCM and embed into cover image LSBs."""
    temp_cover = None
    temp_stego = None
    try:
        cover_bytes = await cover.read()
        suffix = Path(cover.filename or "cover.png").suffix.lower()
        if suffix not in (".png", ".bmp"):
            suffix = ".png"

        temp_cover = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        temp_cover.write(cover_bytes)
        temp_cover.close()

        temp_stego = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        temp_stego.close()

        # Run pipeline
        result = encrypt_and_hide(
            cover_image_path=temp_cover.name,
            secret_text=secret_text,
            passphrase=passphrase,
            output_image_path=temp_stego.name,
        )

        # Read stego image and encode to Base64
        with open(temp_stego.name, "rb") as f:
            stego_b64 = base64.b64encode(f.read()).decode("ascii")

        # Generate 20x amplified difference map
        orig_arr = np.array(Image.open(temp_cover.name))
        stego_arr = np.array(Image.open(temp_stego.name))
        diff = np.abs(orig_arr.astype(np.int16) - stego_arr.astype(np.int16))
        amplified = np.clip(diff * 20, 0, 255).astype(np.uint8)
        diff_img = Image.fromarray(amplified)

        diff_buffer = io.BytesIO()
        diff_img.save(diff_buffer, format="PNG")
        diff_b64 = base64.b64encode(diff_buffer.getvalue()).decode("ascii")

        return JSONResponse({
            "success": True,
            "plaintext_bytes": result["plaintext_bytes"],
            "encrypted_payload_bytes": result["encrypted_payload_bytes"],
            "capacity_bytes": result["capacity_bytes"],
            "capacity_used_pct": result["capacity_used_pct"],
            "psnr_db": result["psnr_db"],
            "mse": result["mse"],
            "ssim": result["ssim"],
            "embedding_rate_bpp": result["embedding_rate_bpp"],
            "is_imperceptible": result["is_imperceptible"],
            "quality_rating": result["quality_rating"],
            "stego_image_base64": f"data:image/png;base64,{stego_b64}",
            "diff_image_base64": f"data:image/png;base64,{diff_b64}",
            "filename": f"stego_{Path(cover.filename or 'carrier').stem}.png",
        })

    except CapacityError as e:
        raise HTTPException(status_code=400, detail=f"Carrier Capacity Exceeded: {e}")
    except UnsupportedFormatError as e:
        raise HTTPException(status_code=400, detail=f"Unsupported Format: {e}")
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if temp_cover and os.path.exists(temp_cover.name):
            os.unlink(temp_cover.name)
        if temp_stego and os.path.exists(temp_stego.name):
            os.unlink(temp_stego.name)


@app.post("/api/extract")
async def api_extract_and_decrypt(
    stego_image: UploadFile = File(...),
    passphrase: str = Form(...),
):
    """Extract and decrypt secret payload from stego image."""
    temp_stego = None
    try:
        stego_bytes = await stego_image.read()
        suffix = Path(stego_image.filename or "stego.png").suffix.lower()
        if suffix not in (".png", ".bmp"):
            suffix = ".png"

        temp_stego = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        temp_stego.write(stego_bytes)
        temp_stego.close()

        recovered_text = extract_and_decrypt(
            stego_image_path=temp_stego.name,
            passphrase=passphrase,
        )

        return JSONResponse({
            "success": True,
            "recovered_text": recovered_text,
            "length_characters": len(recovered_text),
            "length_bytes": len(recovered_text.encode("utf-8")),
        })

    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=f"Authentication Failed: {e}")
    except UnsupportedFormatError as e:
        raise HTTPException(status_code=400, detail=f"Unsupported Format: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if temp_stego and os.path.exists(temp_stego.name):
            os.unlink(temp_stego.name)


@app.post("/api/difference")
async def api_custom_difference(
    cover: UploadFile = File(...),
    stego_file: UploadFile = File(...),
    amplify: int = Form(20),
):
    """Compute customized amplified difference map between cover and stego images."""
    try:
        c_bytes = await cover.read()
        s_bytes = await stego_file.read()

        c_img = Image.open(io.BytesIO(c_bytes))
        s_img = Image.open(io.BytesIO(s_bytes))

        c_arr = np.array(c_img)
        s_arr = np.array(s_img)

        if c_arr.shape != s_arr.shape:
            raise HTTPException(status_code=400, detail="Image dimensions must match.")

        diff = np.abs(c_arr.astype(np.int16) - s_arr.astype(np.int16))
        amplified = np.clip(diff * amplify, 0, 255).astype(np.uint8)

        diff_img = Image.fromarray(amplified)
        buffer = io.BytesIO()
        diff_img.save(buffer, format="PNG")
        b64 = base64.b64encode(buffer.getvalue()).decode("ascii")

        return JSONResponse({
            "diff_image_base64": f"data:image/png;base64,{b64}",
            "max_pixel_delta": int(np.max(diff)),
            "amplification": amplify,
        })
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# Serve Static Assets
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    """Serve main web user interface."""
    index_path = STATIC_DIR / "index.html"
    if index_path.is_file():
        return HTMLResponse(index_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>StegoCrypt Web App</h1><p>Static files loading...</p>")


if __name__ == "__main__":
    import uvicorn
    print("========================================================================")
    print("[*] GOOGLE ANTIGRAVITY - IMAGE ENCRYPTION & STEGANOGRAPHY WEB SERVER")
    print("    Local Web UI: http://127.0.0.1:8000")
    print("========================================================================")
    uvicorn.run("server.py:app", host="127.0.0.1", port=8000, reload=False)
