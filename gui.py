"""
Modern Desktop Graphical User Interface for Image Encryption and Steganography.

This application provides an intuitive, high-performance GUI integrating:
    - Cryptographic Engine (AES-256-GCM with PBKDF2)
    - Steganographic Engine (Vectorized LSB Embedding & Extraction)
    - Visual Quality Analysis (MSE, PSNR, SSIM, BPP)
    - Visual Difference Map Inspector

Built with Tkinter, TTK, Pillow, and Threading for non-blocking asynchronous execution.
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

import numpy as np
from PIL import Image, ImageTk
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

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


# =====================================================================
# Theme Colors & Typography Palette (Catppuccin Mocha / Antigravity Dark)
# =====================================================================
BG_DARK = "#11111b"          # Deep background
BG_SURFACE = "#181825"       # Main panels
BG_CARD = "#1e1e2e"          # Card widgets
BG_INPUT = "#11111b"         # Input background
BG_HOVER = "#313244"         # Button hover

ACCENT_PRIMARY = "#89b4fa"   # Sky blue
ACCENT_SUCCESS = "#a6e3a1"   # Mint green
ACCENT_WARNING = "#f9e2af"   # Amber gold
ACCENT_DANGER = "#f38ba8"    # Rose red
ACCENT_PURPLE = "#cba6f7"    # Lavender

TEXT_PRIMARY = "#cdd6f4"     # Crisp white/light
TEXT_SECONDARY = "#a6adc8"   # Subtle text
TEXT_MUTED = "#6c7086"       # Placeholder/muted text
BORDER_COLOR = "#313244"     # Card border

FONT_FAMILY = "Segoe UI" if sys.platform == "win32" else "Helvetica"
FONT_HERO = (FONT_FAMILY, 16, "bold")
FONT_TITLE = (FONT_FAMILY, 12, "bold")
FONT_HEADING = (FONT_FAMILY, 10, "bold")
FONT_BODY = (FONT_FAMILY, 9)
FONT_BODY_BOLD = (FONT_FAMILY, 9, "bold")
FONT_SMALL = (FONT_FAMILY, 8)
FONT_CODE = ("Consolas" if sys.platform == "win32" else "Courier", 9)


# =====================================================================
# UI Helpers & Custom Widgets
# =====================================================================
def apply_theme(root: tk.Tk) -> ttk.Style:
    """Configure modern dark styling for TTK widgets."""
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    root.configure(bg=BG_DARK)

    # Frames
    style.configure("TFrame", background=BG_DARK)
    style.configure("Surface.TFrame", background=BG_SURFACE)
    style.configure("Card.TFrame", background=BG_CARD)

    # Labels
    style.configure("TLabel", background=BG_DARK, foreground=TEXT_PRIMARY, font=FONT_BODY)
    style.configure("Card.TLabel", background=BG_CARD, foreground=TEXT_PRIMARY, font=FONT_BODY)
    style.configure("Hero.TLabel", background=BG_SURFACE, foreground=ACCENT_PRIMARY, font=FONT_HERO)
    style.configure("Title.TLabel", background=BG_CARD, foreground=ACCENT_PRIMARY, font=FONT_TITLE)
    style.configure("Heading.TLabel", background=BG_CARD, foreground=TEXT_PRIMARY, font=FONT_HEADING)
    style.configure("Muted.TLabel", background=BG_CARD, foreground=TEXT_MUTED, font=FONT_SMALL)
    style.configure("Success.TLabel", background=BG_CARD, foreground=ACCENT_SUCCESS, font=FONT_BODY_BOLD)
    style.configure("Error.TLabel", background=BG_CARD, foreground=ACCENT_DANGER, font=FONT_BODY_BOLD)

    # Buttons
    style.configure(
        "Primary.TButton",
        background=ACCENT_PRIMARY,
        foreground="#11111b",
        font=FONT_BODY_BOLD,
        borderwidth=0,
        focuscolor="none",
        padding=(12, 6),
    )
    style.map(
        "Primary.TButton",
        background=[("active", "#b4befe"), ("disabled", "#45475a")],
        foreground=[("disabled", "#6c7086")],
    )

    style.configure(
        "Success.TButton",
        background=ACCENT_SUCCESS,
        foreground="#11111b",
        font=FONT_BODY_BOLD,
        borderwidth=0,
        focuscolor="none",
        padding=(12, 6),
    )
    style.map(
        "Success.TButton",
        background=[("active", "#94e2d5")],
    )

    style.configure(
        "Secondary.TButton",
        background=BG_HOVER,
        foreground=TEXT_PRIMARY,
        font=FONT_BODY,
        borderwidth=0,
        focuscolor="none",
        padding=(10, 5),
    )
    style.map(
        "Secondary.TButton",
        background=[("active", "#45475a"), ("disabled", "#313244")],
        foreground=[("disabled", "#6c7086")],
    )

    # Entry Fields
    style.configure(
        "TEntry",
        fieldbackground=BG_INPUT,
        foreground=TEXT_PRIMARY,
        insertcolor=TEXT_PRIMARY,
        bordercolor=BORDER_COLOR,
        lightcolor=BORDER_COLOR,
        darkcolor=BORDER_COLOR,
        padding=4,
    )

    # Notebook Tabs
    style.configure(
        "TNotebook",
        background=BG_DARK,
        borderwidth=0,
        tabmargins=[4, 4, 4, 0],
    )
    style.configure(
        "TNotebook.Tab",
        background=BG_SURFACE,
        foreground=TEXT_SECONDARY,
        font=FONT_HEADING,
        padding=[20, 8],
        borderwidth=0,
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", BG_CARD), ("active", BG_HOVER)],
        foreground=[("selected", ACCENT_PRIMARY), ("active", TEXT_PRIMARY)],
    )

    # Progressbar
    style.configure(
        "Horizontal.TProgressbar",
        background=ACCENT_PRIMARY,
        troughcolor=BG_INPUT,
        bordercolor=BORDER_COLOR,
        lightcolor=ACCENT_PRIMARY,
        darkcolor=ACCENT_PRIMARY,
    )

    return style


def create_thumbnail_photoimage(
    image_input: Union[str, Path, np.ndarray, Image.Image],
    max_size: Tuple[int, int] = (180, 140),
) -> Optional[ImageTk.PhotoImage]:
    """Load an image and generate a scaled Tk PhotoImage thumbnail."""
    try:
        if isinstance(image_input, np.ndarray):
            img = Image.fromarray(image_input)
        elif isinstance(image_input, Image.Image):
            img = image_input
        else:
            img = Image.open(image_input)

        img.thumbnail(max_size, Image.Resampling.LANCZOS)
        return ImageTk.PhotoImage(img)
    except Exception:
        return None


# =====================================================================
# Difference Map Inspector Modal Window
# =====================================================================
class DifferenceViewerModal(tk.Toplevel):
    """Side-by-side visual difference map and stego quality inspector."""

    def __init__(
        self,
        parent: tk.Tk,
        original_path: str,
        stego_path: str,
        metrics_dict: Dict[str, Any],
    ):
        super().__init__(parent)
        self.title("Steganography Difference Inspector")
        self.geometry("820x560")
        self.configure(bg=BG_DARK)
        self.transient(parent)
        self.grab_set()

        self.original_path = original_path
        self.stego_path = stego_path
        self.metrics_dict = metrics_dict
        self.amplify_var = tk.IntVar(value=20)
        self.photo_refs = []  # Prevent garbage collection

        self._build_ui()
        self._update_difference_map()

    def _build_ui(self) -> None:
        header = ttk.Frame(self, style="Surface.TFrame", padding=(15, 10))
        header.pack(fill="x")
        ttk.Label(header, text="🔍 Stego Visual Fidelity & Difference Map", style="Hero.TLabel").pack(side="left")

        # Controls for amplification
        ctrl_frame = ttk.Frame(self, style="Surface.TFrame", padding=(15, 6))
        ctrl_frame.pack(fill="x")
        ttk.Label(ctrl_frame, text="Amplification Multiplier: ", style="Card.TLabel").pack(side="left")

        for factor in (5, 10, 20, 50, 100):
            r = tk.Radiobutton(
                ctrl_frame,
                text=f"{factor}x",
                variable=self.amplify_var,
                value=factor,
                command=self._update_difference_map,
                bg=BG_SURFACE,
                fg=TEXT_PRIMARY,
                selectcolor=BG_CARD,
                activebackground=BG_SURFACE,
                activeforeground=ACCENT_PRIMARY,
            )
            r.pack(side="left", padx=6)

        # Image comparison panels
        panels = ttk.Frame(self, padding=12)
        panels.pack(fill="both", expand=True)

        # Panel 1: Original Cover
        p1 = ttk.Frame(panels, style="Card.TFrame", padding=8)
        p1.pack(side="left", fill="both", expand=True, padx=4)
        ttk.Label(p1, text="Original Cover", style="Heading.TLabel").pack(anchor="w")
        self.lbl_orig = ttk.Label(p1, background=BG_CARD)
        self.lbl_orig.pack(fill="both", expand=True, pady=6)

        # Panel 2: Stego Image
        p2 = ttk.Frame(panels, style="Card.TFrame", padding=8)
        p2.pack(side="left", fill="both", expand=True, padx=4)
        ttk.Label(p2, text="Stego Image", style="Heading.TLabel").pack(anchor="w")
        self.lbl_stego = ttk.Label(p2, background=BG_CARD)
        self.lbl_stego.pack(fill="both", expand=True, pady=6)

        # Panel 3: Amplified Difference Map
        p3 = ttk.Frame(panels, style="Card.TFrame", padding=8)
        p3.pack(side="left", fill="both", expand=True, padx=4)
        ttk.Label(p3, text="Amplified Heatmap", style="Heading.TLabel").pack(anchor="w")
        self.lbl_diff = ttk.Label(p3, background=BG_CARD)
        self.lbl_diff.pack(fill="both", expand=True, pady=6)

        # Metrics Footer
        footer = ttk.Frame(self, style="Card.TFrame", padding=(15, 10))
        footer.pack(fill="x", padx=12, pady=(0, 12))

        m_text = (
            f"PSNR: {self.metrics_dict.get('psnr_db', 0):.2f} dB   |   "
            f"MSE: {self.metrics_dict.get('mse', 0):.6f}   |   "
            f"SSIM: {self.metrics_dict.get('ssim', 0):.6f}   |   "
            f"Carrier Altered: {self.metrics_dict.get('modified_percentage', 0)}%   |   "
            f"Rating: {self.metrics_dict.get('quality_rating', 'N/A')}"
        )
        ttk.Label(footer, text=m_text, style="Success.TLabel").pack(side="left")

        btn_close = ttk.Button(footer, text="Close", style="Secondary.TButton", command=self.destroy)
        btn_close.pack(side="right")

        # Load static thumbs
        self.orig_tk = create_thumbnail_photoimage(self.original_path, max_size=(240, 240))
        self.stego_tk = create_thumbnail_photoimage(self.stego_path, max_size=(240, 240))
        if self.orig_tk:
            self.lbl_orig.configure(image=self.orig_tk)
        if self.stego_tk:
            self.lbl_stego.configure(image=self.stego_tk)

    def _update_difference_map(self) -> None:
        try:
            amplify = self.amplify_var.get()
            orig_arr = np.array(Image.open(self.original_path))
            stego_arr = np.array(Image.open(self.stego_path))
            diff = np.abs(orig_arr.astype(np.int16) - stego_arr.astype(np.int16))
            amplified = np.clip(diff * amplify, 0, 255).astype(np.uint8)

            diff_img = Image.fromarray(amplified)
            self.diff_tk = create_thumbnail_photoimage(diff_img, max_size=(240, 240))
            if self.diff_tk:
                self.lbl_diff.configure(image=self.diff_tk)
        except Exception as e:
            self.lbl_diff.configure(text=f"Diff Error: {e}")


# =====================================================================
# Main Application Window
# =====================================================================
class StegoApp(tk.Tk):
    """Main Desktop Application Controller."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Image Encryption & Steganography Engine (AES-256-GCM + LSB)")
        self.geometry("960x720")
        self.minsize(860, 640)
        self.configure(bg=BG_DARK)

        apply_theme(self)

        # State Variables
        self.cover_image_path: Optional[str] = None
        self.stego_image_path: Optional[str] = None
        self.extract_image_path: Optional[str] = None
        self.last_embedding_result: Optional[Dict[str, Any]] = None

        self._build_ui()

    def _build_ui(self) -> None:
        # Header Banner
        header = ttk.Frame(self, style="Surface.TFrame", padding=(20, 12))
        header.pack(fill="x")

        ttk.Label(header, text="🔒 Image Encryption & Steganography Suite", style="Hero.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Enterprise Authenticated Encryption (AES-256-GCM + PBKDF2) with Vectorized LSB Concealment",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(2, 0))

        # Main Tab Container
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=14, pady=10)

        # Tab 1: Encrypt & Hide
        self.tab_hide = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(self.tab_hide, text="  🔒 Encrypt & Hide  ")
        self._build_hide_tab()

        # Tab 2: Extract & Decrypt
        self.tab_extract = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(self.tab_extract, text="  🔓 Extract & Decrypt  ")
        self._build_extract_tab()

        # Footer Status Bar
        self.status_frame = ttk.Frame(self, style="Surface.TFrame", padding=(14, 6))
        self.status_frame.pack(fill="x", side="bottom")

        self.lbl_status = ttk.Label(self.status_frame, text="Ready.", style="Muted.TLabel")
        self.lbl_status.pack(side="left")

        self.progress_bar = ttk.Progressbar(self.status_frame, mode="indeterminate", length=140)

    # =================================================================
    # Tab 1: Encrypt & Hide UI Construction
    # =================================================================
    def _build_hide_tab(self) -> None:
        container = ttk.Frame(self.tab_hide)
        container.pack(fill="both", expand=True)

        # Left Column: Inputs & Image Selection (width 60%)
        left_col = ttk.Frame(container)
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 8))

        # 1. Cover Image Card
        card_cover = ttk.Frame(left_col, style="Card.TFrame", padding=10)
        card_cover.pack(fill="x", pady=(0, 8))

        ttk.Label(card_cover, text="1. Select Lossless Cover Image (.png, .bmp)", style="Heading.TLabel").pack(anchor="w")

        btn_row = ttk.Frame(card_cover, style="Card.TFrame")
        btn_row.pack(fill="x", pady=(6, 4))

        self.btn_select_cover = ttk.Button(btn_row, text="📁 Choose Cover Image...", style="Secondary.TButton", command=self._on_select_cover_image)
        self.btn_select_cover.pack(side="left")

        self.lbl_cover_filename = ttk.Label(btn_row, text="No image selected", style="Muted.TLabel")
        self.lbl_cover_filename.pack(side="left", padx=10)

        # Image preview & capacity details
        info_row = ttk.Frame(card_cover, style="Card.TFrame")
        info_row.pack(fill="x", pady=(4, 0))

        self.lbl_cover_thumb = ttk.Label(info_row, background=BG_INPUT, relief="solid", borderwidth=1)
        self.lbl_cover_thumb.pack(side="left", padx=(0, 10))

        self.lbl_cover_stats = ttk.Label(
            info_row,
            text="Dimensions: N/A\nMax Usable Capacity: 0 bytes\nSupported Channels: RGB/RGBA",
            style="Card.TLabel",
            justify="left",
        )
        self.lbl_cover_stats.pack(side="left", fill="both")

        # 2. Secret Message Card
        card_secret = ttk.Frame(left_col, style="Card.TFrame", padding=10)
        card_secret.pack(fill="both", expand=True, pady=(0, 8))

        ttk.Label(card_secret, text="2. Secret Plaintext Message", style="Heading.TLabel").pack(anchor="w")

        self.txt_secret = tk.Text(
            card_secret,
            bg=BG_INPUT,
            fg=TEXT_PRIMARY,
            insertbackground=TEXT_PRIMARY,
            relief="flat",
            font=FONT_BODY,
            wrap="word",
            height=6,
        )
        self.txt_secret.pack(fill="both", expand=True, pady=(6, 4))
        self.txt_secret.bind("<KeyRelease>", self._on_secret_text_change)

        self.lbl_secret_counter = ttk.Label(card_secret, text="Payload: 0 characters (0 bytes)", style="Muted.TLabel")
        self.lbl_secret_counter.pack(anchor="e")

        # 3. Security Passphrase Card
        card_pass = ttk.Frame(left_col, style="Card.TFrame", padding=10)
        card_pass.pack(fill="x", pady=(0, 8))

        ttk.Label(card_pass, text="3. Security Passphrase (PBKDF2-HMAC-SHA256)", style="Heading.TLabel").pack(anchor="w")

        pass_row = ttk.Frame(card_pass, style="Card.TFrame")
        pass_row.pack(fill="x", pady=(6, 0))

        self.ent_hide_pass = ttk.Entry(pass_row, show="●", font=FONT_BODY)
        self.ent_hide_pass.pack(side="left", fill="x", expand=True, padx=(0, 6))

        self.btn_toggle_hide_pass = ttk.Button(pass_row, text="👁 Show", style="Secondary.TButton", width=8, command=lambda: self._toggle_password_visibility(self.ent_hide_pass, self.btn_toggle_hide_pass))
        self.btn_toggle_hide_pass.pack(side="right")

        # Action Button
        self.btn_encrypt_hide = ttk.Button(
            left_col,
            text="⚡ Encrypt & Hide Payload into Image",
            style="Primary.TButton",
            command=self._on_start_encrypt_and_hide,
        )
        self.btn_encrypt_hide.pack(fill="x", pady=(0, 0))

        # Right Column: Output & Steganography Metrics Dashboard
        right_col = ttk.Frame(container, style="Card.TFrame", padding=12)
        right_col.pack(side="right", fill="both", expand=True)

        ttk.Label(right_col, text="📊 Stego Output & Visual Quality", style="Title.TLabel").pack(anchor="w")

        # Stego preview thumb
        self.lbl_stego_thumb = ttk.Label(right_col, background=BG_INPUT, relief="solid", borderwidth=1)
        self.lbl_stego_thumb.pack(pady=10)

        # Metrics Display Grid
        self.metrics_frame = ttk.Frame(right_col, style="Card.TFrame")
        self.metrics_frame.pack(fill="x", pady=6)

        self.lbl_psnr = ttk.Label(self.metrics_frame, text="Peak SNR (PSNR): -- dB", style="Heading.TLabel")
        self.lbl_psnr.pack(anchor="w", pady=2)

        self.lbl_mse = ttk.Label(self.metrics_frame, text="Mean Squared Error (MSE): --", style="Card.TLabel")
        self.lbl_mse.pack(anchor="w", pady=2)

        self.lbl_ssim = ttk.Label(self.metrics_frame, text="Structural Similarity (SSIM): --", style="Card.TLabel")
        self.lbl_ssim.pack(anchor="w", pady=2)

        self.lbl_capacity_used = ttk.Label(self.metrics_frame, text="Carrier Utilized: -- %", style="Card.TLabel")
        self.lbl_capacity_used.pack(anchor="w", pady=2)

        self.lbl_rating = ttk.Label(self.metrics_frame, text="Imperceptibility: --", style="Success.TLabel")
        self.lbl_rating.pack(anchor="w", pady=(4, 8))

        # Buttons on right
        self.btn_inspect_diff = ttk.Button(
            right_col,
            text="🔍 Inspect Difference Map",
            style="Secondary.TButton",
            state="disabled",
            command=self._on_open_difference_viewer,
        )
        self.btn_inspect_diff.pack(fill="x", pady=(4, 6))

        self.btn_save_stego = ttk.Button(
            right_col,
            text="💾 Save Stego Image As...",
            style="Success.TButton",
            state="disabled",
            command=self._on_save_stego_image,
        )
        self.btn_save_stego.pack(fill="x", side="bottom")

    # =================================================================
    # Tab 2: Extract & Decrypt UI Construction
    # =================================================================
    def _build_extract_tab(self) -> None:
        container = ttk.Frame(self.tab_extract)
        container.pack(fill="both", expand=True)

        # 1. Stego Image Selection Card
        card_select = ttk.Frame(container, style="Card.TFrame", padding=12)
        card_select.pack(fill="x", pady=(0, 10))

        ttk.Label(card_select, text="1. Select Stego Image (.png, .bmp)", style="Heading.TLabel").pack(anchor="w")

        row1 = ttk.Frame(card_select, style="Card.TFrame")
        row1.pack(fill="x", pady=(8, 0))

        self.btn_select_extract_image = ttk.Button(
            row1,
            text="📁 Choose Stego Image...",
            style="Secondary.TButton",
            command=self._on_select_extract_image,
        )
        self.btn_select_extract_image.pack(side="left")

        self.lbl_extract_filename = ttk.Label(row1, text="No image selected", style="Muted.TLabel")
        self.lbl_extract_filename.pack(side="left", padx=10)

        # Thumbnail & dimensions
        extract_info = ttk.Frame(card_select, style="Card.TFrame")
        extract_info.pack(fill="x", pady=(8, 0))

        self.lbl_extract_thumb = ttk.Label(extract_info, background=BG_INPUT, relief="solid", borderwidth=1)
        self.lbl_extract_thumb.pack(side="left", padx=(0, 10))

        self.lbl_extract_stats = ttk.Label(extract_info, text="Dimensions: N/A\nFormat: PNG/BMP", style="Card.TLabel")
        self.lbl_extract_stats.pack(side="left")

        # 2. Decryption Passphrase Card
        card_pass = ttk.Frame(container, style="Card.TFrame", padding=12)
        card_pass.pack(fill="x", pady=(0, 10))

        ttk.Label(card_pass, text="2. Decryption Passphrase", style="Heading.TLabel").pack(anchor="w")

        pass_row = ttk.Frame(card_pass, style="Card.TFrame")
        pass_row.pack(fill="x", pady=(8, 0))

        self.ent_extract_pass = ttk.Entry(pass_row, show="●", font=FONT_BODY)
        self.ent_extract_pass.pack(side="left", fill="x", expand=True, padx=(0, 6))

        self.btn_toggle_extract_pass = ttk.Button(
            pass_row,
            text="👁 Show",
            style="Secondary.TButton",
            width=8,
            command=lambda: self._toggle_password_visibility(self.ent_extract_pass, self.btn_toggle_extract_pass),
        )
        self.btn_toggle_extract_pass.pack(side="right")

        # Action Button
        self.btn_extract_decrypt = ttk.Button(
            container,
            text="🔓 Extract & Decrypt Secret Payload",
            style="Primary.TButton",
            command=self._on_start_extract_and_decrypt,
        )
        self.btn_extract_decrypt.pack(fill="x", pady=(0, 10))

        # 3. Recovered Output Card
        card_out = ttk.Frame(container, style="Card.TFrame", padding=12)
        card_out.pack(fill="both", expand=True)

        header_out = ttk.Frame(card_out, style="Card.TFrame")
        header_out.pack(fill="x", pady=(0, 6))

        ttk.Label(header_out, text="3. Recovered Plaintext Message", style="Heading.TLabel").pack(side="left")

        self.btn_copy_clipboard = ttk.Button(
            header_out,
            text="📋 Copy to Clipboard",
            style="Secondary.TButton",
            command=self._on_copy_to_clipboard,
        )
        self.btn_copy_clipboard.pack(side="right")

        self.txt_recovered = tk.Text(
            card_out,
            bg=BG_INPUT,
            fg=ACCENT_SUCCESS,
            insertbackground=TEXT_PRIMARY,
            relief="flat",
            font=FONT_BODY,
            wrap="word",
        )
        self.txt_recovered.pack(fill="both", expand=True)

    # =================================================================
    # Event Handlers & Business Logic (Tab 1)
    # =================================================================
    def _on_select_cover_image(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Select Lossless Cover Image",
            filetypes=[("Lossless Images", "*.png;*.bmp"), ("PNG Images", "*.png"), ("BMP Images", "*.bmp")],
        )
        if not file_path:
            return

        try:
            self.cover_image_path = file_path
            path_obj = Path(file_path)
            self.lbl_cover_filename.configure(text=path_obj.name)

            # Calculate capacity
            capacity = stego.calculate_capacity(file_path)
            with Image.open(file_path) as img:
                w, h = img.size
                mode = img.mode

            self.lbl_cover_stats.configure(
                text=f"Dimensions: {w} x {h} ({mode})\n"
                     f"Max Usable Capacity: {capacity:,} bytes ({capacity / 1024:.2f} KB)\n"
                     f"LSB Channels: R, G, B (3 bits/pixel)"
            )

            # Update Thumbnail
            self.cover_thumb_tk = create_thumbnail_photoimage(file_path, max_size=(100, 75))
            if self.cover_thumb_tk:
                self.lbl_cover_thumb.configure(image=self.cover_thumb_tk)

            self.set_status(f"Loaded cover image: {path_obj.name} (Capacity: {capacity:,} B)")

        except Exception as e:
            messagebox.showerror("Image Load Error", f"Failed to inspect cover image:\n{e}")

    def _on_secret_text_change(self, event=None) -> None:
        text = self.txt_secret.get("1.0", "end-1c")
        chars = len(text)
        b_len = len(text.encode("utf-8"))
        self.lbl_secret_counter.configure(text=f"Payload: {chars:,} characters ({b_len:,} bytes)")

    def _on_start_encrypt_and_hide(self) -> None:
        if not self.cover_image_path:
            messagebox.showwarning("Missing Cover Image", "Please select a lossless cover image first.")
            return

        secret_text = self.txt_secret.get("1.0", "end-1c")
        if not secret_text:
            messagebox.showwarning("Empty Secret Message", "Please enter a secret message to conceal.")
            return

        passphrase = self.ent_hide_pass.get()
        if not passphrase:
            messagebox.showwarning("Missing Passphrase", "Please enter an encryption passphrase.")
            return

        # Prepare background worker thread
        self._set_busy(True, "Encrypting secret payload and embedding into carrier...")

        # Temporary stego path for immediate review
        temp_stego_path = Path(self.cover_image_path).parent / f"stego_preview_{os.getpid()}.png"

        def worker():
            try:
                result = encrypt_and_hide(
                    cover_image_path=self.cover_image_path,
                    secret_text=secret_text,
                    passphrase=passphrase,
                    output_image_path=temp_stego_path,
                )
                self.after(0, self._on_hide_success, result)
            except CapacityError as exc:
                self.after(0, self._on_hide_error, f"Capacity Exceeded:\n{exc}")
            except UnsupportedFormatError as exc:
                self.after(0, self._on_hide_error, f"Unsupported Format:\n{exc}")
            except Exception as exc:
                self.after(0, self._on_hide_error, f"Operation Failed:\n{exc}")

        threading.Thread(target=worker, daemon=True).start()

    def _on_hide_success(self, result: Dict[str, Any]) -> None:
        self._set_busy(False, "Steganography embedding completed successfully!")
        self.last_embedding_result = result
        self.stego_image_path = result["output_path"]

        # Update metrics labels
        self.lbl_psnr.configure(text=f"Peak SNR (PSNR): {result['psnr_db']:.2f} dB")
        self.lbl_mse.configure(text=f"Mean Squared Error (MSE): {result['mse']:.6f}")
        self.lbl_ssim.configure(text=f"Structural Similarity (SSIM): {result['ssim']:.6f}")
        self.lbl_capacity_used.configure(
            text=f"Carrier Utilized: {result['capacity_used_pct']}% ({result['encrypted_payload_bytes']:,} B)"
        )
        self.lbl_rating.configure(text=f"Imperceptibility: {result['quality_rating']}")

        # Update thumbnail preview
        self.stego_thumb_tk = create_thumbnail_photoimage(result["output_path"], max_size=(160, 120))
        if self.stego_thumb_tk:
            self.lbl_stego_thumb.configure(image=self.stego_thumb_tk)

        self.btn_inspect_diff.configure(state="normal")
        self.btn_save_stego.configure(state="normal")

        messagebox.showinfo(
            "Embedding Succeeded",
            f"Successfully encrypted and embedded payload into stego carrier!\n\n"
            f"• Payload Size: {result['encrypted_payload_bytes']:,} bytes\n"
            f"• PSNR: {result['psnr_db']:.2f} dB (Visual Imperceptibility: {result['quality_rating']})\n"
            f"• SSIM: {result['ssim']:.6f}",
        )

    def _on_hide_error(self, err_msg: str) -> None:
        self._set_busy(False, "Error during embedding.")
        messagebox.showerror("Embedding Error", err_msg)

    def _on_save_stego_image(self) -> None:
        if not self.stego_image_path or not Path(self.stego_image_path).is_file():
            messagebox.showwarning("No Stego Image", "Please embed a message first.")
            return

        save_path = filedialog.asksaveasfilename(
            title="Save Stego Image",
            defaultextension=".png",
            filetypes=[("PNG Image", "*.png"), ("BMP Image", "*.bmp")],
        )
        if not save_path:
            return

        try:
            # Copy or save image
            img = Image.open(self.stego_image_path)
            fmt = "PNG" if Path(save_path).suffix.lower() == ".png" else "BMP"
            img.save(save_path, format=fmt)
            self.set_status(f"Stego image saved to: {Path(save_path).name}")
            messagebox.showinfo("Saved", f"Stego image successfully saved to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save stego image:\n{e}")

    def _on_open_difference_viewer(self) -> None:
        if not self.cover_image_path or not self.stego_image_path or not self.last_embedding_result:
            return
        DifferenceViewerModal(self, self.cover_image_path, self.stego_image_path, self.last_embedding_result)

    # =================================================================
    # Event Handlers & Business Logic (Tab 2)
    # =================================================================
    def _on_select_extract_image(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Select Stego Image to Decrypt",
            filetypes=[("Lossless Images", "*.png;*.bmp"), ("PNG Images", "*.png"), ("BMP Images", "*.bmp")],
        )
        if not file_path:
            return

        try:
            self.extract_image_path = file_path
            path_obj = Path(file_path)
            self.lbl_extract_filename.configure(text=path_obj.name)

            with Image.open(file_path) as img:
                w, h = img.size
                mode = img.mode

            self.lbl_extract_stats.configure(text=f"Dimensions: {w} x {h} ({mode})\nFormat: {path_obj.suffix.upper()}")

            self.extract_thumb_tk = create_thumbnail_photoimage(file_path, max_size=(100, 75))
            if self.extract_thumb_tk:
                self.lbl_extract_thumb.configure(image=self.extract_thumb_tk)

            self.set_status(f"Loaded stego image for extraction: {path_obj.name}")

        except Exception as e:
            messagebox.showerror("Load Error", f"Failed to inspect stego image:\n{e}")

    def _on_start_extract_and_decrypt(self) -> None:
        if not self.extract_image_path:
            messagebox.showwarning("Missing Stego Image", "Please select a stego image to extract from.")
            return

        passphrase = self.ent_extract_pass.get()
        if not passphrase:
            messagebox.showwarning("Missing Passphrase", "Please enter the decryption passphrase.")
            return

        self._set_busy(True, "Extracting LSBs and authenticating AEAD decryption...")

        def worker():
            try:
                plaintext = extract_and_decrypt(
                    stego_image_path=self.extract_image_path,
                    passphrase=passphrase,
                )
                self.after(0, self._on_extract_success, plaintext)
            except AuthenticationError as exc:
                self.after(0, self._on_extract_error, f"Authentication Failed:\n{exc}")
            except Exception as exc:
                self.after(0, self._on_extract_error, f"Extraction Failed:\n{exc}")

        threading.Thread(target=worker, daemon=True).start()

    def _on_extract_success(self, plaintext: str) -> None:
        self._set_busy(False, "Decryption and payload recovery verified!")
        self.txt_recovered.delete("1.0", "end")
        self.txt_recovered.insert("1.0", plaintext)
        messagebox.showinfo("Extraction Succeeded", f"Secret message successfully decrypted and authenticated!\n\nLength: {len(plaintext):,} characters")

    def _on_extract_error(self, err_msg: str) -> None:
        self._set_busy(False, "Decryption failed.")
        self.txt_recovered.delete("1.0", "end")
        messagebox.showerror("Decryption Failure", err_msg)

    def _on_copy_to_clipboard(self) -> None:
        text = self.txt_recovered.get("1.0", "end-1c")
        if not text:
            messagebox.showwarning("Empty", "No text to copy.")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.set_status("Copied recovered secret to clipboard!")
        self.btn_copy_clipboard.configure(text="✅ Copied!")
        self.after(2000, lambda: self.btn_copy_clipboard.configure(text="📋 Copy to Clipboard"))

    # =================================================================
    # Common Utilities
    # =================================================================
    def _toggle_password_visibility(self, entry_widget: ttk.Entry, button_widget: ttk.Button) -> None:
        if entry_widget.cget("show") == "●":
            entry_widget.configure(show="")
            button_widget.configure(text="🙈 Hide")
        else:
            entry_widget.configure(show="●")
            button_widget.configure(text="👁 Show")

    def _set_busy(self, is_busy: bool, status_text: str = "") -> None:
        if is_busy:
            self.progress_bar.pack(side="right", padx=10)
            self.progress_bar.start(10)
            self.btn_encrypt_hide.configure(state="disabled")
            self.btn_extract_decrypt.configure(state="disabled")
        else:
            self.progress_bar.stop()
            self.progress_bar.pack_forget()
            self.btn_encrypt_hide.configure(state="normal")
            self.btn_extract_decrypt.configure(state="normal")
        self.set_status(status_text)

    def set_status(self, text: str) -> None:
        self.lbl_status.configure(text=text)


# =====================================================================
# Standalone Execution Entrypoint
# =====================================================================
if __name__ == "__main__":
    app = StegoApp()
    app.mainloop()
