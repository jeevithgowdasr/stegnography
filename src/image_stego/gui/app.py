"""Main desktop application window for Image Encryption Using Steganography."""

import tkinter as tk
from tkinter import ttk

from .styles import apply_theme, BG_DARK, BG_INPUT, TEXT_MUTED, ACCENT_PRIMARY, FONT_SMALL
from .views.encode_view import EncodeView
from .views.decode_view import DecodeView
from .views.metrics_view import MetricsView


class StegoApp(tk.Tk):
    """Main Steganography Application."""

    def __init__(self):
        super().__init__()

        self.title("StegoCrypt — Secure Image Encryption & Steganography")
        self.geometry("920 x 700")
        self.minsize(820, 600)

        # Apply dark theme
        self.style = apply_theme(self)

        self._build_header()
        self._build_tabs()
        self._build_statusbar()

    def _build_header(self):
        header_frame = ttk.Frame(self, style="TFrame", padding=(15, 12, 15, 6))
        header_frame.pack(fill="x")

        title_label = ttk.Label(
            header_frame,
            text="🔒 StegoCrypt — Image Encryption Using Steganography",
            style="Header.TLabel",
        )
        title_label.pack(anchor="w")

        subtitle_label = ttk.Label(
            header_frame,
            text="AES-256-GCM Authenticated Encryption with Lossless LSB Pixel Embedding (PNG & BMP)",
            style="Muted.TLabel",
        )
        subtitle_label.pack(anchor="w", pady=(2, 0))

    def _build_tabs(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(5, 5))

        # Tab 1: Encrypt & Hide
        self.encode_view = EncodeView(self.notebook, status_callback=self.set_status)
        self.notebook.add(self.encode_view, text="  🔒 Encrypt & Hide  ")

        # Tab 2: Extract & Decrypt
        self.decode_view = DecodeView(self.notebook, status_callback=self.set_status)
        self.notebook.add(self.decode_view, text="  🔓 Extract & Decrypt  ")

        # Tab 3: Metrics & Quality Analysis
        self.metrics_view = MetricsView(self.notebook, status_callback=self.set_status)
        self.notebook.add(self.metrics_view, text="  📊 Quality & PSNR Analysis  ")

    def _build_statusbar(self):
        status_frame = ttk.Frame(self, style="TFrame", padding=(12, 6))
        status_frame.pack(fill="x", side="bottom")

        self.status_var = tk.StringVar(value="Ready. Select an operation to get started.")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, font=FONT_SMALL, foreground=TEXT_MUTED)
        self.status_label.pack(side="left")

        engine_badge = ttk.Label(
            status_frame,
            text="Engine: AES-256-GCM + PBKDF2-HMAC-SHA256 (100k iters)",
            font=FONT_SMALL,
            foreground=ACCENT_PRIMARY,
        )
        engine_badge.pack(side="right")

    def set_status(self, text: str):
        self.status_var.set(text)


def launch_gui():
    """Entry point to start the Tkinter GUI loop."""
    app = StegoApp()
    app.mainloop()


if __name__ == "__main__":
    launch_gui()
