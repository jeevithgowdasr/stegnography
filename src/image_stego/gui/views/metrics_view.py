"""Tab 3: Image Quality, PSNR/MSE, and Steganalysis Metrics View."""

import os
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk

from ...utils.metrics import calculate_quality_metrics, generate_difference_map
from ...utils.image_io import load_image
from ..styles import (
    BG_CARD, BG_INPUT, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT_PRIMARY, ACCENT_SUCCESS, ACCENT_PURPLE, FONT_BODY, FONT_HEADING, FONT_SMALL
)
from ..workers import run_async


class MetricsView(ttk.Frame):
    """View component for measuring PSNR, MSE, and visualizing stego imperceptibility."""

    def __init__(self, parent, status_callback=None):
        super().__init__(parent, style="TFrame")
        self.status_callback = status_callback

        self.orig_path = tk.StringVar()
        self.stego_path = tk.StringVar()
        self.orig_preview_ref = None
        self.stego_preview_ref = None
        self.diff_preview_ref = None

        self._build_ui()

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        # Top Control Card: File Selectors & Compute Button
        top_card = ttk.Frame(self, style="Card.TFrame", padding=15)
        top_card.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        top_card.columnconfigure(1, weight=1)
        top_card.columnconfigure(3, weight=1)

        # Row 0: Original
        ttk.Label(top_card, text="Original Image:", style="Card.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(top_card, textvariable=self.orig_path).grid(row=0, column=1, sticky="ew", padx=(0, 8))
        ttk.Button(top_card, text="Browse...", style="Secondary.TButton", command=self._browse_orig).grid(
            row=0, column=2, padx=(0, 15)
        )

        # Row 0: Stego
        ttk.Label(top_card, text="Stego Image:", style="Card.TLabel").grid(row=0, column=3, sticky="w", padx=(0, 8))
        ttk.Entry(top_card, textvariable=self.stego_path).grid(row=0, column=4, sticky="ew", padx=(0, 8))
        ttk.Button(top_card, text="Browse...", style="Secondary.TButton", command=self._browse_stego).grid(
            row=0, column=5
        )

        self.compute_btn = ttk.Button(
            top_card, text="🔬 Analyze Quality & Metrics", style="Primary.TButton", command=self._start_analysis
        )
        self.compute_btn.grid(row=1, column=0, columnspan=6, sticky="ew", pady=(12, 0))

        # Bottom Display Area: Metrics on Left, Visual Comparisons on Right
        bottom_frame = ttk.Frame(self, style="TFrame")
        bottom_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        bottom_frame.columnconfigure(0, weight=1)
        bottom_frame.columnconfigure(1, weight=2)
        bottom_frame.rowconfigure(0, weight=1)

        # Left Card: Metrics Dashboard
        metrics_card = ttk.Frame(bottom_frame, style="Card.TFrame", padding=15)
        metrics_card.grid(row=0, column=0, sticky="nsew", padx=(0, 5), pady=5)
        metrics_card.columnconfigure(0, weight=1)

        ttk.Label(metrics_card, text="Steganographic Fidelity Report", style="SubHeader.TLabel").pack(
            anchor="w", pady=(0, 10)
        )

        self.psnr_card = self._create_metric_widget(metrics_card, "PSNR (Peak Signal-to-Noise Ratio)", "-- dB", "Imperceptible: > 60 dB")
        self.mse_card = self._create_metric_widget(metrics_card, "MSE (Mean Squared Error)", "--", "Near zero is ideal")
        self.mod_card = self._create_metric_widget(metrics_card, "Pixels Modified", "--", "Percentage of cover pixels altered")
        self.max_diff_card = self._create_metric_widget(metrics_card, "Max Pixel Variation", "--", "Max delta per channel (0-255)")

        # Right Card: Visual Difference Map
        visual_card = ttk.Frame(bottom_frame, style="Card.TFrame", padding=15)
        visual_card.grid(row=0, column=1, sticky="nsew", padx=(5, 0), pady=5)
        visual_card.columnconfigure(0, weight=1)
        visual_card.rowconfigure(1, weight=1)

        ttk.Label(visual_card, text="Amplified Modification Map (Red = Altered LSBs)", style="SubHeader.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 10)
        )

        self.diff_canvas = tk.Canvas(
            visual_card, bg=BG_INPUT, highlightthickness=1, highlightbackground="#313244"
        )
        self.diff_canvas.grid(row=1, column=0, sticky="nsew")

    def _create_metric_widget(self, parent, title, initial_val, subtitle):
        frame = ttk.Frame(parent, style="Card.TFrame")
        frame.pack(fill="x", pady=6)
        ttk.Label(frame, text=title, style="Card.TLabel").pack(anchor="w")
        val_label = ttk.Label(frame, text=initial_val, font=(FONT_BODY[0], 13, "bold"), foreground=ACCENT_PRIMARY)
        val_label.pack(anchor="w")
        sub_label = ttk.Label(frame, text=subtitle, style="Muted.TLabel")
        sub_label.pack(anchor="w")
        return val_label

    def _browse_orig(self):
        p = filedialog.askopenfilename(title="Select Original Image", filetypes=[("Lossless Images", "*.png;*.bmp")])
        if p:
            self.orig_path.set(p)

    def _browse_stego(self):
        p = filedialog.askopenfilename(title="Select Stego Image", filetypes=[("Lossless Images", "*.png;*.bmp")])
        if p:
            self.stego_path.set(p)

    def _start_analysis(self):
        orig = self.orig_path.get().strip()
        stego = self.stego_path.get().strip()

        if not orig or not os.path.isfile(orig):
            messagebox.showwarning("Missing Image", "Please select the original cover image.")
            return
        if not stego or not os.path.isfile(stego):
            messagebox.showwarning("Missing Image", "Please select the stego image.")
            return

        self.compute_btn.configure(state="disabled", text="Computing Metrics...")

        def task():
            orig_arr, _ = load_image(orig)
            stego_arr, _ = load_image(stego)
            metrics = calculate_quality_metrics(orig_arr, stego_arr)
            diff_map = generate_difference_map(orig_arr, stego_arr)
            return metrics, diff_map

        def on_success(res):
            self.compute_btn.configure(state="normal", text="🔬 Analyze Quality & Metrics")
            metrics, diff_map = res

            # Update Metric Labels
            if metrics.psnr_db >= 900:
                self.psnr_card.configure(text="∞ (Identical)", foreground=ACCENT_SUCCESS)
            elif metrics.psnr_db >= 60:
                self.psnr_card.configure(text=f"{metrics.psnr_db} dB (Excellent)", foreground=ACCENT_SUCCESS)
            else:
                self.psnr_card.configure(text=f"{metrics.psnr_db} dB", foreground=ACCENT_PURPLE)

            self.mse_card.configure(text=f"{metrics.mse:.6f}")
            self.mod_card.configure(
                text=f"{metrics.total_pixels_modified:,} px ({metrics.modified_percentage}%)"
            )
            self.max_diff_card.configure(text=f"{metrics.max_pixel_diff} / 255")

            # Render Difference Canvas
            pil_diff = Image.fromarray(diff_map)
            canvas_w = self.diff_canvas.winfo_width() or 400
            canvas_h = self.diff_canvas.winfo_height() or 240
            pil_diff.thumbnail((canvas_w, canvas_h), Image.Resampling.LANCZOS)
            self.diff_preview_ref = ImageTk.PhotoImage(pil_diff)

            self.diff_canvas.delete("all")
            self.diff_canvas.create_image(
                canvas_w // 2, canvas_h // 2, image=self.diff_preview_ref, anchor="center"
            )

            if self.status_callback:
                self.status_callback(f"Quality analysis complete. PSNR: {metrics.psnr_db} dB | MSE: {metrics.mse}")

        def on_error(err):
            self.compute_btn.configure(state="normal", text="🔬 Analyze Quality & Metrics")
            if self.status_callback:
                self.status_callback(f"Analysis failed: {str(err)}")
            messagebox.showerror("Analysis Error", str(err))

        run_async(self, task, on_success, on_error)
