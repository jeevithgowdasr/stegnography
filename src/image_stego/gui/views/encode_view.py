"""Tab 1: Encrypt & Hide View for the desktop application."""

import os
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk

from ...core.pipeline import encrypt_and_hide
from ...stego.capacity import calculate_max_payload_size, format_bytes
from ...utils.image_io import load_image
from ..styles import (
    BG_CARD, BG_INPUT, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT_PRIMARY, ACCENT_SUCCESS, ACCENT_DANGER, FONT_BODY, FONT_HEADING, FONT_SMALL, FONT_CODE
)
from ..workers import run_async


class EncodeView(ttk.Frame):
    """View component for encrypting data and embedding it into cover images."""

    def __init__(self, parent, status_callback=None):
        super().__init__(parent, style="TFrame")
        self.status_callback = status_callback

        self.cover_path = tk.StringVar()
        self.secret_mode = tk.StringVar(value="text")  # "text" or "file"
        self.secret_file_path = tk.StringVar()
        self.password_var = tk.StringVar()
        self.show_password = tk.BooleanVar(value=False)
        self.cover_capacity = 0
        self.cover_dimensions = (0, 0)
        self.preview_image_ref = None

        self._build_ui()

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        # Left Column: Image Selection & Preview
        left_card = ttk.Frame(self, style="Card.TFrame", padding=15)
        left_card.grid(row=0, column=0, sticky="nsew", padx=(10, 5), pady=10)
        left_card.columnconfigure(0, weight=1)

        ttk.Label(left_card, text="1. Select Cover Image (Lossless PNG / BMP)", style="SubHeader.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 10)
        )

        browse_frame = ttk.Frame(left_card, style="Card.TFrame")
        browse_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        browse_frame.columnconfigure(0, weight=1)

        self.path_entry = ttk.Entry(browse_frame, textvariable=self.cover_path)
        self.path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ttk.Button(browse_frame, text="Browse...", style="Secondary.TButton", command=self._browse_cover).grid(
            row=0, column=1
        )

        # Image Preview Box
        self.preview_canvas = tk.Canvas(
            left_card, bg=BG_INPUT, highlightthickness=1, highlightbackground="#313244", height=220
        )
        self.preview_canvas.grid(row=2, column=0, sticky="nsew", pady=(0, 10))

        # Capacity info
        self.info_label = ttk.Label(
            left_card,
            text="No image loaded. Please select a PNG or BMP image.",
            style="Muted.TLabel",
            wraplength=320,
        )
        self.info_label.grid(row=3, column=0, sticky="w")

        # Capacity Progress Bar
        self.cap_bar = ttk.Progressbar(left_card, style="Horizontal.TProgressbar", mode="determinate")
        self.cap_bar.grid(row=4, column=0, sticky="ew", pady=(10, 5))
        self.cap_text = ttk.Label(left_card, text="Storage: 0 B / 0 B (0%)", style="Muted.TLabel")
        self.cap_text.grid(row=5, column=0, sticky="w")

        # Right Column: Payload & Encryption Settings
        right_card = ttk.Frame(self, style="Card.TFrame", padding=15)
        right_card.grid(row=0, column=1, sticky="nsew", padx=(5, 10), pady=10)
        right_card.columnconfigure(0, weight=1)
        right_card.rowconfigure(3, weight=1)

        ttk.Label(right_card, text="2. Confidential Secret Payload", style="SubHeader.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 10)
        )

        # Mode Selection
        mode_frame = ttk.Frame(right_card, style="Card.TFrame")
        mode_frame.grid(row=1, column=0, sticky="w", pady=(0, 10))

        ttk.Radiobutton(
            mode_frame,
            text="Text Message",
            variable=self.secret_mode,
            value="text",
            command=self._on_mode_change,
        ).pack(side="left", padx=(0, 20))

        ttk.Radiobutton(
            mode_frame,
            text="Secret File",
            variable=self.secret_mode,
            value="file",
            command=self._on_mode_change,
        ).pack(side="left")

        # Container for Text vs File
        self.payload_container = ttk.Frame(right_card, style="Card.TFrame")
        self.payload_container.grid(row=2, column=0, sticky="nsew", pady=(0, 10))
        self.payload_container.columnconfigure(0, weight=1)
        self.payload_container.rowconfigure(0, weight=1)

        # Text input widget
        self.text_input = tk.Text(
            self.payload_container,
            bg=BG_INPUT,
            fg=TEXT_PRIMARY,
            insertbackground=TEXT_PRIMARY,
            relief="flat",
            font=FONT_BODY,
            wrap="word",
            height=8,
        )
        self.text_input.bind("<KeyRelease>", lambda e: self._update_payload_metrics())
        self.text_input.grid(row=0, column=0, sticky="nsew")

        # File input widget (hidden initially)
        self.file_frame = ttk.Frame(self.payload_container, style="Card.TFrame")
        self.file_frame.columnconfigure(0, weight=1)
        self.file_label = ttk.Label(self.file_frame, text="No secret file selected.", style="Muted.TLabel")
        self.file_label.grid(row=0, column=0, sticky="w", pady=(10, 5))
        ttk.Button(
            self.file_frame, text="Select Secret File...", style="Secondary.TButton", command=self._browse_secret_file
        ).grid(row=1, column=0, sticky="w")

        # 3. Encryption Password
        ttk.Label(right_card, text="3. Encryption Passphrase (AES-256-GCM)", style="SubHeader.TLabel").grid(
            row=4, column=0, sticky="w", pady=(10, 5)
        )

        pwd_frame = ttk.Frame(right_card, style="Card.TFrame")
        pwd_frame.grid(row=5, column=0, sticky="ew", pady=(0, 15))
        pwd_frame.columnconfigure(0, weight=1)

        self.pwd_entry = ttk.Entry(pwd_frame, textvariable=self.password_var, show="*")
        self.pwd_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        self.show_pwd_btn = ttk.Button(
            pwd_frame, text="👁", width=3, style="Secondary.TButton", command=self._toggle_show_pwd
        )
        self.show_pwd_btn.grid(row=0, column=1)

        # Action Button
        self.encode_btn = ttk.Button(
            right_card,
            text="🔒 Encrypt & Hide in Image",
            style="Primary.TButton",
            command=self._start_encode_process,
        )
        self.encode_btn.grid(row=6, column=0, sticky="ew")

    def _toggle_show_pwd(self):
        if self.show_password.get():
            self.pwd_entry.configure(show="*")
            self.show_password.set(False)
        else:
            self.pwd_entry.configure(show="")
            self.show_password.set(True)

    def _on_mode_change(self):
        if self.secret_mode.get() == "text":
            self.file_frame.grid_forget()
            self.text_input.grid(row=0, column=0, sticky="nsew")
        else:
            self.text_input.grid_forget()
            self.file_frame.grid(row=0, column=0, sticky="nsew")
        self._update_payload_metrics()

    def _browse_cover(self):
        path = filedialog.askopenfilename(
            title="Select Cover Image",
            filetypes=[("Lossless Images", "*.png;*.bmp"), ("PNG Image", "*.png"), ("BMP Image", "*.bmp")],
        )
        if path:
            self.cover_path.set(path)
            self._load_cover_preview(path)

    def _browse_secret_file(self):
        path = filedialog.askopenfilename(title="Select Confidential File to Hide")
        if path:
            self.secret_file_path.set(path)
            size = os.path.getsize(path)
            self.file_label.configure(
                text=f"Selected: {Path(path).name} ({format_bytes(size)})",
                foreground=ACCENT_PRIMARY,
            )
            self._update_payload_metrics()

    def _load_cover_preview(self, path: str):
        try:
            arr, (w, h) = load_image(path)
            self.cover_dimensions = (w, h)
            self.cover_capacity = calculate_max_payload_size(w, h, channels=3)

            self.info_label.configure(
                text=f"Image: {Path(path).name}\nDimensions: {w} x {h} px\nMax Storage: {format_bytes(self.cover_capacity)}",
                foreground=TEXT_PRIMARY,
            )

            # Render scaled thumbnail
            pil_img = Image.fromarray(arr)
            pil_img.thumbnail((320, 200), Image.Resampling.LANCZOS)
            self.preview_image_ref = ImageTk.PhotoImage(pil_img)

            self.preview_canvas.delete("all")
            canvas_w = self.preview_canvas.winfo_width() or 320
            canvas_h = self.preview_canvas.winfo_height() or 200
            self.preview_canvas.create_image(
                canvas_w // 2, canvas_h // 2, image=self.preview_image_ref, anchor="center"
            )

            self._update_payload_metrics()
        except Exception as e:
            messagebox.showerror("Image Load Error", str(e))

    def _update_payload_metrics(self):
        if self.cover_capacity == 0:
            self.cap_bar["value"] = 0
            self.cap_text.configure(text="Storage: 0 B / 0 B (0%)")
            return

        if self.secret_mode.get() == "text":
            text = self.text_input.get("1.0", tk.END).strip()
            payload_bytes = len(text.encode("utf-8"))
        else:
            file_p = self.secret_file_path.get()
            payload_bytes = os.path.getsize(file_p) if (file_p and os.path.isfile(file_p)) else 0

        pct = (payload_bytes / self.cover_capacity) * 100 if self.cover_capacity > 0 else 0
        self.cap_bar["value"] = min(100, pct)

        if payload_bytes > self.cover_capacity:
            self.cap_text.configure(
                text=f"Storage Exceeded: {format_bytes(payload_bytes)} / {format_bytes(self.cover_capacity)} ({pct:.1f}%)",
                foreground=ACCENT_DANGER,
            )
        else:
            self.cap_text.configure(
                text=f"Storage: {format_bytes(payload_bytes)} / {format_bytes(self.cover_capacity)} ({pct:.1f}%)",
                foreground=TEXT_MUTED,
            )

    def _start_encode_process(self):
        cover = self.cover_path.get().strip()
        pwd = self.password_var.get().strip()

        if not cover or not os.path.isfile(cover):
            messagebox.showwarning("Missing Cover Image", "Please select a valid cover image.")
            return

        if not pwd:
            messagebox.showwarning("Missing Password", "Please enter an encryption password.")
            return

        secret_text = None
        secret_file = None

        if self.secret_mode.get() == "text":
            secret_text = self.text_input.get("1.0", tk.END).strip()
            if not secret_text:
                messagebox.showwarning("Empty Secret", "Please enter a message to hide.")
                return
        else:
            secret_file = self.secret_file_path.get().strip()
            if not secret_file or not os.path.isfile(secret_file):
                messagebox.showwarning("Missing Secret File", "Please select a valid secret file to hide.")
                return

        out_path = filedialog.asksaveasfilename(
            title="Save Stego Image As",
            defaultextension=".png",
            filetypes=[("PNG Image", "*.png"), ("BMP Image", "*.bmp")],
            initialfile=f"{Path(cover).stem}_stego.png",
        )
        if not out_path:
            return

        self.encode_btn.configure(state="disabled", text="Encrypting & Embedding...")
        if self.status_callback:
            self.status_callback("Encrypting payload and embedding into pixels...")

        def task():
            return encrypt_and_hide(
                cover_image_path=cover,
                password=pwd,
                secret_text=secret_text,
                secret_file_path=secret_file,
                output_image_path=out_path,
            )

        def on_success(res):
            self.encode_btn.configure(state="normal", text="🔒 Encrypt & Hide in Image")
            if self.status_callback:
                self.status_callback(f"Success! Stego image saved to: {res.output_path}")
            messagebox.showinfo(
                "Stego Image Created!",
                f"Successfully encrypted and embedded payload!\n\n"
                f"Output File: {res.output_path}\n"
                f"Payload Size: {format_bytes(res.payload_bytes)}\n"
                f"Capacity Used: {res.capacity_used_pct}%",
            )

        def on_error(err):
            self.encode_btn.configure(state="normal", text="🔒 Encrypt & Hide in Image")
            if self.status_callback:
                self.status_callback(f"Error: {str(err)}")
            messagebox.showerror("Embedding Failed", str(err))

        run_async(self, task, on_success, on_error)
