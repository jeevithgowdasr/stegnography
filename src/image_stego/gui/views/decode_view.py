"""Tab 2: Extract & Decrypt View for the desktop application."""

import os
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk

from ...core.pipeline import extract_and_decrypt
from ...core.models import PayloadType
from ...stego.capacity import format_bytes
from ...utils.image_io import load_image
from ..styles import (
    BG_CARD, BG_INPUT, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    ACCENT_PRIMARY, ACCENT_SUCCESS, ACCENT_DANGER, FONT_BODY, FONT_HEADING, FONT_SMALL
)
from ..workers import run_async


class DecodeView(ttk.Frame):
    """View component for extracting and decrypting hidden steganographic data."""

    def __init__(self, parent, status_callback=None):
        super().__init__(parent, style="TFrame")
        self.status_callback = status_callback

        self.stego_path = tk.StringVar()
        self.password_var = tk.StringVar()
        self.show_password = tk.BooleanVar(value=False)
        self.preview_image_ref = None
        self.latest_result = None

        self._build_ui()

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        # Left Column: Stego Image Selection & Password
        left_card = ttk.Frame(self, style="Card.TFrame", padding=15)
        left_card.grid(row=0, column=0, sticky="nsew", padx=(10, 5), pady=10)
        left_card.columnconfigure(0, weight=1)

        ttk.Label(left_card, text="1. Select Stego Image (PNG / BMP)", style="SubHeader.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 10)
        )

        browse_frame = ttk.Frame(left_card, style="Card.TFrame")
        browse_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        browse_frame.columnconfigure(0, weight=1)

        self.path_entry = ttk.Entry(browse_frame, textvariable=self.stego_path)
        self.path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ttk.Button(browse_frame, text="Browse...", style="Secondary.TButton", command=self._browse_stego).grid(
            row=0, column=1
        )

        # Preview Canvas
        self.preview_canvas = tk.Canvas(
            left_card, bg=BG_INPUT, highlightthickness=1, highlightbackground="#313244", height=220
        )
        self.preview_canvas.grid(row=2, column=0, sticky="nsew", pady=(0, 10))

        # Password Section
        ttk.Label(left_card, text="2. Decryption Passphrase", style="SubHeader.TLabel").grid(
            row=3, column=0, sticky="w", pady=(10, 5)
        )

        pwd_frame = ttk.Frame(left_card, style="Card.TFrame")
        pwd_frame.grid(row=4, column=0, sticky="ew", pady=(0, 15))
        pwd_frame.columnconfigure(0, weight=1)

        self.pwd_entry = ttk.Entry(pwd_frame, textvariable=self.password_var, show="*")
        self.pwd_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        self.show_pwd_btn = ttk.Button(
            pwd_frame, text="👁", width=3, style="Secondary.TButton", command=self._toggle_show_pwd
        )
        self.show_pwd_btn.grid(row=0, column=1)

        # Extract Button
        self.decode_btn = ttk.Button(
            left_card,
            text="🔓 Extract & Decrypt Secret",
            style="Primary.TButton",
            command=self._start_decode_process,
        )
        self.decode_btn.grid(row=5, column=0, sticky="ew", pady=(5, 0))

        # Right Column: Decrypted Output & Verification
        right_card = ttk.Frame(self, style="Card.TFrame", padding=15)
        right_card.grid(row=0, column=1, sticky="nsew", padx=(5, 10), pady=10)
        right_card.columnconfigure(0, weight=1)
        right_card.rowconfigure(2, weight=1)

        ttk.Label(right_card, text="Decrypted Secret Output", style="SubHeader.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 5)
        )

        # Integrity Status Badge
        self.status_badge = ttk.Label(
            right_card,
            text="Awaiting stego image and password.",
            style="Muted.TLabel",
            wraplength=320,
        )
        self.status_badge.grid(row=1, column=0, sticky="w", pady=(0, 10))

        # Text Output Box
        self.output_text = tk.Text(
            right_card,
            bg=BG_INPUT,
            fg=TEXT_PRIMARY,
            insertbackground=TEXT_PRIMARY,
            relief="flat",
            font=FONT_BODY,
            wrap="word",
        )
        self.output_text.grid(row=2, column=0, sticky="nsew", pady=(0, 10))

        # Action Buttons for Output
        out_action_frame = ttk.Frame(right_card, style="Card.TFrame")
        out_action_frame.grid(row=3, column=0, sticky="ew")
        out_action_frame.columnconfigure(0, weight=1)
        out_action_frame.columnconfigure(1, weight=1)

        self.copy_btn = ttk.Button(
            out_action_frame,
            text="📋 Copy Text",
            style="Secondary.TButton",
            state="disabled",
            command=self._copy_to_clipboard,
        )
        self.copy_btn.grid(row=0, column=0, sticky="ew", padx=(0, 5))

        self.save_file_btn = ttk.Button(
            out_action_frame,
            text="💾 Save Extracted File",
            style="Success.TButton",
            state="disabled",
            command=self._save_extracted_file,
        )
        self.save_file_btn.grid(row=0, column=1, sticky="ew", padx=(5, 0))

    def _toggle_show_pwd(self):
        if self.show_password.get():
            self.pwd_entry.configure(show="*")
            self.show_password.set(False)
        else:
            self.pwd_entry.configure(show="")
            self.show_password.set(True)

    def _browse_stego(self):
        path = filedialog.askopenfilename(
            title="Select Stego Image",
            filetypes=[("Lossless Images", "*.png;*.bmp"), ("PNG Image", "*.png"), ("BMP Image", "*.bmp")],
        )
        if path:
            self.stego_path.set(path)
            self._load_preview(path)

    def _load_preview(self, path: str):
        try:
            arr, (w, h) = load_image(path)
            pil_img = Image.fromarray(arr)
            pil_img.thumbnail((320, 200), Image.Resampling.LANCZOS)
            self.preview_image_ref = ImageTk.PhotoImage(pil_img)

            self.preview_canvas.delete("all")
            canvas_w = self.preview_canvas.winfo_width() or 320
            canvas_h = self.preview_canvas.winfo_height() or 200
            self.preview_canvas.create_image(
                canvas_w // 2, canvas_h // 2, image=self.preview_image_ref, anchor="center"
            )
        except Exception as e:
            messagebox.showerror("Image Load Error", str(e))

    def _start_decode_process(self):
        stego = self.stego_path.get().strip()
        pwd = self.password_var.get().strip()

        if not stego or not os.path.isfile(stego):
            messagebox.showwarning("Missing Stego Image", "Please select a valid stego image.")
            return
        if not pwd:
            messagebox.showwarning("Missing Password", "Please enter the decryption password.")
            return

        self.decode_btn.configure(state="disabled", text="Extracting & Decrypting...")
        self.status_badge.configure(text="Extracting bits and verifying AES-GCM tag...", style="Muted.TLabel")

        def task():
            return extract_and_decrypt(stego_image_path=stego, password=pwd)

        def on_success(res):
            self.decode_btn.configure(state="normal", text="🔓 Extract & Decrypt Secret")
            self.latest_result = res
            self.output_text.delete("1.0", tk.END)

            if res.payload_type == PayloadType.TEXT:
                self.status_badge.configure(
                    text="✓ AES-256-GCM Integrity Verified! Secret message decrypted successfully.",
                    style="Success.TLabel",
                )
                self.output_text.insert("1.0", res.text_content or "")
                self.copy_btn.configure(state="normal")
                self.save_file_btn.configure(state="disabled")
            else:
                file_size = len(res.binary_content or b"")
                self.status_badge.configure(
                    text=f"✓ AES-256-GCM Integrity Verified! Secret file '{res.filename}' ({format_bytes(file_size)}) ready to save.",
                    style="Success.TLabel",
                )
                self.output_text.insert(
                    "1.0",
                    f"[Confidential Embedded File]\n\n"
                    f"Filename: {res.filename}\n"
                    f"File Size: {format_bytes(file_size)}\n"
                    f"Click 'Save Extracted File' below to write this file to your computer.",
                )
                self.copy_btn.configure(state="disabled")
                self.save_file_btn.configure(state="normal")

            if self.status_callback:
                self.status_callback("Decryption successful and authenticated.")

        def on_error(err):
            self.decode_btn.configure(state="normal", text="🔓 Extract & Decrypt Secret")
            self.status_badge.configure(text=f"✗ Authentication Failed: {str(err)}", style="Error.TLabel")
            self.output_text.delete("1.0", tk.END)
            self.copy_btn.configure(state="disabled")
            self.save_file_btn.configure(state="disabled")
            if self.status_callback:
                self.status_callback(f"Decryption failed: {str(err)}")
            messagebox.showerror("Decryption Failed", str(err))

        run_async(self, task, on_success, on_error)

    def _copy_to_clipboard(self):
        text = self.output_text.get("1.0", tk.END).strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            messagebox.showinfo("Copied", "Secret message copied to clipboard.")

    def _save_extracted_file(self):
        if not self.latest_result or not self.latest_result.binary_content:
            return

        default_name = self.latest_result.filename or "extracted_secret.bin"
        save_path = filedialog.asksaveasfilename(
            title="Save Extracted Secret File",
            initialfile=default_name,
        )
        if save_path:
            try:
                Path(save_path).write_bytes(self.latest_result.binary_content)
                messagebox.showinfo("File Saved", f"Successfully saved secret file to:\n{save_path}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save file: {e}")
