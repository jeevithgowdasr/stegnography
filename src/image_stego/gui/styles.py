"""Modern dark theme styling and custom colors for Tkinter / TTK."""

import tkinter as tk
from tkinter import ttk

# Modern Dark Palette
BG_DARK = "#181825"
BG_CARD = "#1e1e2e"
BG_INPUT = "#11111b"
BG_HOVER = "#313244"

ACCENT_PRIMARY = "#89b4fa"      # Soft Sky Blue
ACCENT_SUCCESS = "#a6e3a1"      # Mint Green
ACCENT_WARNING = "#f9e2af"      # Amber
ACCENT_DANGER = "#f38ba8"       # Rose Red
ACCENT_PURPLE = "#cba6f7"       # Lavender

TEXT_PRIMARY = "#cdd6f4"
TEXT_SECONDARY = "#a6adc8"
TEXT_MUTED = "#6c7086"
BORDER_COLOR = "#313244"

FONT_FAMILY = "Segoe UI" if tk.TkVersion >= 8.6 else "Helvetica"
FONT_TITLE = (FONT_FAMILY, 14, "bold")
FONT_HEADING = (FONT_FAMILY, 11, "bold")
FONT_BODY = (FONT_FAMILY, 10)
FONT_BODY_BOLD = (FONT_FAMILY, 10, "bold")
FONT_SMALL = (FONT_FAMILY, 9)
FONT_CODE = ("Consolas", 10)


def apply_theme(root: tk.Tk) -> ttk.Style:
    """Configure modern dark style for the TTK widgets."""
    style = ttk.Style(root)
    
    # Use clam as baseline engine
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    root.configure(bg=BG_DARK)

    # General Frames
    style.configure("TFrame", background=BG_DARK)
    style.configure("Card.TFrame", background=BG_CARD, relief="flat")

    # Labels
    style.configure("TLabel", background=BG_DARK, foreground=TEXT_PRIMARY, font=FONT_BODY)
    style.configure("Card.TLabel", background=BG_CARD, foreground=TEXT_PRIMARY, font=FONT_BODY)
    style.configure("Header.TLabel", background=BG_DARK, foreground=ACCENT_PRIMARY, font=FONT_TITLE)
    style.configure("SubHeader.TLabel", background=BG_CARD, foreground=ACCENT_PRIMARY, font=FONT_HEADING)
    style.configure("Muted.TLabel", background=BG_CARD, foreground=TEXT_MUTED, font=FONT_SMALL)
    style.configure("Success.TLabel", background=BG_CARD, foreground=ACCENT_SUCCESS, font=FONT_BODY_BOLD)
    style.configure("Error.TLabel", background=BG_CARD, foreground=ACCENT_DANGER, font=FONT_BODY_BOLD)

    # Primary Buttons
    style.configure(
        "Primary.TButton",
        background=ACCENT_PRIMARY,
        foreground="#11111b",
        font=FONT_BODY_BOLD,
        borderwidth=0,
        focuscolor="none",
        padding=(14, 8),
    )
    style.map(
        "Primary.TButton",
        background=[("active", "#74c7ec"), ("disabled", "#45475a")],
        foreground=[("disabled", "#6c7086")],
    )

    # Secondary Buttons
    style.configure(
        "Secondary.TButton",
        background=BG_HOVER,
        foreground=TEXT_PRIMARY,
        font=FONT_BODY,
        borderwidth=1,
        bordercolor=BORDER_COLOR,
        focuscolor="none",
        padding=(10, 6),
    )
    style.map(
        "Secondary.TButton",
        background=[("active", "#45475a"), ("disabled", "#313244")],
        foreground=[("disabled", "#6c7086")],
    )

    # Success Buttons
    style.configure(
        "Success.TButton",
        background=ACCENT_SUCCESS,
        foreground="#11111b",
        font=FONT_BODY_BOLD,
        borderwidth=0,
        focuscolor="none",
        padding=(14, 8),
    )
    style.map(
        "Success.TButton",
        background=[("active", "#94e2d5")],
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
        padding=6,
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
        background=BG_CARD,
        foreground=TEXT_SECONDARY,
        font=FONT_BODY_BOLD,
        padding=[16, 8],
        borderwidth=0,
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", BG_HOVER), ("active", "#313244")],
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

    # Radiobuttons
    style.configure(
        "TRadiobutton",
        background=BG_CARD,
        foreground=TEXT_PRIMARY,
        font=FONT_BODY,
        focuscolor="none",
    )
    style.map(
        "TRadiobutton",
        background=[("active", BG_CARD)],
        foreground=[("active", ACCENT_PRIMARY)],
    )

    return style
