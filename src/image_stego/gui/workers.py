"""Background threading dispatcher for non-blocking Tkinter operations."""

import threading
import tkinter as tk
from typing import Callable, Any


def run_async(
    widget: tk.Widget,
    target_func: Callable[..., Any],
    on_success: Callable[[Any], None],
    on_error: Callable[[Exception], None],
    *args: Any,
    **kwargs: Any,
):
    """
    Execute a target function in a background daemon thread,
    marshaling the result or error back to Tkinter's main event loop.
    
    Args:
        widget: Any Tkinter widget used to invoke widget.after().
        target_func: The worker function to run in background.
        on_success: Callback called with the return value on success.
        on_error: Callback called with the Exception on failure.
        *args, **kwargs: Arguments forwarded to target_func.
    """
    def worker():
        try:
            result = target_func(*args, **kwargs)
            widget.after(0, lambda: on_success(result))
        except Exception as err:
            widget.after(0, lambda: on_error(err))

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
