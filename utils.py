"""
utils.py
========

Miscellaneous helpers shared by the Streamlit UI and the core modules.

Author: <Your Name>
Course: Information Security – Final Year Project
"""

from __future__ import annotations

import io
from typing import Final

from PIL import Image

#: File extensions accepted as lossless carriers in the UI uploader.
ACCEPTED_UPLOAD_TYPES: Final[list[str]] = ["png", "bmp"]


def human_readable_bytes(num_bytes: int) -> str:
    """Return a human-friendly representation of a byte count.

    Examples
    --------
    >>> human_readable_bytes(0)
    '0 B'
    >>> human_readable_bytes(2048)
    '2.0 KB'
    """
    if num_bytes < 0:
        raise ValueError("Byte count cannot be negative.")
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(num_bytes)
    unit_index = 0
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    return f"{size:.1f} {units[unit_index]}"


def pil_image_to_bytes(image: Image.Image, fmt: str = "PNG") -> bytes:
    """Serialise a PIL image to bytes in the given lossless format."""
    fmt = fmt.upper()
    if fmt not in {"PNG", "BMP"}:
        raise ValueError(f"Unsupported output format: {fmt}")
    buffer = io.BytesIO()
    image.save(buffer, format=fmt)
    return buffer.getvalue()


def image_info(image: Image.Image) -> dict[str, int | str]:
    """Return a small dictionary summarising key image attributes."""
    return {
        "width": image.width,
        "height": image.height,
        "mode": image.mode,
        "format": image.format or "UNKNOWN",
    }


def safe_filename(stem: str, extension: str = "png") -> str:
    """Produce a filesystem-safe filename from a user-supplied stem."""
    cleaned = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in stem)
    cleaned = cleaned.strip("_") or "stego_image"
    return f"{cleaned}.{extension.lstrip('.')}"
