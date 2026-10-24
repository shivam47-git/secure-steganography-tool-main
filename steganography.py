

from __future__ import annotations

import io
from typing import Final

import numpy as np
from PIL import Image


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Sentinel appended to every payload so the decoder knows where to stop.
#: Chosen to be short, ASCII-only, and extremely unlikely to appear by chance.
END_MARKER: Final[str] = "<<<END>>>"

#: Image formats whose pixels survive a save/load round-trip unchanged.
SUPPORTED_FORMATS: Final[tuple[str, ...]] = ("PNG", "BMP")

#: Number of channels used for embedding (R, G, B).
CHANNELS_USED: Final[int] = 3


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class SteganographyError(Exception):
    """Base class for all steganography-related errors."""


class MessageTooLargeError(SteganographyError):
    """Raised when the payload does not fit inside the carrier image."""


class NoHiddenMessageError(SteganographyError):
    """Raised when no end-marker is found in a candidate stego-image."""


class UnsupportedImageFormatError(SteganographyError):
    """Raised when a lossy or otherwise unsupported image format is supplied."""


# ---------------------------------------------------------------------------
# Capacity helpers
# ---------------------------------------------------------------------------

def calculate_capacity(width: int, height: int) -> dict[str, int | float]:

    if width <= 0 or height <= 0:
        raise ValueError("Width and height must be positive integers.")

    total_bits = width * height * CHANNELS_USED
    total_bytes = total_bits // 8
    marker_overhead = len(END_MARKER)
    max_chars = max(total_bytes - marker_overhead, 0)

    return {
        "total_bits": total_bits,
        "total_bytes": total_bytes,
        "max_chars": max_chars,
        "marker_overhead_chars": marker_overhead,
    }


def utilization_percentage(message_chars: int, width: int, height: int) -> float:
    """Return the percentage of available payload bytes used by a message."""
    capacity = calculate_capacity(width, height)
    max_chars = capacity["max_chars"]
    if max_chars == 0:
        return 0.0
    return min(100.0, (message_chars / max_chars) * 100.0)


# ---------------------------------------------------------------------------
# Internal bit helpers
# ---------------------------------------------------------------------------

def _text_to_bits(text: str) -> np.ndarray:
    """Convert a UTF-8 string to a flat ``uint8`` numpy array of bits."""
    raw = text.encode("utf-8")
    # np.unpackbits expects uint8 — produces MSB-first bits, which we keep.
    bits = np.unpackbits(np.frombuffer(raw, dtype=np.uint8))
    return bits


def _bits_to_bytes(bits: np.ndarray) -> bytes:
    """Pack a flat MSB-first bit array (uint8 of 0/1) into a ``bytes`` object."""
    # Trim trailing partial byte if any (defensive).
    usable_len = (len(bits) // 8) * 8
    bits = bits[:usable_len]
    return bytes(np.packbits(bits.astype(np.uint8)))


# ---------------------------------------------------------------------------
# Public API – encoding
# ---------------------------------------------------------------------------

def _validate_carrier(image: Image.Image) -> Image.Image:
    """Validate carrier format and return an RGB-converted copy."""
    fmt = (image.format or "").upper()
    # When loaded from raw bytes the format is set; when constructed in code it
    # may be None. We only reject formats we *know* are lossy.
    if fmt and fmt not in SUPPORTED_FORMATS and fmt in {"JPEG", "JPG", "WEBP"}:
        raise UnsupportedImageFormatError(
            f"Format '{fmt}' is lossy and not supported. "
            f"Use one of: {', '.join(SUPPORTED_FORMATS)}."
        )
    # Always work in RGB so we know channel layout.
    return image.convert("RGB")


def encode_image(image: Image.Image, message: str) -> Image.Image:

    if not message:
        raise ValueError("Message must be a non-empty string.")

    rgb = _validate_carrier(image)
    arr = np.array(rgb, dtype=np.uint8)  # shape: (H, W, 3)

    payload = message + END_MARKER
    bits = _text_to_bits(payload)

    capacity_bits = arr.size  # H * W * 3
    if bits.size > capacity_bits:
        raise MessageTooLargeError(
            f"Payload requires {bits.size} bits but the image only "
            f"provides {capacity_bits} bits of capacity."
        )

    # Flatten for vectorised bit manipulation.
    flat = arr.reshape(-1).copy()
    # Clear the LSB of the slots we'll write to, then OR-in the payload bits.
    flat[: bits.size] = (flat[: bits.size] & 0b1111_1110) | bits

    stego = flat.reshape(arr.shape)
    out = Image.fromarray(stego, mode="RGB")
    return out


def encode_to_png_bytes(image: Image.Image, message: str) -> bytes:
  
    stego = encode_image(image, message)
    buffer = io.BytesIO()
    stego.save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Public API – decoding
# ---------------------------------------------------------------------------

def decode_image(image: Image.Image) -> str:

    rgb = _validate_carrier(image)
    arr = np.array(rgb, dtype=np.uint8).reshape(-1)

    # Extract every LSB and pack into bytes.
    bits = arr & 1
    byte_stream = _bits_to_bytes(bits)

    sentinel = END_MARKER.encode("utf-8")
    marker_index = byte_stream.find(sentinel)
    if marker_index == -1:
        raise NoHiddenMessageError(
            "No hidden message could be located in this image. "
            "Either the image is unmodified or it was not produced by this tool."
        )

    payload_bytes = byte_stream[:marker_index]
    try:
        return payload_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NoHiddenMessageError(
            "Hidden payload was located but could not be decoded as UTF-8. "
            "The image may be corrupted."
        ) from exc


# ---------------------------------------------------------------------------
# Convenience: bytes -> Image
# ---------------------------------------------------------------------------

def load_image_from_bytes(data: bytes) -> Image.Image:
    """Load a PIL image from raw bytes and preserve its format attribute."""
    img = Image.open(io.BytesIO(data))
    img.load()
    return img
