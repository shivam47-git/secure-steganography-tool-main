"""Unit tests for the LSB steganography engine."""

from __future__ import annotations

import io

import numpy as np
import pytest
from PIL import Image

from steganography import (
    END_MARKER,
    MessageTooLargeError,
    NoHiddenMessageError,
    UnsupportedImageFormatError,
    calculate_capacity,
    decode_image,
    encode_image,
    encode_to_png_bytes,
    load_image_from_bytes,
    utilization_percentage,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def small_image() -> Image.Image:
    """A 64×64 RGB image with deterministic but varied pixel data."""
    rng = np.random.default_rng(seed=42)
    arr = rng.integers(0, 256, size=(64, 64, 3), dtype=np.uint8)
    return Image.fromarray(arr, mode="RGB")


@pytest.fixture
def tiny_image() -> Image.Image:
    """A 4×4 RGB image — capacity is intentionally tiny."""
    arr = np.zeros((4, 4, 3), dtype=np.uint8)
    return Image.fromarray(arr, mode="RGB")


# ---------------------------------------------------------------------------
# Encode / decode round-trip
# ---------------------------------------------------------------------------

def test_encode_decode_roundtrip(small_image):
    """A message embedded then extracted must come back identical."""
    message = "Hello, steganography world!"
    stego = encode_image(small_image, message)
    recovered = decode_image(stego)
    assert recovered == message


def test_encode_preserves_dimensions(small_image):
    stego = encode_image(small_image, "x")
    assert stego.size == small_image.size
    assert stego.mode == "RGB"


def test_encode_modifies_only_lsb(small_image):
    """The stego image must differ from the original only in the LSB."""
    message = "Test"
    stego = encode_image(small_image, message)
    orig = np.array(small_image.convert("RGB"))
    new = np.array(stego)
    # Upper 7 bits should be identical everywhere.
    assert np.all((orig & 0b1111_1110) == (new & 0b1111_1110))


def test_roundtrip_via_png_bytes(small_image):
    """The PNG download path must also survive a save/load cycle."""
    message = "Persisted through PNG."
    png_bytes = encode_to_png_bytes(small_image, message)
    reloaded = load_image_from_bytes(png_bytes)
    assert decode_image(reloaded) == message


def test_unicode_message(small_image):
    """UTF-8 messages — including emoji — must round-trip cleanly."""
    message = "السلام عليكم — مرحبا 🛡️🔐"
    stego = encode_image(small_image, message)
    assert decode_image(stego) == message


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------

def test_message_too_large(tiny_image):
    """A 4×4 image has 48 bits of capacity — far too small for this message."""
    with pytest.raises(MessageTooLargeError):
        encode_image(tiny_image, "This message will definitely not fit.")


def test_empty_message_rejected(small_image):
    with pytest.raises(ValueError):
        encode_image(small_image, "")


def test_no_hidden_message_in_unmodified_image():
    """An image that was never encoded should raise NoHiddenMessageError."""
    # Pure black image — its LSBs are all zero, so the decoder will read a
    # very long run of NULs and never find the sentinel.
    plain = Image.fromarray(np.zeros((32, 32, 3), dtype=np.uint8), mode="RGB")
    with pytest.raises(NoHiddenMessageError):
        decode_image(plain)


def test_jpeg_rejected_for_encoding(small_image):
    """Loading the image back as JPEG must be rejected as a carrier."""
    buf = io.BytesIO()
    small_image.save(buf, format="JPEG", quality=80)
    buf.seek(0)
    jpeg_img = Image.open(buf)
    jpeg_img.load()
    assert jpeg_img.format == "JPEG"
    with pytest.raises(UnsupportedImageFormatError):
        encode_image(jpeg_img, "hi")


def test_decode_returns_only_message_not_sentinel(small_image):
    """The sentinel itself must be stripped from the decoded output."""
    message = "the secret"
    stego = encode_image(small_image, message)
    out = decode_image(stego)
    assert END_MARKER not in out
    assert out == message


# ---------------------------------------------------------------------------
# Capacity helpers
# ---------------------------------------------------------------------------

def test_capacity_basic():
    cap = calculate_capacity(100, 100)
    # 100*100*3 = 30 000 bits = 3 750 bytes
    assert cap["total_bits"] == 30_000
    assert cap["total_bytes"] == 3_750
    assert cap["max_chars"] == 3_750 - len(END_MARKER)


def test_capacity_rejects_non_positive():
    with pytest.raises(ValueError):
        calculate_capacity(0, 10)
    with pytest.raises(ValueError):
        calculate_capacity(10, -5)


def test_utilization_percentage_caps_at_100():
    # Asking for a million chars in a tiny image returns 100.0 (capped).
    assert utilization_percentage(1_000_000, 16, 16) == 100.0


def test_utilization_percentage_zero_when_empty():
    assert utilization_percentage(0, 100, 100) == 0.0
