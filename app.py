"""
app.py
======

Streamlit front-end for the Secure Image Steganography Tool.

Run locally::

    streamlit run app.py

Author: Rubaisha Ahmed & Ibrahim Sial
Course: Information Security – Final Year Project
"""

from __future__ import annotations

import streamlit as st

from encryption import (
    InvalidPasswordError,
    decrypt_message,
    encrypt_message,
    password_strength,
)
from steganography import (
    MessageTooLargeError,
    NoHiddenMessageError,
    UnsupportedImageFormatError,
    calculate_capacity,
    decode_image,
    encode_to_png_bytes,
    load_image_from_bytes,
    utilization_percentage,
)
from utils import (
    ACCEPTED_UPLOAD_TYPES,
    human_readable_bytes,
    image_info,
    safe_filename,
)

# ---------------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Secure Image Steganography Tool",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Lightweight CSS to give the app a slightly more polished feel without
# departing too far from Streamlit defaults (dark-mode safe).
st.markdown(
    """
    <style>
    .stApp h1, .stApp h2, .stApp h3 { letter-spacing: -0.01em; }
    .metric-card {
        padding: 0.75rem 1rem;
        border-radius: 0.5rem;
        background-color: rgba(127,127,127,0.08);
        border: 1px solid rgba(127,127,127,0.18);
        margin-bottom: 0.5rem;
    }
    .small-muted { color: rgba(127,127,127,0.9); font-size: 0.85rem; }
    .stTabs [data-baseweb="tab-list"] { gap: 0.25rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.title("🛡️ Stego Tool")
    st.caption("Secure Image Steganography with Optional Encryption")
    st.markdown("---")
    st.markdown(
        """
        **Course:** Information Security 
        
        **Project Type:** Final Course Project 
        
        **Author:** _Rubaisha Ahmed & Ibrahim Sial_ 
        
        **Student ID:** _20221-33350 & 20211-30954_
        
        **Instructor:** _Salman Akber_ 
        
        **Institution:** _Institute of Business Management_ 
        
        """
    )
    st.markdown("---")
    st.markdown("### How it works")
    st.markdown(
        "This tool hides text inside the **least significant bits** of an "
        "image's pixels. Optionally, the text is **encrypted** with a "
        "password-derived key (PBKDF2 + Fernet) **before** being embedded, "
        "giving you both *confidentiality* and *unobservability*."
    )
    st.markdown("---")
    st.caption("Use only lossless images (PNG / BMP) as carriers.")


# ---------------------------------------------------------------------------
# Internal helpers (defined before use because Streamlit runs top-to-bottom)
# ---------------------------------------------------------------------------

def _looks_like_encrypted(text: str) -> bool:
    """Cheap heuristic: encrypted payloads are url-safe base64 of >= 60 chars."""
    import string

    if len(text) < 60:
        return False
    allowed = set(string.ascii_letters + string.digits + "-_=")
    return all(c in allowed for c in text)


# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------

tab_encode, tab_decode, tab_capacity, tab_security, tab_about = st.tabs(
    ["➤ ENCODE", "  ➤ DECODE    ", "➤ CAPACITY CALCULATOR    ", "➤ SECURITY ANALYSIS    ", "➤ ABOUT    "]
)


# ===========================================================================
# Tab 1 — Encode
# ===========================================================================

with tab_encode:
    st.header("Hide a secret message inside an image")
    st.markdown(
        "Upload a **PNG or BMP** carrier image and the tool will embed your "
        "message into its least-significant pixel bits. Supply a password to "
        "additionally encrypt the message with AES (via Fernet)."
    )

    col_in, col_preview = st.columns([1, 1])

    with col_in:
        carrier_file = st.file_uploader(
            "Carrier image (PNG or BMP)",
            type=ACCEPTED_UPLOAD_TYPES,
            key="encode_uploader",
            help="JPEG is intentionally rejected because lossy compression "
            "destroys the hidden bits.",
        )
        message = st.text_area(
            "Secret message",
            height=160,
            placeholder="Type or paste the text you want to hide…",
        )
        password = st.text_input(
            "Password (optional)",
            type="password",
            help="If provided, the message is encrypted with a key derived "
            "from this password before being embedded.",
        )

        if password:
            score, label = password_strength(password)
            st.progress(score / 5)
            st.caption(f"Password strength: **{label}** ({score}/5)")

        encode_clicked = st.button("🔒 Embed message", type="primary", use_container_width=True)

    with col_preview:
        if carrier_file is not None:
            try:
                preview_img = load_image_from_bytes(carrier_file.getvalue())
                st.image(preview_img, caption="Carrier preview", use_container_width=True)
                info = image_info(preview_img)
                cap = calculate_capacity(info["width"], info["height"])
                st.markdown(
                    f"<div class='metric-card'>"
                    f"<b>Dimensions:</b> {info['width']} × {info['height']} px ({info['format']})<br>"
                    f"<b>File size:</b> {human_readable_bytes(len(carrier_file.getvalue()))}<br>"
                    f"<b>Max characters:</b> {cap['max_chars']:,}"
                    f"</div>",
                    unsafe_allow_html=True,
                )
            except Exception as exc:  # pragma: no cover - defensive UI guard
                st.error(f"Could not open image: {exc}")
        else:
            st.info("Upload a carrier image to see a preview here.")

    if encode_clicked:
        if carrier_file is None:
            st.error("Please upload a carrier image first.")
        elif not message.strip():
            st.error("Please enter a non-empty message.")
        else:
            try:
                with st.status("Embedding message…", expanded=False) as status:
                    img = load_image_from_bytes(carrier_file.getvalue())

                    if password:
                        status.update(label="Encrypting message with PBKDF2 + Fernet…")
                        payload = encrypt_message(message, password)
                    else:
                        payload = message

                    status.update(label="Writing LSB bits…")
                    png_bytes = encode_to_png_bytes(img, payload)
                    status.update(label="Done ✅", state="complete")

                msg_len = len(payload)
                used_pct = utilization_percentage(msg_len, img.width, img.height)

                st.success("Message embedded successfully.")

                metric_cols = st.columns(4)
                metric_cols[0].metric("Message bytes", f"{msg_len:,}")
                metric_cols[1].metric("Capacity used", f"{used_pct:.2f}%")
                metric_cols[2].metric("Image size", f"{img.width}×{img.height}")
                metric_cols[3].metric("Output", "PNG (lossless)")

                st.progress(min(used_pct / 100.0, 1.0))

                st.download_button(
                    label="⬇️ Download stego image",
                    data=png_bytes,
                    file_name=safe_filename("stego_image", "png"),
                    mime="image/png",
                    use_container_width=True,
                )

                if password:
                    st.info(
                        "The message was encrypted *before* embedding. The "
                        "recipient must use the **same password** to decode it."
                    )

            except MessageTooLargeError as exc:
                st.error(f"❌ {exc}")
            except UnsupportedImageFormatError as exc:
                st.error(f"❌ {exc}")
            except Exception as exc:  # pragma: no cover - defensive UI guard
                st.error(f"Unexpected error: {exc}")


# ===========================================================================
# Tab 2 — Decode
# ===========================================================================

with tab_decode:
    st.header("Extract a hidden message")
    st.markdown(
        "Upload a stego-image produced by this tool. If a password was used "
        "during embedding, supply the same password here."
    )

    col_d_in, col_d_preview = st.columns([1, 1])

    with col_d_in:
        stego_file = st.file_uploader(
            "Stego image (PNG or BMP)",
            type=ACCEPTED_UPLOAD_TYPES,
            key="decode_uploader",
        )
        password_dec = st.text_input(
            "Password (if used during embedding)",
            type="password",
            key="decode_password",
        )
        decode_clicked = st.button("Reveal message", type="primary", use_container_width=True)

    with col_d_preview:
        if stego_file is not None:
            try:
                stego_preview = load_image_from_bytes(stego_file.getvalue())
                st.image(stego_preview, caption="Stego preview", use_container_width=True)
            except Exception as exc:  # pragma: no cover - defensive UI guard
                st.error(f"Could not open image: {exc}")
        else:
            st.info("Upload a stego image to begin.")

    if decode_clicked:
        if stego_file is None:
            st.error("Please upload a stego image first.")
        else:
            try:
                with st.status("Extracting hidden bitstream…", expanded=False) as status:
                    img = load_image_from_bytes(stego_file.getvalue())
                    extracted = decode_image(img)
                    status.update(label="Bits extracted ✅", state="running")

                    if password_dec:
                        status.update(label="Decrypting with provided password…")
                        plaintext = decrypt_message(extracted, password_dec)
                    else:
                        # Heuristic: if it looks like our base64 envelope and
                        # the user did not supply a password, warn them.
                        if _looks_like_encrypted(extracted):
                            st.warning(
                                "The hidden payload appears to be encrypted but "
                                "no password was supplied. Showing the raw "
                                "ciphertext below — provide the password to decrypt."
                            )
                        plaintext = extracted

                    status.update(label="Done ✅", state="complete")

                st.success("Message recovered.")
                st.text_area("Recovered message", value=plaintext, height=200)

            except NoHiddenMessageError as exc:
                st.error(f"❌ {exc}")
            except InvalidPasswordError as exc:
                st.error(f"❌ {exc}")
            except UnsupportedImageFormatError as exc:
                st.error(f"❌ {exc}")
            except ValueError as exc:
                st.error(f"❌ Invalid payload: {exc}")
            except Exception as exc:  # pragma: no cover - defensive UI guard
                st.error(f"Unexpected error: {exc}")


# ===========================================================================
# Tab 3 — Capacity Calculator
# ===========================================================================

with tab_capacity:
    st.header("Image capacity calculator")
    st.markdown(
        "Estimate how much text you can hide in an RGB image of a given size. "
        "Each pixel contributes **3 bits** of capacity (one LSB per channel)."
    )

    col_w, col_h = st.columns(2)
    width = col_w.number_input("Width (px)", min_value=1, value=800, step=1)
    height = col_h.number_input("Height (px)", min_value=1, value=600, step=1)
    expected_chars = st.number_input(
        "Planned message length (characters)", min_value=0, value=0, step=1
    )

    cap = calculate_capacity(int(width), int(height))
    util = utilization_percentage(int(expected_chars), int(width), int(height))

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total bits", f"{cap['total_bits']:,}")
    m2.metric("Total bytes", f"{cap['total_bytes']:,}")
    m3.metric("Max characters", f"{cap['max_chars']:,}")
    m4.metric("Utilization", f"{util:.2f}%")

    st.progress(min(util / 100.0, 1.0))

    st.caption(
        f"Marker overhead: **{cap['marker_overhead_chars']}** characters reserved "
        "for the end-of-message sentinel `<<<END>>>`."
    )


# ===========================================================================
# Tab 4 — Security Analysis
# ===========================================================================

with tab_security:
    st.header("Security analysis")

    st.subheader("1. What is LSB steganography?")
    st.markdown(
        "Least-Significant-Bit (LSB) steganography hides data inside the "
        "lowest-order bit of each colour channel. Because the human eye is "
        "insensitive to single-bit variations in colour intensity, the "
        "modified *stego image* is visually indistinguishable from the "
        "original *cover image*."
    )

    st.subheader("2. Steganography vs. Encryption")
    st.markdown(
        "- **Encryption** protects the *content* of a message — an attacker "
        "knows a secret message exists but cannot read it.\n"
        "- **Steganography** protects the *existence* of a message — the "
        "attacker is unaware that a message exists at all.\n"
        "- Combining both gives **defence in depth**: even if an analyst "
        "detects the steganographic channel, the recovered bytes remain "
        "ciphertext."
    )

    st.subheader("3. Confidentiality in the CIA triad")
    st.markdown(
        "*Confidentiality* — one of the three pillars of information security "
        "alongside *Integrity* and *Availability* — ensures information is "
        "accessible only to authorised parties. This tool addresses "
        "confidentiality through two complementary mechanisms: covert "
        "transmission (steganography) and password-derived symmetric "
        "encryption (Fernet, which is AES-128-CBC with HMAC-SHA256 for "
        "integrity)."
    )

    st.subheader("4. Limitations & attack vectors")
    st.markdown(
        "- **Statistical steganalysis** (e.g. chi-square, RS analysis, sample "
        "pair analysis) can detect LSB embedding because it perturbs the "
        "distribution of pixel values.\n"
        "- **Format conversion** to JPEG or any other lossy codec destroys "
        "the payload.\n"
        "- **Re-saving / resizing / cropping** the image by an intermediary "
        "almost always destroys the payload.\n"
        "- **Brute force on weak passwords** — although PBKDF2 with 480 000 "
        "iterations adds significant cost, very weak passphrases remain "
        "vulnerable.\n"
        "- **Visual inspection of small images** with very large payloads "
        "can occasionally reveal subtle artefacts (e.g. faint noise patterns)."
    )

    st.subheader("5. Best practices")
    st.markdown(
        "- Use carrier images with **rich natural noise** (photographs) "
        "rather than flat synthetic graphics or screenshots.\n"
        "- Never reuse the same carrier image for multiple secrets — "
        "differential analysis trivially recovers them.\n"
        "- Always combine steganography with **strong encryption** and a "
        "high-entropy passphrase.\n"
        "- Distribute stego images only through channels that preserve "
        "lossless data (file transfer, encrypted email attachments). Avoid "
        "social media platforms that recompress uploads.\n"
        "- Treat steganography as a *complement* to — never a substitute "
        "for — cryptographically sound communication."
    )


# ===========================================================================
# Tab 5 — About
# ===========================================================================

with tab_about:
    st.header("About this project")
    st.markdown(
        """
        **Secure Image Steganography Tool with Optional Encryption** is a
        final-year Information Security project that demonstrates two
        complementary techniques for protecting message confidentiality:

        1. **LSB Steganography** — hiding data within the least-significant
           bits of image pixels so that the existence of the message itself
           is concealed.
        2. **Password-based symmetric encryption** — using PBKDF2-HMAC-SHA256
           to derive a key from a user passphrase, then encrypting the message
           with Fernet (AES-128-CBC + HMAC-SHA256) before embedding.

        ### Tech stack
        - Python 3.11+
        - Streamlit (UI)
        - Pillow & NumPy (image processing)
        - `cryptography` (Fernet & PBKDF2)
        - pytest (unit tests)
        - Docker & GitHub Actions (deployment & CI)

        ### Repository layout
        ```
        secure-steganography-tool/
        ├── app.py                # Streamlit UI
        ├── steganography.py      # LSB encode / decode
        ├── encryption.py         # PBKDF2 + Fernet
        ├── utils.py              # Helpers
        ├── tests/                # pytest suite
        ├── docs/                 # Academic report & slides outline
        ├── assets/demo_images/   # Sample carrier images
        ├── Dockerfile
        ├── docker-compose.yml
        └── .github/workflows/    # CI pipeline
        ```

        ### Author
        - **Name:** _Rubaisha Ahmed & Ibrahim Sial_
        - **Roll number:** _20221-33350 & 20211-30954_
        - **Instructor:** _Salman Akber_
        - **Institution:** _Institute of Business Management_

        ### License
        Released under the MIT License. See ``LICENSE`` for full text.
        """
    )

    st.markdown("---")
    st.caption(
        "This tool is intended for educational use only. It is not a "
        "substitute for professionally audited secure communications software."
    )
