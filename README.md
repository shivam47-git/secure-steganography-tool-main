# 🛡️ Secure Image Steganography Tool with Optional Encryption

[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![CI](https://img.shields.io/badge/tests-pytest-success.svg)](https://github.com/features/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Streamlit](https://img.shields.io/badge/built%20with-Streamlit-FF4B4B.svg)](https://streamlit.io)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](Dockerfile)

A web-based application — submitted as a final-year **Information Security**
project — that demonstrates the practical synthesis of two confidentiality
techniques:

1. **LSB (Least Significant Bit) steganography** to conceal *the existence* of
   a message inside an image.
2. **Password-based symmetric encryption** (PBKDF2-HMAC-SHA256 → Fernet) to
   conceal *the content* of that message — applied **before** embedding.

The result: even if an analyst detects the steganographic channel, the
recovered bytes remain authenticated ciphertext.

---

## Table of contents

- [Features](#features)
- [Project structure](#project-structure)
- [Installation](#installation)
- [Running locally](#running-locally)
- [Running the test suite](#running-the-test-suite)
- [Docker usage](#docker-usage)
- [Continuous integration](#continuous-integration)
- [Cloud deployment](#cloud-deployment)
- [Screenshots](#screenshots)
- [Security concepts demonstrated](#security-concepts-demonstrated)
- [Future improvements](#future-improvements)
- [License](#license)

---

## Features

| Tab | What it does |
| --- | --- |
| 🔒 **Encode** | Upload a PNG/BMP, type a message, optionally supply a password, and download a stego-PNG. |
| 🔓 **Decode** | Upload a stego-image, optionally supply the password, and recover the plaintext. |
| 📏 **Capacity Calculator** | Compute total bits/bytes/characters available in any image dimension. |
| 🔬 **Security Analysis** | In-depth notes on LSB, encryption vs. steganography, the CIA triad, attack vectors and best practices. |
| ℹ️ **About** | Project, author, license, and stack information. |

Additional highlights:

- **Robust sentinel marker** (`<<<END>>>`) to detect end-of-message reliably.
- **Strict carrier validation** — JPEG and other lossy formats are rejected.
- **Custom exception hierarchy**: `MessageTooLargeError`, `NoHiddenMessageError`,
  `InvalidPasswordError`, `UnsupportedImageFormatError`.
- **Password strength indicator** in the UI.
- **480 000-iteration PBKDF2** key derivation matching current OWASP guidance.
- **Authenticated encryption** — Fernet wraps AES-128-CBC with HMAC-SHA256, so
  tampering is detected, not silently accepted.
- **Comprehensive pytest suite** (32 tests) covering round-trips, error paths,
  capacity maths, and the password strength heuristic.

---

## Project structure

```
secure-steganography-tool/
├── app.py                    # Streamlit UI (5 tabs)
├── steganography.py          # LSB encode / decode + capacity helpers
├── encryption.py             # PBKDF2 + Fernet wrappers
├── utils.py                  # Small shared helpers
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
├── Dockerfile
├── docker-compose.yml
├── .github/
│   └── workflows/
│       └── python-ci.yml     # GitHub Actions CI
├── tests/
│   ├── test_steganography.py
│   └── test_encryption.py
├── assets/
│   └── demo_images/          # Sample PNG + BMP carriers
└── docs/
    ├── project_report.md     # Full academic report
    └── presentation_outline.md
```

---

## Installation

> Requires **Python 3.11+** (3.12 tested).

```bash
# 1. Clone
git clone https://github.com/<your-username>/secure-steganography-tool.git
cd secure-steganography-tool

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Running locally

```bash
streamlit run app.py
```

Streamlit will open the app at <http://localhost:8501>. Try the workflow:

1. Open the **Encode** tab.
2. Upload `assets/demo_images/landscape.png`.
3. Type a secret message (and optionally a password).
4. Click **Embed message** and download the resulting `stego_image.png`.
5. Switch to the **Decode** tab, re-upload `stego_image.png`, supply the same
   password if used, and click **Reveal message**.

---

## Running the test suite

```bash
pytest -v
```

Expected output (abridged):

```
tests/test_encryption.py .................                 [ 53%]
tests/test_steganography.py ..............                 [100%]
============================== 32 passed ===============================
```

---



## Continuous integration

`.github/workflows/python-ci.yml` runs on every push and pull request against
`main`. It:

1. Spins up an Ubuntu runner with Python 3.11 and 3.12.
2. Installs `requirements.txt`.
3. Runs `pytest -v`.

A green build is a hard requirement for merging.

---

## Cloud deployment

### Streamlit Community Cloud

1. Push the repository to GitHub.
2. Sign in to <https://share.streamlit.io> with your GitHub account.
3. Click **New app** → select your fork → set **Main file path** to `app.py`.
4. Click **Deploy** — Streamlit will install `requirements.txt` automatically.

### Render / Railway / Fly.io (any Docker-compatible PaaS)

The provided `Dockerfile` exposes port `8501` and runs:

```bash
streamlit run app.py --server.port=8501 --server.address=0.0.0.0
```

Point your platform of choice at the repository, choose **Docker** as the
build method, and set the runtime port to `8501`. No additional environment
variables are required.

---

## Screenshots

> _Replace these placeholders with real screenshots after deploying locally._

| | |
| --- | --- |
| ![Encode tab](docs/screenshots/encode.png) | ![Decode tab](docs/screenshots/decode.png) |
| ![Capacity calculator](docs/screenshots/capacity.png) | ![Security analysis](docs/screenshots/security.png) |

To produce your own, simply run the app, take screenshots of each tab, and
save them under `docs/screenshots/` with the filenames above.

---

## Security concepts demonstrated

| Concept | Where in the code |
| --- | --- |
| **Confidentiality (CIA triad)** | Steganography + encryption layered together |
| **Symmetric encryption (Fernet/AES)** | `encryption.encrypt_message` / `decrypt_message` |
| **Authenticated encryption** | Fernet's built-in HMAC-SHA256 — surfaced as `InvalidPasswordError` on tamper |
| **Key derivation (PBKDF2-HMAC-SHA256)** | `encryption.derive_key` with 480 000 iterations |
| **Salt for password-based crypto** | 16 random bytes generated per encryption call |
| **LSB steganography** | `steganography.encode_image` / `decode_image` |
| **Capacity / payload analysis** | `steganography.calculate_capacity` |
| **Input validation & defensive coding** | Custom exceptions, strict format whitelist |
| **Statistical steganalysis discussion** | Security Analysis tab + `docs/project_report.md` |

---

## Future improvements

- **Higher-bit embedding** (k-LSB with k ≥ 2) with adaptive capacity warnings.
- **Steganalysis demo** — visualise LSB histograms / chi-square tests.
- **Adaptive embedding** in noisy regions only (edge-aware) to lower
  detectability.
- **Drag-and-drop image upload** (already supported by Streamlit's uploader
  on supported browsers; can be made more prominent via custom components).
- **QR-code export** of the extracted plaintext for mobile capture.
- **Audio steganography** companion module.
- **Multi-recipient public-key mode** using X25519 + libsodium.
- **Tamper-evident headers** with explicit version & feature bits.

---

