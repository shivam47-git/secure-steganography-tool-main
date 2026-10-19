# Secure Image Steganography Tool with Optional Encryption
### A Final-Year Project Report — Information Security

**Author:** _<Your Name>_
**Roll Number / ID:** _<Your Roll Number>_
**Supervisor:** _<Supervisor Name>_
**Department:** _<Department>_
**Institution:** _<Your University>_
**Submission date:** _<Month Year>_

---

## Table of contents

1. [Abstract](#1-abstract)
2. [Introduction](#2-introduction)
3. [Problem Statement](#3-problem-statement)
4. [Objectives](#4-objectives)
5. [Literature Review](#5-literature-review)
6. [Methodology](#6-methodology)
7. [System Design](#7-system-design)
8. [Implementation Details](#8-implementation-details)
9. [Results](#9-results)
10. [Security Analysis](#10-security-analysis)
11. [Limitations](#11-limitations)
12. [Future Work](#12-future-work)
13. [Conclusion](#13-conclusion)
14. [References](#14-references)

---

## 1. Abstract

The rapid digitisation of communication has made the *confidentiality* of
exchanged information one of the central concerns of modern information
security. While encryption protects the **content** of a message, it does not
hide the **fact** that a confidential message exists — an observation that
itself can constitute a security breach in adversarial environments. Image
steganography addresses this gap by concealing data within the perceptually
imperceptible bits of a carrier image.

This project presents a complete, web-based tool that combines two
complementary techniques: (i) least-significant-bit (LSB) steganography for
covert channel construction, and (ii) password-based authenticated symmetric
encryption (PBKDF2-HMAC-SHA256 → Fernet/AES-128-CBC + HMAC-SHA256) for
content confidentiality. The application is built in Python with Streamlit
and exposes five tabs — *Encode*, *Decode*, *Capacity Calculator*, *Security
Analysis*, and *About* — each supporting a pedagogical objective alongside
its functional one. A test suite of 32 unit tests covers round-trip
correctness, capacity arithmetic, error handling and the password-strength
heuristic; a Docker image and a GitHub Actions pipeline enable reproducible
deployment and continuous integration.

The system has been validated on PNG and BMP carriers ranging from
64 × 64 pixels up to several megapixels, embedding payloads of thousands of
characters at well under 1% capacity utilisation while remaining visually
indistinguishable from the originals.

---

## 2. Introduction

Information security professionals routinely speak of the **CIA triad** —
Confidentiality, Integrity and Availability — as the three guiding properties
of any secure system. Confidentiality is most often achieved through
cryptography. However, in many real-world settings the *presence* of
encrypted traffic itself draws attention, e.g. censorship-regime traffic
analysis, insider-threat monitoring, or covert intelligence channels. This
class of threat is the motivating concern of **steganography** — literally
"covered writing" — whose goal is to embed information so that an observer
cannot tell that a message exists at all.

Of the many steganographic schemes catalogued in the literature, the
**Least-Significant-Bit** technique remains the canonical educational
example. It is conceptually simple, well-understood, and exposes the core
trade-offs (capacity vs. imperceptibility vs. detectability) clearly. It is
therefore an ideal subject for a final-year undergraduate project that aims
to demonstrate both the mechanics of an information-hiding system and the
adversarial reasoning required to evaluate it.

This project goes beyond a textbook LSB demonstrator by layering optional
password-based encryption *underneath* the steganographic channel, providing
**defence in depth**: even an analyst who successfully detects and extracts
the embedded bytes is left with an authenticated ciphertext.

---

## 3. Problem Statement

Plain encryption tools (e.g. GnuPG, Signal) cannot satisfy a class of users
whose *threat model* includes adversaries with the power to observe and act
on the mere existence of encrypted communication. Conversely, naive
steganographic implementations frequently:

- Use **lossy carrier formats** (e.g. JPEG), silently corrupting the payload.
- Omit a robust **end-of-message marker**, leading to truncated or
  garbage-laden decodes.
- Provide **no integrity check**, so a single bit of tampering produces a
  plausible-looking but incorrect plaintext.
- **Encrypt only optionally** with weak key derivation, exposing users to
  brute-force attacks on short passwords.
- Lack any **user-facing explanation** of the underlying threat model,
  leading to a false sense of security.

The problem this project addresses is therefore: *Design and implement a
production-grade educational tool that combines LSB steganography with
password-based authenticated encryption, exposes its capacity and threat
characteristics transparently to the user, and is reproducible enough to
serve as a portfolio artefact and submission for an Information Security
course.*

---

## 4. Objectives

1. **Functional** — Implement working LSB encode/decode for PNG and BMP
   carriers, with optional PBKDF2 + Fernet encryption.
2. **Robustness** — Reject lossy carriers, detect missing payloads, surface
   wrong passwords distinctly from absent messages, and reject oversized
   inputs cleanly.
3. **Educational** — Embed in the UI a "Security Analysis" tab explaining
   LSB, encryption-vs-steganography, the CIA triad, statistical attacks and
   best practices.
4. **Usability** — Provide a multi-tab Streamlit interface with progress
   indicators, drag-and-drop upload, a password strength meter, and clear
   error messaging.
5. **Quality** — Achieve ≥ 30 unit tests covering round-trips, encryption
   errors, oversize rejection, capacity maths, and Unicode payloads.
6. **Reproducibility** — Provide a Dockerfile, docker-compose file, GitHub
   Actions CI, and a deployment recipe for Streamlit Community Cloud.
7. **Documentation** — Deliver an academic report (this document) and a
   slide-deck outline suitable for an oral defence.

---

## 5. Literature Review

**Cachin (1998)** formalised steganographic security in information-theoretic
terms, requiring the statistical distribution of stego-objects to be
indistinguishable from cover-objects. While naïve LSB embedding fails this
criterion under sophisticated analysis, it remains the most pedagogically
accessible variant and a baseline against which later schemes are measured.

**Fridrich, Goljan & Du (2001)** introduced *RS-steganalysis*, demonstrating
that the dual-statistics of pixel pairs reveal LSB embedding with high
sensitivity. Subsequent work (e.g. **Ker, 2005**, on weighted-stego analysis;
**Pevný, Bas & Fridrich, 2010**, on subtractive pixel adjacency models)
sharpened the attack to the point where modern stego systems must
incorporate adaptive, content-aware embedding to remain undetectable.

**Provos & Honeyman (2003)** surveyed practical steganography on the public
internet, finding very few documented uses despite media speculation. Their
work emphasises the importance of *defence in depth* — combining
steganography with cryptography — which is the design principle adopted by
this project.

On the cryptographic side, **Kaliski (2000, RFC 2898)** specifies PBKDF2,
the password-based key-derivation function used here. **Percival & Josefsson
(2016, RFC 7914)** later proposed scrypt to defeat hardware attackers, but
PBKDF2 with high iteration counts remains acceptable per **OWASP (2023)**
Password Storage Cheat Sheet (≥ 480 000 iterations of PBKDF2-HMAC-SHA256).
The encryption primitive itself is **Fernet** — a high-level wrapper around
AES-128-CBC + HMAC-SHA256 specified by the Python `cryptography` library —
which provides authenticated encryption and replay protection through
embedded timestamps and IVs.

For implementation guidance the project draws on **Streamlit's official
documentation** (Snowflake, 2024) and **Pillow's documentation** (Murray
et al., 2024), as well as the canonical NumPy bit-packing routines
(`packbits`, `unpackbits`).

---

## 6. Methodology

The project followed an **iterative, test-driven** development methodology:

1. **Requirements & threat modelling.** The functional and educational goals
   in §4 were enumerated, and a simple threat model defined (passive
   adversary capable of statistical analysis; active adversary capable of
   re-saving the image; offline brute-force adversary against the password).
2. **Modular decomposition.** Three independent modules were specified:
   `steganography.py` (carrier-side), `encryption.py` (key derivation +
   AEAD), and `utils.py` (cross-cutting helpers).
3. **Test-first implementation.** Unit tests were written before each
   feature: round-trips first, then error cases, then capacity arithmetic.
4. **UI assembly.** Once the core modules were green, the Streamlit UI was
   built in a single-file `app.py` with five tabs.
5. **Continuous integration.** A GitHub Actions workflow was added to enforce
   the test suite on every push.
6. **Containerisation.** A multi-stage Dockerfile and a docker-compose file
   were authored to enable one-command deployment.
7. **Documentation.** The README, this report, and a slide-deck outline were
   written in parallel with implementation to capture rationale while it
   was fresh.

Total effort: approximately _<N>_ weeks at _<H>_ hours per week.

---

## 7. System Design

### 7.1 High-level architecture

```
   ┌────────────────────────────────────────────────────┐
   │                  Streamlit UI (app.py)             │
   │ ┌──────┐ ┌──────┐ ┌──────────┐ ┌──────────┐ ┌─────┐│
   │ │Encode│ │Decode│ │Capacity  │ │Security  │ │About││
   │ └──┬───┘ └───┬──┘ └──────────┘ └──────────┘ └─────┘│
   │    │        │                                     │
   └────┼────────┼─────────────────────────────────────┘
        │        │
        ▼        ▼
   ┌──────────────────┐    ┌─────────────────────────┐
   │  encryption.py   │    │   steganography.py      │
   │  PBKDF2 + Fernet │    │   LSB encode / decode   │
   └────────┬─────────┘    └────────────┬────────────┘
            │                           │
            └────────────┬──────────────┘
                         ▼
                  ┌─────────────┐
                  │   utils.py  │
                  └─────────────┘
```

### 7.2 Data flow — encoding

```
plaintext ──► [optional encrypt(password)] ──► payload ──► append("<<<END>>>")
                                                              │
                                                              ▼
                                                       UTF-8 → bits
                                                              │
                                                              ▼
   carrier RGB array  ◄─► (channel & 0b11111110) | bit ──► stego array
                                                              │
                                                              ▼
                                                        save as PNG
```

### 7.3 Data flow — decoding

```
stego PNG ──► RGB array ──► extract LSBs ──► pack to bytes
                                                  │
                                                  ▼
                                  search for "<<<END>>>" in bytes
                                                  │
                                                  ▼
                                       prefix.decode("utf-8") = payload
                                                  │
                              (if password supplied) ▼
                                       decrypt(payload, password)
                                                  │
                                                  ▼
                                            recovered plaintext
```

### 7.4 Wire format of an encrypted payload

After base64 decoding, the embedded ciphertext envelope is:

```
┌─────────────┬────────────────────────────────────────────┐
│  salt (16B) │              Fernet token                  │
└─────────────┴────────────────────────────────────────────┘
   random                AES-128-CBC + HMAC-SHA256
```

The whole envelope is then URL-safe-base64-encoded for ASCII safety inside
the steganographic channel.

---

## 8. Implementation Details

### 8.1 Module: `encryption.py`

- **`derive_key(password, salt)`** — wraps `PBKDF2HMAC(SHA256, length=32,
  salt=salt, iterations=480_000)` and returns a url-safe-base64 Fernet key.
- **`encrypt_message(message, password)`** — generates 16 random salt bytes,
  derives a key, calls `Fernet.encrypt`, then concatenates `salt || token`
  and base64-encodes the result.
- **`decrypt_message(payload_b64, password)`** — reverses the process and
  maps `cryptography.fernet.InvalidToken` to a `InvalidPasswordError` for
  clearer UI surfacing. Truncated/malformed payloads raise `ValueError`.
- **`password_strength(password)`** — a five-criterion heuristic (length ≥ 8,
  lower, upper, digit, symbol) that returns a `(score, label)` tuple for the
  UI strength meter. Not a substitute for password-policy enforcement.

### 8.2 Module: `steganography.py`

- **`encode_image(image, message)`** — converts the carrier to RGB, flattens
  the array, clears the LSB of the first `len(payload_bits)` channels and
  ORs in each payload bit. This is fully vectorised through NumPy and runs
  in microseconds for typical inputs.
- **`decode_image(image)`** — extracts every LSB into a byte stream, then
  finds the `<<<END>>>` sentinel **inside the byte stream** rather than the
  decoded string. This avoids a UTF-8 decoding failure on the random LSBs
  that follow the marker.
- **`calculate_capacity(width, height)`** and **`utilization_percentage()`**
  — pure functions that drive the Capacity Calculator tab.

### 8.3 Module: `app.py`

A single Streamlit script, ≈ 350 lines, structured around `st.tabs`. Each
tab is self-contained; shared state is intentionally avoided to keep the
control flow linear. Notable UX choices include:

- `st.status` context managers around the encode/decode pipelines to give
  step-wise progress feedback.
- A live preview of the carrier (and stego) image alongside a metric card
  summarising dimensions, file size and max-character capacity.
- A heuristic check (`_looks_like_encrypted`) that warns users who try to
  decode an encrypted payload without supplying a password.

### 8.4 Tests

The pytest suite contains 32 tests grouped into two files. Notable cases:

- **Round-trip with random pixel data** to guarantee correctness against
  realistic LSB distributions.
- **`test_encode_modifies_only_lsb`** verifies that the top 7 bits of every
  channel are byte-for-byte identical to the input — a structural invariant
  of the algorithm.
- **`test_jpeg_rejected_for_encoding`** generates an in-memory JPEG and
  asserts the encoder refuses it.
- **`test_tampered_ciphertext_raises_invalid_password`** flips a single bit
  in the Fernet token and verifies HMAC catches it.
- **`test_password_strength_scoring`** parametrised across six inputs to pin
  the heuristic.

---

## 9. Results

### 9.1 Functional verification

All 32 unit tests pass on Python 3.12 (CPython, Linux):

```
============================== 32 passed in 3.80s ==============================
```

End-to-end manual verification:

| Input | Output | Status |
| --- | --- | --- |
| 128 × 128 random PNG + 39-char plaintext + 22-char password | Stego PNG (≈ 49 KB) decodes to identical plaintext | ✅ |
| 720 × 480 demo landscape + 1 200-char essay, no password | Identical recovery | ✅ |
| Same carrier as above + wrong password on decode | `InvalidPasswordError` shown to user | ✅ |
| 4 × 4 black PNG + 100-char message | `MessageTooLargeError` shown to user | ✅ |
| JPEG carrier upload | `UnsupportedImageFormatError` shown to user | ✅ |
| Decode of unmodified PNG | `NoHiddenMessageError` shown to user | ✅ |

### 9.2 Capacity benchmarks

| Carrier | Pixels | Capacity (chars) | Typical message (10 lines × 80 chars) | Utilisation |
| --- | --- | --- | --- | --- |
| 64 × 64 | 4 096 | 1 527 | 800 chars | 52.4% |
| 480 × 720 | 345 600 | 129 591 | 800 chars | 0.62% |
| 1080p photo | 2 073 600 | 777 591 | 800 chars | 0.10% |

### 9.3 Visual fidelity

Subjective inspection of stego/original pairs at 0.62% utilisation shows no
perceptible difference. Pixel-difference histograms confirm that only the
LSB of each channel has been altered, and only over a small prefix of the
image, leaving > 99% of bits untouched.

---

## 10. Security Analysis

### 10.1 Threat model

| Adversary | Capability | Project mitigation |
| --- | --- | --- |
| Passive eavesdropper | Reads transmitted images | Steganography hides existence of message |
| Steganalyst | Statistical analysis of pixel LSBs | Acknowledged limitation; mitigation = encrypt first, use noisy carriers |
| Active tamperer | Re-saves, crops, resizes | Acknowledged limitation; PNG/BMP-only carriers + integrity bit via Fernet HMAC if encrypted |
| Offline brute-forcer | Guesses passwords | 480 000-round PBKDF2-HMAC-SHA256 + password strength meter |
| Pixel-flipping attacker | Modifies stego image bits | Fernet HMAC detects tamper, returns `InvalidPasswordError` |

### 10.2 Confidentiality argument

- *Unobservability.* LSB embedding modifies pixel values by at most ±1, well
  below the noise floor of a typical photograph. Without statistical tools,
  an observer cannot tell that any message is present.
- *Content secrecy.* When a password is supplied, the payload is Fernet
  ciphertext. Fernet is built from AES-128-CBC + HMAC-SHA256 — both
  primitives are NIST-approved and considered cryptographically sound. The
  key is derived with PBKDF2-HMAC-SHA256 at the OWASP-recommended iteration
  count, so an attacker who recovers the ciphertext still faces a costly
  offline brute-force.
- *Integrity.* The HMAC layer in Fernet ensures any modification to the
  embedded ciphertext is detected — and surfaced as a wrong-password error
  rather than an attacker-controlled plaintext.

### 10.3 Known statistical attacks

- **Chi-square attack** detects LSB embedding by counting the frequency of
  PoVs (pairs of values that differ only in their LSB). Embedded regions
  show a characteristic flattening of the histogram.
- **RS analysis** (Fridrich et al.) examines the discrimination function
  applied to regular and singular groups of pixels.
- **Sample Pair Analysis** estimates the embedding rate by comparing the
  populations of "trace" and "anti-trace" pairs.

These attacks are out of scope as a defensive mitigation for this project —
their detection bound grows with embedding rate, so the **best defence is
to encrypt and use very low utilisation in a noisy carrier**.

### 10.4 Out-of-scope concerns

- **Side-channel attacks** against the host OS (cold-boot, swap-file
  forensics) are not in scope.
- **Operational security** — for instance, leaking the password through a
  keylogger — is the user's responsibility.

---

## 11. Limitations

1. **Statistical detectability.** LSB steganography is the easiest scheme to
   detect under modern steganalysis. The tool is therefore best framed as a
   *teaching aid* rather than an operational covert-channel.
2. **Format brittleness.** Any lossy conversion of the carrier (e.g. JPEG
   recompression by a messaging service) destroys the payload.
3. **Limited carrier types.** Only PNG and BMP are supported. Audio, video,
   document-format and network-protocol steganography are out of scope.
4. **No key management.** Passwords are typed by the user; there is no key
   escrow, key rotation, or recipient public-key support.
5. **Fixed embedding strategy.** The encoder writes the payload into the
   first N pixels in row-major order; an adaptive, content-aware embedder
   would be more resistant to steganalysis.
6. **No multi-recipient mode.** The tool is point-to-point with a shared
   secret; there is no support for envelope encryption or group recipients.

---

## 12. Future Work

- **Adaptive embedding** that spreads payload bits across noisy, high-entropy
  regions only.
- **k-LSB embedding** (k > 1) with capacity/quality trade-off controls.
- **Pluggable carriers**: WAV audio, lossless WebP, RAW photos.
- **Public-key envelope encryption** so users need not share a password
  out-of-band — e.g. age/libsodium box encryption with the Fernet key.
- **Integrated steganalysis demo** showing the chi-square histogram before
  and after embedding.
- **QR-code export** of decoded plaintext for hand-off to a phone.
- **Audit logging** for organisational deployments.
- **WebAssembly port** for fully client-side, server-less use.

---

## 13. Conclusion

This project demonstrates that a small, well-tested codebase can convey two
of the most important confidentiality concepts in information security —
covert channels and authenticated encryption — while remaining accessible
to undergraduate students. The combination of LSB steganography for
unobservability and PBKDF2-derived Fernet encryption for content secrecy
captures the principle of **defence in depth** in a form learners can run,
break and reason about in their own browsers.

The final tool is functional, fully tested, containerised, continuously
integrated, and ready for deployment to Streamlit Community Cloud or any
Docker-compatible platform. Its limitations — primarily the statistical
detectability of naïve LSB embedding — are surfaced honestly in the
in-app Security Analysis tab and in this report, modelling the kind of
threat-aware engineering culture the course aims to cultivate.

---

## 14. References

1. Cachin, C. (1998). *An Information-Theoretic Model for Steganography.*
   Proc. 2nd Int. Workshop on Information Hiding, LNCS 1525.
2. Fridrich, J., Goljan, M., & Du, R. (2001). *Reliable Detection of LSB
   Steganography in Color and Grayscale Images.* Proc. ACM Workshop on
   Multimedia and Security.
3. Ker, A. D. (2005). *Improved Detection of LSB Steganography in Grayscale
   Images.* Proc. 6th Information Hiding Workshop, LNCS 3200.
4. Pevný, T., Bas, P., & Fridrich, J. (2010). *Steganalysis by Subtractive
   Pixel Adjacency Matrix.* IEEE Trans. Information Forensics & Security.
5. Provos, N., & Honeyman, P. (2003). *Hide and Seek: An Introduction to
   Steganography.* IEEE Security & Privacy.
6. Kaliski, B. (2000). *PKCS #5: Password-Based Cryptography Specification
   Version 2.0.* IETF RFC 2898.
7. Percival, C., & Josefsson, S. (2016). *The scrypt Password-Based Key
   Derivation Function.* IETF RFC 7914.
8. OWASP Foundation. (2023). *Password Storage Cheat Sheet.* Retrieved from
   <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>.
9. NIST. (2001). *FIPS PUB 197: Advanced Encryption Standard.*
10. Cryptography.io Authors. (2024). *cryptography — Fernet symmetric
    encryption documentation.* <https://cryptography.io/>.
11. Snowflake Inc. (2024). *Streamlit Documentation.*
    <https://docs.streamlit.io/>.
12. Murray, A., et al. (2024). *Pillow (PIL Fork) Documentation.*
    <https://pillow.readthedocs.io/>.
13. Stallings, W. (2020). *Cryptography and Network Security: Principles and
    Practice* (8th ed.). Pearson.
14. Anderson, R. (2020). *Security Engineering: A Guide to Building
    Dependable Distributed Systems* (3rd ed.). Wiley.

---

*End of report.*
