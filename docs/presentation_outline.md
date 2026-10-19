# Presentation Outline — Secure Image Steganography Tool

**Target length:** 10 – 12 slides, ≈ 15 minutes + 5 minutes Q&A.
**Audience:** Information Security course instructor, examiners, and peers.

> Speaker notes are given in *italics* under each slide. Keep on-slide text to
> short bullets — the talking is yours, the slide is a visual anchor.

---

## Slide 1 — Title

- **Title:** Secure Image Steganography Tool with Optional Encryption
- **Subtitle:** A final-year Information Security project
- **Author:** _<Your Name>_ • _<Roll Number>_
- **Supervisor:** _<Supervisor Name>_
- _<Department, University, Year>_

*Speaker notes — Welcome the audience, introduce yourself and the supervisor
in one sentence, and read the title aloud.*

---

## Slide 2 — Problem & Motivation

- Encryption hides *content* — not *existence*.
- Existence-of-message alone can compromise the user (censorship, traffic
  analysis, insider monitoring).
- Naive online steganography tools often: use lossy carriers silently
  corrupt the payload, skip integrity, or omit encryption entirely.

*Speaker notes — Frame the gap that steganography fills, and pre-empt the
common student question "why not just encrypt?" with a one-sentence answer.*

---

## Slide 3 — Project Goals

1. Working LSB encode/decode for PNG and BMP.
2. Optional **password-based authenticated encryption** before embedding.
3. **In-app educational content** for the CIA triad and steganalysis.
4. A test suite, Docker image, and CI pipeline good enough to **deploy
   anywhere** and **submit as a portfolio artefact**.

*Speaker notes — Read each as a measurable success criterion; you will tie
each back to a demo or test count later.*

---

## Slide 4 — Background: LSB Steganography

- For every RGB pixel: clear the lowest bit, OR in the next payload bit.
- ±1 change per channel is below human visual perception thresholds.
- Capacity = `width × height × 3 bits` (≈ 3.75 KB in a 100 × 100 image).
- **Lossless carriers only.** JPEG re-encoding destroys the payload.

*Speaker notes — Use a simple binary example: 11010110 (214) → 11010111 (215)
is invisible to the eye. Then point at the architecture diagram on the next
slide.*

---

## Slide 5 — Background: PBKDF2 + Fernet

- **Fernet** = AES-128-CBC + HMAC-SHA256 (authenticated encryption).
- **PBKDF2-HMAC-SHA256** with **480 000 iterations** (OWASP 2023+).
- 16-byte random **salt** per message — no rainbow tables, no reuse risk.
- Wire format: `base64( salt || fernet_token )`.

*Speaker notes — Emphasise authenticated encryption: the HMAC catches
tampering, which we surface as `InvalidPasswordError`.*

---

## Slide 6 — System Architecture

```
┌──────────────┐    ┌──────────────────┐    ┌────────────────┐
│ Streamlit UI │──▶│ steganography.py │──▶│ Image (PNG/BMP)│
│   (app.py)   │    │ LSB encode/decode│    └────────────────┘
└──────┬───────┘    └────────┬─────────┘
       │                     │
       ▼                     ▼
┌──────────────┐    ┌──────────────────┐
│encryption.py │    │     utils.py     │
│PBKDF2+Fernet │    └──────────────────┘
└──────────────┘
```

*Speaker notes — Walk left-to-right: UI receives input, encryption layer
optionally encrypts, steganography layer embeds, image is downloaded.*

---

## Slide 7 — Implementation Highlights

- **Vectorised NumPy LSB** — `(channel & 0b1111_1110) | bit` over the
  flattened array. Sub-millisecond for typical inputs.
- **Sentinel `<<<END>>>`** located in the **byte stream**, not the decoded
  string — defends against random-LSB trailing UTF-8 corruption.
- **Custom exceptions:** `MessageTooLargeError`, `NoHiddenMessageError`,
  `InvalidPasswordError`, `UnsupportedImageFormatError`.
- **Streamlit `st.status`** for step-wise progress feedback.

*Speaker notes — These are the engineering decisions you can defend if
questioned in detail.*

---

## Slide 8 — Live Demo (≈ 3 minutes)

1. **Encode** with no password — show capacity metric.
2. **Encode** with a password — show password strength meter.
3. **Decode** without password — heuristic warning fires.
4. **Decode** with correct password — plaintext recovered.
5. Try uploading a **JPEG** — show the format rejection.

*Speaker notes — Keep the demo to under 3 minutes. Pre-load the demo images
in your browser tabs. If you run out of time, skip step 5.*

---

## Slide 9 — Testing & CI

- **32 pytest unit tests** in two files.
- Coverage includes round-trips, error paths, capacity arithmetic, Unicode
  payloads, JPEG rejection, HMAC tamper detection.
- **GitHub Actions** runs the suite on Python 3.11 and 3.12 for every push.
- Docker image builds reproducibly in `< 60 s`.

*Speaker notes — Be ready to show the green CI badge on the README if asked.*

---

## Slide 10 — Security Analysis

- **What we protect:** confidentiality of content (encryption) +
  confidentiality of *existence* (steganography).
- **What we don't protect against:**
  - Statistical steganalysis (chi-square, RS, SPA).
  - Lossy re-encoding by intermediaries.
  - Side channels on the user's host.
- **Best practices baked in:** OWASP-compliant PBKDF2, salt, AEAD, format
  whitelist, capacity transparency.

*Speaker notes — This slide is your "honest threats" disclosure. Examiners
love candour about limitations.*

---

## Slide 11 — Limitations & Future Work

- **Limitations:** detectable under modern steganalysis; brittle to
  recompression; shared-secret only.
- **Future directions:**
  - Adaptive embedding into noisy/edge regions.
  - k-LSB with quality controls.
  - X25519 public-key envelope mode.
  - Audio / video / WebP carriers.
  - In-app steganalysis visualiser (chi-square histograms).

*Speaker notes — Pick **one** future direction you'd genuinely pursue and
say "if I had another semester, I'd start with X" — examiners ask this.*

---

## Slide 12 — Q & A / Thank You

- **GitHub:** `github.com/<your-username>/secure-steganography-tool`
- **Live demo:** `<your-streamlit-url>`
- **Contact:** _<email>_
- **Acknowledgements:** _<Supervisor Name>_, _<Lab>_, _<Funding>_.

*Speaker notes — Have a backup slide ready with the architecture diagram
and a screenshot of the test output in case of detailed questions.*

---

## Optional backup slides

- **B1.** Bit-level diagram of LSB embedding on a single pixel.
- **B2.** Side-by-side cover vs. stego histogram for the demo landscape.
- **B3.** Source code excerpt of `encode_image` showing the vectorised mask.
- **B4.** Test-suite screenshot (`32 passed in 3.80s`).
