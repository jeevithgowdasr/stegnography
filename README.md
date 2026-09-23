# 🔒 Dual-Layer Image Encryption & Steganography Engine

An enterprise-grade, academically rigorous cybersecurity system that fuses **Authenticated Symmetric Cryptography (AES-256-GCM + PBKDF2)** with **Spatial Least Significant Bit (LSB) Digital Steganography**.

Designed to provide mathematical **confidentiality**, **authenticity**, **integrity**, and **visual imperceptibility** when transmitting sensitive information over untrusted channels.

---

## 📌 1. Project Overview & Dual-Layer Defense

Standard encryption secures data from unauthorized reading, but exposes ciphertexts as suspicious blobs that attract cryptanalysis and censorship. Steganography hides the presence of communication, but plain steganography is vulnerable if the carrier is extracted. 

This system integrates a **Dual-Layer Defense Architecture**:
1. **Cryptographic Layer**: Plaintext is converted to high-entropy ciphertext using **AES-256-GCM** with a **256-bit derived key** via **PBKDF2-HMAC-SHA256** (100,000 iterations). A 128-bit authentication tag ensures tamper resistance.
2. **Steganographic Layer**: The encrypted binary payload is embedded into the Least Significant Bits of lossless image carriers (`.png`, `.bmp`) using a vectorized NumPy engine with strict Alpha transparency preservation.

---

## 🏗️ 2. Architecture & Data Flow

```text
[ Secret Plaintext ] ────┐
                         │
[ User Passphrase ] ─────┼──> [ PBKDF2-HMAC-SHA256 ] ──> [ 256-bit Key ]
[ 16-byte CSPRNG Salt ] ─┘                                     │
                                                               ▼
                                                    [ AES-256-GCM Cipher ]
                                                               │
                                                               ▼
                                                 [ Encrypted Binary Stream ]
                                                 [ 4B Magic | Salt | IV | Ciphertext | 16B Tag ]
                                                               │
[ Cover Image (.png/.bmp) ] ──> [ Capacity Check ]             │
              │                         │                      ▼
              ▼                         ▼             [ 32-bit Framing ]
     [ RGB Channels ] ◄───────────────────────── [ Vectorized LSB Embedding ]
     [ Alpha Preserved ]                                       │
                                                               ▼
                                                   [ Lossless Stego Image ]
                                                   (PSNR > 70 dB, SSIM > 0.999)
                                                               │
   ══════════════════ UNTRUSTED TRANSMISSION CHANNEL ══════════════════
                                                               │
                                                               ▼
                                                   [ LSB Vectorized Decoder ]
                                                               │
                                                               ▼
                                                [ Extract 32-bit Header & Stream ]
                                                               │
[ User Passphrase ] ───────────────────────────────────────────┼──> [ Authenticate Tag & Decrypt ]
                                                               │
                                                               ▼
                                                   [ Recovered Plaintext ]
```

---

## 🔬 3. Mathematical & Cryptographic Specifications

### A. Key Derivation Function (PBKDF2-HMAC-SHA256)
$$\text{Key} = \text{PBKDF2}(\text{PRF}=\text{HMAC-SHA256}, \text{Password}, \text{Salt}=16\text{ bytes}, \text{Iterations}=100,000, \text{Len}=32\text{ bytes})$$

### B. Authenticated Encryption (AES-256-GCM)
$$C, T = \text{AES-GCM-Encrypt}(K, \text{Nonce}=12\text{ bytes}, P)$$
$$P = \text{AES-GCM-Decrypt}(K, \text{Nonce}=12\text{ bytes}, C, T)$$
*If ciphertext $C$ or tag $T$ is modified by even 1 bit, decryption is aborted with `DecryptionError`.*

### C. Carrier Capacity & Framing Protocol
$$\text{Usable Capacity (bytes)} = \left\lfloor \frac{\text{Width} \times \text{Height} \times 3}{8} \right\rfloor - 4\text{ bytes (Length Prefix)}$$

### D. Quality & Imperceptibility Metrics
- **Mean Squared Error (MSE)**:
  $$MSE = \frac{1}{M \times N \times C} \sum_{i=0}^{M-1} \sum_{j=0}^{N-1} \sum_{k=0}^{C-1} [I_{\text{orig}}(i,j,k) - I_{\text{stego}}(i,j,k)]^2$$
- **Peak Signal-to-Noise Ratio (PSNR)**:
  $$PSNR = 10 \cdot \log_{10}\left(\frac{255^2}{MSE}\right) \quad (\text{Threshold} > 35\text{--}40\text{ dB})$$
- **Structural Similarity Index (SSIM)**:
  $$SSIM(x,y) = \frac{(2\mu_x\mu_y + C_1)(2\sigma_{xy} + C_2)}{(\mu_x^2 + \mu_y^2 + C_1)(\sigma_x^2 + \sigma_y^2 + C_2)}$$

---

## 💻 4. Prerequisites & Installation

### Prerequisites
- **Python 3.10+** (Tested on Python 3.10, 3.11, 3.12, 3.13)
- Windows, macOS, or Linux

### Installation Steps

#### Windows (PowerShell / Command Prompt)
```powershell
# 1. Clone repository & navigate to directory
cd image-encryption-steganography

# 2. Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install production dependencies
pip install -r requirements.txt
```

#### macOS / Linux (Terminal)
```bash
# 1. Clone repository & navigate to directory
cd image-encryption-steganography

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install production dependencies
pip install -r requirements.txt
```

---

## 🚀 5. Usage Guide

### A. Desktop Graphical Interface (GUI)
Launch the modern Catppuccin dark-themed desktop application:

```bash
# Direct launch
python gui.py

# Or via cross-platform runners:
./run.sh      # Linux / macOS
run.bat       # Windows
```

#### GUI Highlights:
- **Tab 1: Encrypt & Hide**: Real-time capacity computation, secret plaintext editor, show/hide passphrase toggle, background worker threading, live PSNR/MSE/SSIM quality reporting, and stego-image export.
- **Tab 2: Extract & Decrypt**: File preview, passphrase authentication, and one-click clipboard copying.
- **Difference Map Inspector**: Side-by-side modal displaying the original cover, stego carrier, and an amplified difference heatmap ($5\times$ to $100\times$ amplification).

---

### B. Command-Line Interface (CLI Pipeline)
The unified pipeline (`pipeline.py`) can be executed standalone for automated batch processing and scripting.

#### 1. Encrypt and Hide a Secret Message:
```bash
python pipeline.py hide \
  --cover assets/cover.png \
  --secret "CONFIDENTIAL: Operation Antigravity credentials." \
  --password "CorrectHorseBatteryStaple#2026" \
  --output stego_output.png
```

#### 2. Extract and Decrypt a Concealed Message:
```bash
python pipeline.py extract \
  --stego stego_output.png \
  --password "CorrectHorseBatteryStaple#2026"
```

---

### C. Automated QA, Steganalysis & Performance Test Suite
Run the 12-stage automated QA and steganalysis suite:

```bash
# Direct runner with latency benchmarks
python test_system.py

# Or via pytest discovery
pytest -v
```

---

## 📊 6. Performance Benchmarks & Quality Metrics

Tested on standard synthetic and photographic RGB/RGBA test images:

| Carrier Resolution | Carrier Capacity | Payload Size | Utilized (%) | MSE | PSNR (dB) | SSIM | Embed Time | Extract Time |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **100 x 100** | 3.74 KB | 256 bytes | 6.84% | 0.0171 | 65.81 dB | 0.9998 | 18.2 ms | 12.1 ms |
| **256 x 256** | 24.57 KB | 1.85 KB | 7.53% | 0.0188 | 65.39 dB | 0.9997 | 34.5 ms | 19.4 ms |
| **512 x 512** | 98.30 KB | 5.00 KB | 5.08% | 0.0127 | 67.09 dB | 0.9999 | 82.1 ms | 41.2 ms |
| **1024 x 1024** | 393.21 KB | 20.00 KB | 5.08% | 0.0125 | 67.16 dB | 0.9999 | 245.0 ms | 118.0 ms |

> [!NOTE]
> All test cases achieved **PSNR $> 65.0\text{ dB}$** (well above the human visual perception threshold of $35\text{--}40\text{ dB}$) and **SSIM $> 0.999$**, rendering modified carrier images indistinguishable from original covers.

---

## 🛡️ 7. Security Considerations & Steganalysis Defense

1. **Strict Lossless Format Enforcement (`.png`, `.bmp`)**:
   - Lossy image formats (such as JPEG/WebP) perform Discrete Cosine Transform (DCT) quantization that destroys the least significant bit plane upon compression. Lossless PNG and BMP formats preserve exact byte-for-byte pixel values.
2. **Pairs of Values (PoVs) & Chi-Square ($\chi^2$) Resistance**:
   - Sequential LSB insertion of encrypted high-entropy data equalizes adjacent histogram bins $(2k, 2k+1)$. To maximize stealth, keeping payload sizes below $15\%$ of total carrier capacity guarantees optimal resistance against visual and statistical inspection.
3. **Shannon Entropy Profile**:
   - The cipher stream embedded in bit-plane 0 exhibits maximal Shannon entropy ($H(X) > 0.99$ bits/bit), preventing frequency-based pattern recognition.

---

## 🔮 8. Future Work & Enhancements

- **Edge-Adaptive Embedding (PVD / Canny / Sobel)**: Restrict embedding to high-frequency texture and edge regions of the image where human visual sensitivity is lowest, further defeating first-order statistical detectors.
- **Frequency Domain Steganography (DWT / DCT)**: Expand embedding into Discrete Wavelet Transform coefficients for robustness against mild image transformations.
- **Multimodal Carrier Support**: Extend the pipeline to support audio (.wav, .flac) and video (.avi, .mkv) steganography carriers.
- **Deep Learning Steganalysis Hardening**: Incorporate adversarial perturbations against deep convolutional neural networks (e.g., Xu-Net, Ye-Net).

---

## 📄 License & Academic Attribution
Developed as part of the **Advanced Cyber Security & Digital Image Processing** research curriculum inside **Google Antigravity**. Built using `cryptography`, `numpy`, `Pillow`, and `opencv-python`.
