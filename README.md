# 🛡️ StegFix — A Transformer-Based Detector for Network Steganography

StegFix is a web-based, real-time network steganography detection platform powered by a custom Transformer encoder.The **FeatureTokenTransformer** — capable of detecting covert channels hidden inside DNS, ICMP, TCP, and UDP traffic with **94.42% mean accuracy** and only a **0.91% false positive rate**, even on steganographic techniques never seen during training.

<img width="292" height="411" alt="image" src="https://github.com/user-attachments/assets/1f5fafc1-4958-42a5-a339-7550aaa7ab1c" />

---

## 📌 Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [The FeatureTokenTransformer Model](#the-featuretokentransformer-model)
- [Dataset](#dataset)
- [Results](#results)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Installation & Setup](#installation--setup)
- [Usage](#usage)
- [Testing](#testing)
- [Limitations](#limitations)
- [Future Work](#future-work)
- [References](#references)
- [License](#license)

---

## 📖 Overview

Network steganography hides the **existence** of communication — not just its content — inside ordinary, protocol-compliant packets. Signature-based IDS, statistical anomaly detectors, and classical ML approaches fail to generalize to previously unseen covert channel techniques.

StegFix bridges the gap between academically validated deep learning research and a practically deployable Security Operations Centre (SOC) tool. It integrates a pre-trained Transformer model into a live, browser-accessible dashboard — no Python scripts, no specialist training required.

<img width="575" height="324" alt="image" src="https://github.com/user-attachments/assets/892bd9e4-5ee9-4656-bcdb-3b5ac5c87f13" />

---

## ❗ Problem Statement

Existing detection systems fail across five compounding dimensions:

1. **Signature-based IDS** (Snort, Zeek) cannot detect protocol-compliant covert traffic with no known signature.
2. **Classical ML** (SVM, Random Forest) requires protocol-specific manual feature engineering that does not generalize.
3. **Deep learning detectors** (LSTM, CNN) overfit to training distributions — LSTM accuracy has been documented dropping from **99.4% to 76.9%** under cross-technique evaluation.
4. No existing system has been evaluated against **adversarial anti-forensic modifications**.
5. No existing multi-protocol system provides **interpretable detection reasoning** for forensic investigation.

StegFix addresses all five gaps in a single evaluated framework.

---

## ✨ Key Features

- 🧠 **AI-Powered Detection** — Custom Transformer encoder analyzing 225 flow-level behavioral features
- 🌐 **Multi-Protocol Coverage** — DNS, ICMP, TCP, and UDP handled by one unified model
- 📡 **Real-Time Live Packet Capture** — Integrated via Npcap, no CLI required
- 🎯 **Steganography Technique Classification** — Header Manipulation / Timing Obfuscation / Flow Blending
- ✅ **94.42% Accuracy / 0.91% False Positive Rate** — under Leave-One-Technique-Out (LOTO) evaluation
- 📄 **Forensic CSV Log Export** — full detection metadata for audit and investigation
- 🖥️ **Browser-Based Analyst Dashboard** — live alerts, charts, and per-protocol analysis
- 🔐 **Behavioral Generalization** — all traffic identifiers (IP, ports, timestamps) removed before training to force the model to learn behavior, not tool signatures

---

## 🏗️ System Architecture

<img width="488" height="327" alt="image" src="https://github.com/user-attachments/assets/c8656a6d-0a60-44d7-8d0c-f65d619d57c0" />

---

## 🧬 The FeatureTokenTransformer Model

- Each of the **225 flow-level behavioral features** is treated as an independent input token
- **4 AttentionBlocks**, **8 attention heads**, `d_model = 128`
- Feed-forward network: 128 → 256 → 128 (ReLU), dropout = 0.3
- Global average pooling → shared processing head → **3 simultaneous output heads**:
  1. Binary detection (Normal / Covert)
  2. Technique classification (Header Manipulation / Timing Obfuscation / Flow Blending)
  3. Protocol attribution (DNS / ICMP / TCP / UDP)
- Returns a **225×225 attention weight matrix** per block for forensic interpretability

**Why Transformers?** Global self-attention computes pairwise relevance across all 225 features simultaneously — essential for timing-based covert channels where the covert signal is distributed across the entire flow. This is something neither CNN's bounded receptive field nor LSTM's sequential processing can achieve.

---

## 📊 Dataset

- **13,848 samples** total, split 80/20 (11,078 train / 2,770 test), stratified
- **225 features**: DNS (66), ICMP (97), TCP (41), UDP (26)
- **3 feature categories**: Header Manipulation (107), Timing Obfuscation (50), Flow Blending (73)

**Sources:**
- **DNS** — Kaggle DNS Tunneling dataset (10 tools: cobalt_strike, dns2tcp, dnscat2, DNSExfiltrator, DNSlivery, iodine, OzymanDNS, reverse_dns_shell, tcp-over-dns, tuns)
- **ICMP, TCP, UDP** — Self-generated in an isolated VM lab (Kali Linux attacker VM + Ubuntu 20.04 victim VM, host-only network) using **Ptunnel**, **Covert_TCP**, **Scapy**, and Python sockets

**Preprocessing:** identifier removal (IP, port, timestamp) → deduplication → label encoding → StandardScaler normalization → tensor conversion.

> ⚠️ Raw and processed datasets are not included in this repository due to size. DNS data source is linked under [References](#references).

---

## 📈 Results

### Model vs. Baselines (LOTO Evaluation)

| Model | Mean Binary Accuracy | Std Dev | Gap vs. Transformer |
|---|---|---|---|
| **FeatureTokenTransformer** | **94.42%** | ±3.50% | — |
| LSTM | 78.40% | ±6.20% | −16.02 pts |
| CNN | 76.20% | ±5.80% | −18.22 pts |
| Random Forest | 69.80% | ±8.10% | −24.62 pts |
| SVM | 63.10% | ±9.40% | −31.32 pts |

**Mean False Positive Rate: 0.91%**

### Per-Split LOTO Results

| Split | Withheld Technique | Binary Acc. | Protocol Acc. | FPR | FNR |
|---|---|---|---|---|---|
| 1 | Timing Obfuscation | 90.60% | 91.80% | 0.90% | 17.97% |
| 2 | Flow Blending | 99.05% | 96.10% | 1.18% | 0.78% |
| 3 | Header Manipulation | 93.60% | 98.93% | 0.64% | 12.13% |

### System Testing
- **14/14 test cases passed** (unit, integration, system, usability, security/negative testing)
- Mean SUS usability score: **76.3** (target ≥ 70)
- Verified against SQL injection, XSS payloads, session tampering, and disconnected-interface conditions
- Cross-browser tested: Chrome, Firefox, Edge

📄 Full test methodology and results are documented in `Documentations/`.

---

## 🧰 Tech Stack

**Frontend:**
- React + TypeScript
- Vite (build tool)
- Tailwind CSS + PostCSS

**Backend:**
- REST API (`backend/`)
- Python Flask (Transformer inference microservice)

**Model:**
- Python, PyTorch, Scikit-learn (`model/`)

**Packet Capture:**
- Npcap, Wireshark (development/verification)

**Environment:**
- Kali Linux (attacker VM), Ubuntu (victim VM), Windows 10/11 (deployment)

**Dev Tools:**
- Git/GitHub, Node.js, Google Colab / Kaggle (model training)

---

## 📁 Project Structure

```
StegFix/
├── Documentations/          # Full project report, diagrams, and write-ups
├── Interface Images/        # Dashboard and UI screenshots
├── backend/                 # REST API + Flask inference service
├── model/                   # FeatureTokenTransformer model, training scripts, weights
├── src/                     # React + TypeScript frontend source
├── index.html                # Frontend entry point
├── package.json              # Frontend dependencies
├── package-lock.json
├── vite.config.js            # Vite build configuration
├── tailwind.config.js        # Tailwind CSS configuration
├── postcss.config.js
├── tsconfig.json              # TypeScript base config
├── tsconfig.node.json
├── requirements.txt           # Python dependencies (model + backend)
├── .gitignore
└── README.md
```

> **Note:** `node_modules/`, `.env`, and `__pycache__/` are intentionally excluded/ignored — install dependencies locally using the setup instructions below.

---

## ⚙️ Installation & Setup

### Prerequisites
- Windows 10/11 (64-bit) — required for Npcap
- Node.js 18+
- Python 3.9+
- Npcap

### 1. Clone the repository
```bash
git clone https://github.com/MalaikaUmbreen/StegFix.git
cd StegFix
```

### 2. Set up the frontend
```bash
npm install
npm run dev
# Runs on http://localhost:5173 (Vite default)
```

### 3. Set up the backend
```bash
cd backend
pip install -r ../requirements.txt
# Configure environment variables (see below)
# Start the backend server
```

### 4. Set up the model / inference service
```bash
cd model
python app.py
# Runs the Flask inference endpoint (default: http://localhost:5000)
```

### 5. Environment variables
Create a `.env` file in the project root (not tracked by Git) with the required variables, e.g.:
```
INFERENCE_SERVICE_URL=http://localhost:5000
```

### 6. Install Npcap
Download and install [Npcap](https://npcap.com/) with WinPcap API compatibility mode enabled.

---

## 🚀 Usage

1. Register/login through the dashboard
2. Select your network interface and click **Start Capture**
3. View live detections, technique classification, and protocol breakdown in real time
4. Inspect individual flows under **Flow Detail Analysis**
5. Export detection history via **Export CSV** on the Logs page

### Testing detection with sample covert tools
Use freely available covert channel tools from an isolated attacker VM to simulate covert traffic against a victim machine running StegFix:
- **DNS**: dns2tcp, dnscat2, iodine
- **ICMP**: Ptunnel
- **TCP**: Covert_TCP
- **UDP**: custom multi-channel encoding

> ⚠️ Only run these tools in an isolated lab environment (VMs with no external network access). Do not run covert traffic generation tools against production networks.

---

## 🧪 Testing

Full test case documentation (14 test cases covering functional and non-functional requirements) is available in `Documentations/`. Testing covered:

- Unit testing (API endpoints via Postman)
- Integration testing (Npcap → Backend → Flask → Database → Frontend)
- System testing (full analyst workflows, pre-labeled PCAP replay)
- Usability testing (SUS score 76.3)
- Security/negative testing (SQL injection, XSS, session tampering)

---

## ⚠️ Limitations

- ICMP/TCP/UDP training data generated in an isolated lab — not yet validated on real backbone network traffic
- LOTO evaluation used a balanced dataset; real-world traffic has far lower covert-to-normal ratios
- Covers 3 technique categories only (Header Manipulation, Timing Obfuscation, Flow Blending) — emerging methods (QUIC, DoH tunneling, IPv6 extension headers) not yet covered
- Npcap capture requires Windows 10/11 — no native Linux/macOS support yet
- Single-instance Flask inference service — not yet containerized for horizontal scaling
- No detection capability for steganography inside fully encrypted (TLS/QUIC) traffic

---

## 🔮 Future Work

- Extend detection to QUIC, DNS-over-HTTPS, and IPv6 extension header covert channels
- Cross-platform deployment via libpcap (Linux/macOS) + Docker containerization
- Validation against real-world traffic (MAWI, CAIDA datasets)
- SIEM integration (Splunk, Zeek plugin, Wireshark dissector)
- Federated learning for privacy-preserving multi-site model improvement
- Automated retraining pipeline triggered by confidence-score drift

---

## 📚 References

- G. J. Simmons, *The Prisoners' Problem and the Subliminal Channel*, CRYPTO 1983
- B. W. Lampson, *A Note on the Confinement Problem*, CACM 1973
- S. Wendzel et al., *Pattern-Based Survey and Categorization of Network Covert Channel Techniques*, ACM Computing Surveys 2015
- A. Vaswani et al., *Attention Is All You Need*, NeurIPS 2017
- K. Cho and C.-H. Lai, *A New Approach for Network Steganography Detection Based on Deep Learning Techniques*, IJACSA 2021
- Kaggle DNS Tunneling Dataset: https://www.kaggle.com/datasets/daumellado/dns-tunneling-dataset

Full reference list available in `Documentations/`.

---

## 📄 License

This project is shared for educational and research purposes. Feel free to explore, fork, and learn from it. If you use this work or build upon it, please provide appropriate credit.

---

⭐ If you found this project interesting or useful, consider giving it a star!
