# AEAD Performance Benchmark Results

This document records the empirical evaluation of lightweight AEAD candidates (**ASCON-128**) against standard symmetric encryption schemes (**AES-128-GCM** and **ChaCha20-Poly1305**) as part of the M2M IoT Security project.

---

## 1. Experimental Setup

* **Environment:** Python 3.14 (Virtual Environment in WSL/Ubuntu)
* **Iterations per Test:** 5,000 iterations per payload size
* **Evaluated Metrics:**
  * **Encryption / Decryption Time:** Average runtime per operation ($\mu s$)
  * **Throughput:** Data processing rate ($MB/s$)
  * **Tag Overhead:** Additional authentication byte count per packet
  * **Peak RAM Usage:** Maximum memory allocated during cipher execution ($KB$)

---

## 2. Benchmark Results

### Payload Size: 64 Bytes (Small Telemetry / Sensor Packet)

| Algorithm | Enc Time ($\mu s$) | Dec Time ($\mu s$) | Throughput ($MB/s$) | Tag Overhead (Bytes) | Peak RAM ($KB$) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ASCON-128** | 3679.64 | 3916.65 | 0.02 | 16 | 4.44 |
| **AES-128-GCM** | 1.17 | 1.46 | 52.27 | 16 | 0.35 |
| **ChaCha20-Poly1305** | 2.77 | 3.49 | 22.01 | 16 | 0.30 |

---

### Payload Size: 256 Bytes (Medium Status Payload)

| Algorithm | Enc Time ($\mu s$) | Dec Time ($\mu s$) | Throughput ($MB/s$) | Tag Overhead (Bytes) | Peak RAM ($KB$) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ASCON-128** | 10352.49 | 10194.15 | 0.02 | 16 | 2.27 |
| **AES-128-GCM** | 1.43 | 1.64 | 171.06 | 16 | 0.86 |
| **ChaCha20-Poly1305** | 1.86 | 2.16 | 131.04 | 16 | 0.86 |

---

### Payload Size: 1024 Bytes (1 KB / High-density Sensor Log)

| Algorithm | Enc Time ($\mu s$) | Dec Time ($\mu s$) | Throughput ($MB/s$) | Tag Overhead (Bytes) | Peak RAM ($KB$) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ASCON-128** | 31841.13 | 28945.50 | 0.03 | 16 | 6.57 |
| **AES-128-GCM** | 1.47 | 1.67 | 663.77 | 16 | 3.11 |
| **ChaCha20-Poly1305** | 1.81 | 1.96 | 538.19 | 16 | 3.11 |

---

### Payload Size: 4096 Bytes (4 KB / Firmware Block or Large Packet)

| Algorithm | Enc Time ($\mu s$) | Dec Time ($\mu s$) | Throughput ($MB/s$) | Tag Overhead (Bytes) | Peak RAM ($KB$) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ASCON-128** | 110838.67 | 11081.47 | 0.04 | 16 | 24.64 |
| **AES-128-GCM** | 2.21 | 2.59 | 1767.18 | 16 | 12.11 |
| **ChaCha20-Poly1305** | 3.52 | 3.51 | 1110.71 | 16 | 12.11 |

---

## 3. Analysis & Key Takeaways

1. **Authentication Tag Uniformity:**
   * All three algorithms produce a standardized **16-byte (128-bit) authentication tag**, providing equivalent $2^{128}$ security strength against payload forgery.

2. **Execution Overhead in Python Environment:**
   * **AES-128-GCM** and **ChaCha20-Poly1305** leverage C-compiled OpenSSL bindings and hardware-accelerated instructions (AES-NI / SIMD) via `cryptography.hazmat`.
   * **ASCON-128** in this environment runs via pure-Python bitwise operations, leading to significantly higher latency per operation.

3. **Relevance to Constrained Embedded Hardware:**
   * On native microcontrollers (e.g., 8-bit/32-bit Cortex-M0/ESP32 without dedicated hardware AES accelerators), pure C implementations of **ASCON-128** drastically outperform software AES due to simpler substitution-permutation networks (SPN) and lower RAM footprint.