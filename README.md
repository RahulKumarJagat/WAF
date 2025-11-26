Here is the formatted `README.md` file. You can copy the code block below directly into your project's `README.md` file.

````markdown
# Advanced WAF (Web Application Firewall) 🦀🤖

![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![PyTorch](https://img.shields.io/badge/PyTorch-%23EE4C2C.svg?style=for-the-badge&logo=PyTorch&logoColor=white)
![Pingora](https://img.shields.io/badge/Cloudflare-Pingora-orange?style=for-the-badge)

A next-generation, high-performance Web Application Firewall built with **Rust (Pingora)** and **Python (PyTorch/BERT)**. This project demonstrates a hybrid defense-in-depth architecture that combines the raw speed of async Rust with the semantic understanding of Deep Learning to block sophisticated web attacks.

## 🚀 Features

* **Hybrid Architecture:**
    * **Layer 1 (Rust):** High-speed DDoS protection and Rate Limiting (100 req/min).
    * **Layer 2 (Rust Regex):** Instant blocking of known signatures (SQLi, Path Traversal) and static asset whitelisting.
    * **Layer 3 (Anti-Bot):** User-Agent fingerprinting to block scanners (Nmap, Nikto, Nessus).
    * **Layer 4 (AI Brain):** A fine-tuned **BERTv3** model running in Python analyzes the *semantic intent* of payloads to catch obfuscated attacks (e.g., buried XSS, logic fraud) that bypass regex.
* **Zero-Copy Bridge:** Uses **PyO3** to efficiently pass data between the Rust proxy and the embedded Python interpreter without serialization overhead.
* **Async & Multi-threaded:** Built on Cloudflare's **Pingora** framework to handle thousands of concurrent connections.
* **Smart Logic Detection:** Specifically trained to detect business logic attacks (e.g., `price: 0.00` fraud attempts).

## 🛠️ Tech Stack

* **Core Proxy:** Rust (Pingora framework)
* **AI Engine:** Python 3.10+
* **ML Framework:** PyTorch (Transformers)
* **Model:** BERT-v3 (Sequence Classification)
* **FFI Bridge:** PyO3
* **State Management:** DashMap (Concurrent Hashmap)

## 📂 Project Structure

```text
.
├── Cargo.toml              # Rust dependencies (Pingora, PyO3, Tokio)
├── src
│   ├── main.rs             # Entry point, Server initialization
│   ├── proxy.rs            # WAF Logic (Rate Limiting, Regex, Request Filtering)
│   └── engine.rs           # Rust-Python Bridge (PyO3)
├── waf_brain
│   ├── core.py             # Python AI Engine (Model Loading, Heuristics, Inference)
│   └── ai_model/           # Directory containing your trained BERT model
│       ├── config.json
│       └── model.safetensors
└── README.md
````

## ⚡ Quick Start

### Prerequisites

1.  **Rust Toolchain:** Install via `rustup`.
2.  **Python 3.10+:** Ensure it is in your PATH.
3.  **Python Dependencies:**
    ```bash
    pip install torch transformers
    ```
4.  **AI Model:** Place your trained BERT model files inside `waf_brain/ai_model/`.

### Running the WAF

Build and run the project in release mode for optimal performance.

```bash
# The WAF will listen on 0.0.0.0:6188
cargo run --release
```

*Wait for the log message: `[PYTHON BRAIN] Deep Learning Model Ready!`*

## 🧪 Testing

Use the included Python test scripts to verify the WAF's detection capabilities.

### 1\. Robust Test Suite

Tests "False Positives" (Math, JSON) vs "True Positives" (XSS, SQLi).

```bash
python3 waf_test_robust.py
```

### 2\. Manual Attack Examples (cURL)

**Blocked (SQL Injection):**

```bash
curl -v "[http://127.0.0.1:6188/search?q=union+select+password+from+users](http://127.0.0.1:6188/search?q=union+select+password+from+users)"
# Result: 403 Forbidden
```

**Blocked (Logic Fraud):**

```bash
curl -v -X POST "[http://127.0.0.1:6188/checkout](http://127.0.0.1:6188/checkout)" \
     -H "Content-Type: application/json" \
     -d '{"item": "PS5", "price": "0.00"}'
# Result: 403 Forbidden
```

**Allowed (Legitimate JSON):**

```bash
curl -v -X POST "[http://127.0.0.1:6188/api](http://127.0.0.1:6188/api)" \
     -H "Content-Type: application/json" \
     -d '{"id": 123, "status": "active"}'
# Result: 404 (Passed WAF, Hit Upstream)
```

## 🛡️ Defense in Depth Strategy

| Layer | Technology | Responsibility | Latency Impact |
| :--- | :--- | :--- | :--- |
| **1** | Rust (DashMap) | **DDoS Protection**: Rate limits IPs (100 req/min). | \~0.01ms |
| **2** | Rust (Regex) | **Fast Filter**: Blocks obvious SQLi (`UNION SELECT`) & Bots. | \~0.1ms |
| **3** | Python (Heuristics) | **Sanity Check**: Whitelists valid JSON/Math to reduce AI load. | \~0.5ms |
| **4** | Python (BERT) | **Deep Analysis**: Detects semantic malice in ambiguous payloads. | \~50-150ms |

## ⚠️ Performance Note

This WAF loads a Transformer model into RAM. Ensure your machine has at least **4GB of free RAM**. If the process is `Killed`, you are running out of memory—try using a distilled model (e.g., `DistilBERT`) or reducing the max sequence length in `core.py`.

## 📜 License

MIT License

```
```
