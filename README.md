

````markdown
# AI-Powered Web Application Firewall (WAF)

![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange?logo=rust)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Security](https://img.shields.io/badge/Security-AI%20Powered-green)

A hybrid, high-performance Web Application Firewall. This project leverages **Rust** for low-latency traffic interception and proxying, integrated with a **Python-based Deep Learning brain** to detect malicious payloads (SQLi, XSS, RCE) in real-time.

## 📂 Repository Structure

```text
.
├── src/                # Rust Engine (Proxy & Traffic Handling)
│   ├── main.rs         # Application Entry Point
│   ├── engine.rs       # Interface between Rust and Python
│   └── proxy.rs        # Async HTTP Proxy Logic
├── waf_brain/          # AI Detection Core
│   ├── core.py         # Main Classification Logic
│   └── ai_model/       # Transformer Model & Tokenizers
├── config/             # Configuration
│   └── certs.pem       # SSL Certificates (See Setup)
├── Cargo.toml          # Rust Dependencies
└── pyproject.toml      # Python Dependencies
````

## 🚀 Features

  * **Hybrid Engine**: Combines the speed of Rust with the ecosystem of Python AI.
  * **Deep Learning Detection**: Uses a `safetensors` model to understand context, reducing false positives compared to traditional Regex WAFs.
  * **Real-Time Blocking**: Intercepts requests and blocks threats before they reach the upstream server.
  * **Custom Tokenizer**: Includes specialized tokenization for web attack vectors.

## 🛠️ Installation & Setup

### 1\. Prerequisites

  * **Rust**: [Install Rust](https://rustup.rs/)
  * **Python 3.10+**: Ensure Python is installed and added to your PATH.

### 2\. Clone the Repository

```bash
git clone [https://github.com/RahulKumarJagat/WAF.git](https://github.com/RahulKumarJagat/WAF.git)
cd WAF
```

### 3\. Setup Python Environment

The Rust engine requires the Python environment to load the AI model.

```bash
# Create a virtual environment
python -m venv .venv

# Activate the environment
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install .
```

### 4\. Model Setup

Ensure your AI model weights are present. If you cloned this repo without Git LFS, you may need to manually place `model.safetensors` into `waf_brain/ai_model/`.

### 5\. SSL Configuration

For HTTPS inspection, place your certificate file in the config directory:

```bash
# Ensure the config folder exists
mkdir -p config
# Place your certificate (Do not commit real keys to GitHub!)
cp /path/to/your/certs.pem config/certs.pem
```

## 🏃‍♂️ Usage

To start the WAF, use Cargo. This will compile the Rust source and link against the Python environment.

```bash
# Run in release mode for performance
cargo run --release
```

*The WAF will start listening on the configured port (default: 8080/8000).*

## ⚠️ Disclaimer

This tool is for educational and defensive purposes only. Do not use this software to attack targets you do not have permission to test.

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

[MIT](https://choosealicense.com/licenses/mit/)

```
```
