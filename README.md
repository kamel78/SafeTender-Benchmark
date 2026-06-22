# SafeTender: Benchmark & Reference Implementation

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Language: Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)
[![Wasm: Supported](https://img.shields.io/badge/Wasm-Supported-blueviolet.svg)](https://webassembly.org/)

This repository contains the official prototype and benchmarking suite for SafeTender, a decentralized, web-native cryptographic framework for threshold-based e-procurement without a trusted dealer[cite: 1]. 

SafeTender combines the additive homomorphism of elliptic curve operations with verifiable secret sharing (VSS) active-security guarantees[cite: 1]. The client-side core cryptographic primitives are compiled from Rust into WebAssembly (Wasm) to run inside a high-performance, memory-safe browser sandbox[cite: 1]. 

---

## 📂 Repository Structure

The workspace is organized into a modular Rust cargo workspace comprising the browser-facing asset stack, the client-side WebAssembly layer, and an asynchronous backend server:
```text
|-- Cargo.toml                  # Workspace configuration
|-- Cargo.lock
|-- web/                        # Frontend UI and client asset pipeline
|   |-- sharing.html            # Setup, DKG, and benchmarking dashboard
|   |-- encryption.html         # Client-side bid encryption interface
|   |-- reconstruction.html     # Secret share aggregation and opening panel
|   |-- css/                    # Component stylesheets (enc.css, styles.css, all.min.css)
|   |-- webfonts/               # Iconography assets (FontAwesome)
|   |-- scripts/                # Execution scripts (core.js, files.js, scripts.js, bench.js)
|   |-- pkg/                    # Web-ready target binaries and optimized assets (.br)
|-- wasm/                       # WebAssembly interface compilation layer
|   |-- Cargo.toml
|   |-- src/
|   |   |-- lib.rs              # JS/Wasm binding exposures (wasm-bindgen entry points)
|   |-- pkg/                    # Compiled distribution bundle output
|   |-- secrete_sharing/        # Monolithic cryptography kernel crate
|       |-- Cargo.toml
|       |-- src/
|           |-- lib.rs          # Internal crate registration
|           |-- fields/         # Custom prime fields and modular arithmetic implementations
|           |   |-- fields_core/ (prime_fields.rs, hashs.rs, arithmetic.rs, builders.rs, exponent.rs)
|           |-- curves/         # Elliptic curve scalar multiplication algebra
|           |   |-- curves_core/ (curve_arithmetics.rs)
|           |-- shamir/         # Shamir threshold scheme logic
|           |   |-- shamir_core/ (core.rs)
|           |-- encryption/     # Symmetric and hybrid envelope encryption steps
|               |-- crypto_core/ (chacha_poly1305.rs)
|-- server/                     # Coordination Layer
    |-- Cargo.toml
    |-- src/
        |-- main.rs             # Axum / Async routing infrastructure
```
## 🛠️ Technology Stack

* **Crypto Kernel**: Native Rust implementation containing specialized modules for `fields` (modular field arithmetic, custom primitives, and exponents) alongside `curves` (constant-time coordinate mapping) and `shamir` algorithms.
* **Symmetric Layer**: Authenticated Encryption with Associated Data (AEAD) driven by ChaCha20-Poly1305 configurations.
* **Client Runtime**: `wasm-pack` generated WebAssembly layers, exposing compiled cryptographic routines straight to browser runtimes via JavaScript hooks.
* **Server Stack**: Asynchronous network communication built over the Axum web framework.

---

## 🚀 Getting Started

### Prerequisites
* Rust Toolchain (Stable 2021 edition or newer)
* `wasm-pack` (Run `cargo install wasm-pack` to install)

### 1. Compile Cryptographic WebAssembly Bindings
Build the core cryptographic bindings using `wasm-pack`. Target the compilation to generate browser-compatible packages:

cd wasm
wasm-pack build --target web --out-dir ../web/pkg

### 2. Launch the Backend Infrastructure
Navigate into the backend coordination layer and initialize the runtime server node:

cd ../server
cargo run --release

Once active, navigate your browser to the local server address to access the step-by-step cryptographic sequence dashboards.

---

## 🔬 Benchmarking Metrics

Performance validation and profiling tools are built right into the frontend workspace interfaces (`sharing.html`, `encryption.html`, and `reconstruction.html`), backed by `bench.js`. These profiles trace microsecond execution timelines across:
* **Field Arithmetic Operations**: Evaluating latency metrics for modular field arithmetic, point inversions, and exponentiation loops.
* **Secret Reconstruction**: Benchmarking Lagrange interpolation efficiency over escalating numbers of collected sub-shares.
* **Encryption Throughput**: Assessing data processing rates during symmetric encryption cycles using ChaCha20-Poly1305.

---

## 📄 Citation & Academic Reference

If you incorporate this implementation model or baseline metrics within scientific text layouts, please attribute the work as follows[cite: 1]:

```bibtex
@article{bouremena2026safetender,
  title={SafeTender: A Web-Native, Zero-Trust Architecture for Sealed-Bid Procurement with Universally Composable Security},
  author={Bouremena, Aya and Boumedienne, Karima and Faraoun, Kamel Mohamed},
  journal={Computer Science Department, EEDIS Laboratory, Djilalli Liabès University},
  year={2026}
}
