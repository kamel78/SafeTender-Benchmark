# SafeTender: Benchmark & Reference Implementation

This repository contains the official prototype and benchmarking suite for SafeTender, a decentralized, web-native cryptographic framework for threshold-based e-procurement without a trusted dealer[cite: 1]. 

SafeTender resolves the Chronological Paradox inherent to classical Secret Sharing Schemes (SSS) by combining the additive homomorphism of elliptic curve scalar multiplication over the secp256k1 curve with Feldman Verifiable Secret Sharing (VSS) active-security guarantees[cite: 1]. All client-side cryptographic primitives execute within a memory-safe WebAssembly (Wasm) sandbox[cite: 1]. Shares are preserved across long submission-to-opening windows via a server-blind configuration driven by the OPAQUE asymmetric Password-Authenticated Key Exchange (aPAKE) protocol and Argon2id password hardening[cite: 1].

---

## Repository Structure

The project is decoupled into an asynchronous server backend, a dedicated browser-side client application, and web-native WebAssembly compilation bridges[cite: 1]:
```text
|-- LICENSE
|-- README.md
|-- client/                           # Client-side core cryptography compiled to Wasm
|   |-- Cargo.toml
|   |-- Cargo.lock
|   |-- pkg/                          # Compiled Wasm outputs and JS bindings
|   |   |-- axclient.js
|   |   |-- axclient_bg.wasm
|   |   |-- axclient_bg.wasm.d.ts
|   |   |-- package.json
|   |   |-- axclient.d.ts
|   |-- src/
|       |-- lib.rs                    # Wasm implementation for bid encryption & client state
|-- server/                           # State-blind coordination layer & static web assets
    |-- Cargo.toml
    |-- Cargo.lock
    |-- main.rs                       # Axum + Tokio server initialization
    |-- wasm_interface/               # Web interfaces for distributed key generation & crypto actions
    |   |-- Cargo.toml
    |   |-- src/lib.rs
    |   |-- html/                     # Interface steps (yakhdam, sharing, encryption, reconstruction)
    |   |-- css/
    |   |-- scripts/
    |-- static/                       # Compiled output bins and core web assets
    |   |-- html/                     # Role-based templates (register, login, dashboards, recovery)
    |   |-- emails/                   # Invitation email templates
    |   |-- pkg/                      # Copied binary payloads for frontend consumption
    |-- tests/                        # Integration testing suite
    |   |-- db_connection.rs
    |-- src/
        |-- authorization_jwt/        # Short-lived JWT session issuance
        |-- authentication_opaque/    # Server-side OPAQUE aPAKE engine & cipher suites
        |-- handlers/                 # Endpoint logic (Shamir, Marché events, Commissions, Notifications)
        |-- entities/                 # Database mapping (SeaORM structures)
```
---

## Technology Stack

* Crypto Core: Rust k256 crate — Constant-time secp256k1 scalar field multiplication, Feldman VSS commitments, and ECIES operations.
* Client Engine: wasm-pack / WebAssembly — Isolates personal key fragments and polynomials inside linear memory sandboxes.
* Auth Pipeline: OPAQUE PAKE + Argon2id — Enables server-blind storage, preventing plaintext share exposure under database breaches[cite: 1].
* Server Tier: Axum + Tokio (Async Rust) — Handles concurrent WebSocket message relays and metadata routing without visibility into secrets.
* Persistence: PostgreSQL + SeaORM — Stores public metadata, signed commitment vectors, and encrypted artifacts.

---

## Getting Started

### Prerequisites
* Rust Toolchain (Stable 2021 edition or newer)
* wasm-pack (cargo install wasm-pack)
* PostgreSQL Instance

### 1. Build the WebAssembly Assets
Compile the core cryptographic bindings to WebAssembly target layers before running the local infrastructure:

cd client
wasm-pack build --target web --out-dir pkg

cd ../server/wasm_interface
wasm-pack build --target web --out-dir ../static/pkg

### 2. Configure Environment Variables
Create a .env file within the root of the server/ directory:

DATABASE_URL=postgres://user:password@localhost:5432/safetender_db
SERVER_BIND_ADDRESS=127.0.0.1:8080
JWT_SECRET=your_super_secret_jwt_signing_key_here

### 3. Run the Server Node
Initialize the persistence layer and launch the Axum multi-threaded platform:

cd server
cargo run --release

The server will bind to http://127.0.0.1:8080.

---

## Benchmarking Metrics

The testing workspace validates performance parameters directly referenced in the paper's evaluation[cite: 1]:
* DKG Setup Phase Latency: Sub-millisecond execution patterns for typical configuration metrics (e.g., t=3, n=5) within standard browser sandboxes[cite: 1].
* Memory Constraints: Minimal client overhead bounded to approximately 64 MB per Argon2id instance[cite: 1].
* Sub-Share Disqualification: Fault detection and cheater isolation running inside the asynchronous WebSocket engine[cite: 1].

To evaluate the database connection pool constraints, navigate to the server and trigger the automated system tests:

cd server
cargo test --test db_connection

---

## Citation & Academic Reference

If you incorporate this implementation model or baseline metrics within scientific text layouts, please attribute the work as follows[cite: 1]:

@article{bouremena2026safetender,
  title={SafeTender: A Web-Native, Zero-Trust Architecture for Sealed-Bid Procurement with Universally Composable Security},
  author={Bouremena, Aya and Boumedienne, Karima and Faraoun, Kamel Mohamed},
  journal={Computer Science Department, EEDIS Laboratory, Djilalli Liabès University},
  year={2026}
}

---

## License
Distributed under standard academic terms. See the enclosed LICENSE file for permissions.
