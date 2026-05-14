# MailGuard PKI - Project Context

This document provides a comprehensive overview of the MailGuard PKI project, serving as instructional context for development and maintenance.

## 📋 Project Overview
**MailGuard PKI** is a Public Key Infrastructure system designed to provide secure email communication via **S/MIME**. It facilitates the entire lifecycle of digital certificates, from Root CA creation to user certificate issuance, revocation, and key recovery.

### Main Technologies
- **Language:** Python 3.x
- **Web Framework:** [FastHTML](https://fasthtml.com/) (built on Starlette)
- **UI/Styling:** Pico CSS
- **Cryptography Engine:** OpenSSL (invoked via Python subprocesses)
- **Database:** SQLite (managed in `crypto_core/ra.py`)
- **Directory Integration:** LDAP/3 for Active Directory synchronization

### Architecture & Components
The system is divided into several logical authorities and modules located in `crypto_core/`:
- **Root CA (`root_ca.py`):** Generates the top-level self-signed certificate. Intended for offline/vault storage.
- **Intermediate CA (`inter_ca.py`):** Acts as the primary issuing authority, signed by the Root CA.
- **Registration Authority (RA) (`ra.py`):** Manages user identities, enrollment, and authentication.
- **Key Recovery Authority (KRA) / Escrow (`escrow.py`):** Provides a secure mechanism for administrative recovery of user private keys using a master password.
- **Validation Engine (`validation.py`):** Performs automated X.509 chain validation and compliance checks.
- **CRL Manager (`crl.py`):** Handles certificate revocation and CRL generation.

## 🚀 Building and Running

### Prerequisites
- Python 3.10+
- OpenSSL installed and available in the system path.

### Setup
```bash
# 1. Clone the repository
git clone https://github.com/Isaiah-Work/MailGuard-PKI.git
cd MailGuard-PKI

# 2. Create and activate a virtual environment
python -m venv env
source ./env/bin/activate  # On Windows: .\env\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Running the Application
```bash
python main.py
```
The application defaults to `http://0.0.0.0:8099`.

### Key Outputs
- `root_ca_output/`: Contains the Root CA private key and certificate.
- `ca_intermedia_output/`: Contains the Intermediate CA keys, certificates, and CRL.
- `usuarios_p12_output/`: Stores generated `.p12` bundles and public certificates for users.

## 🛠 Development Conventions

### Coding Style
- **Procedural/Functional leaning:** The core logic in `crypto_core` is largely organized into functional modules.
- **Subprocess calls:** Extensive use of `subprocess.run` to execute OpenSSL commands. 
- **Type Hinting:** Used in many parts of the codebase for clarity.

### Security Practices
- **Password Hashing:** Uses `scrypt` for storing user passwords in the RA database.
- **Private Key Protection:** All private keys (`.key` and `.p12`) are encrypted using **AES-256-CBC**.
- **Session Security:** CA intermediate and master passwords are kept in memory during an "unlocked" session and never persisted to the database.

### Standards Compliance
The project adheres to several IETF RFCs for interoperability:
- **RFC 5280:** X.509 v3 Certificates and CRLs.
- **RFC 8017:** PKCS #1 (RSA Cryptography).
- **RFC 7292:** PKCS #12 (Personal Information Exchange Syntax).
- **RFC 8551:** S/MIME v4.0 Message Specification.

## 📂 Key Files & Directories
- `main.py`: The entry point and FastHTML routing definitions.
- `crypto_core/`: The heart of the PKI logic.
- `requirements.txt`: Project dependencies (primarily `fasthtml` and `ldap3`).
- `AGENTS.md`: Historical/Contextual agent instructions (internal).
- `README.md`: High-level project description and roadmap.
