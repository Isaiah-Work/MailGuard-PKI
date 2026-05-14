# MailGuard PKI — Agent Instructions

## Project overview

MailGuard PKI is an academic S/MIME PKI management system. It provides a
3-tier certificate hierarchy (Root CA → Intermediate CA → user certs)
with CRL publishing, key escrow, and a web-based Registration Authority.

- **Language:** Python 3.12+ (stdlib-heavy)
- **Web framework:** [FastHTML](https://fastht.ml/) + Starlette + Pico CSS
- **Infrastructure:** OpenSSL CLI (via `subprocess`)
- **Database:** SQLite via stdlib `sqlite3`
- **Single dependency:** `python-fasthtml` (see `requirements.txt`)

All user-facing text, comments, and docstrings are in **Mexican Spanish**.

## Commands

### Setup

```bash
python -m venv env
source ./env/bin/activate
pip install -r requirements.txt
```

### Run (development)

```bash
python main.py
# Serves on http://0.0.0.0:8099
```

### Docker

```bash
docker compose up --build
```

### Tests

There are currently **no automated tests** in this project. Each module in
`crypto_core/` has an `if __name__ == "__main__":` block for manual
execution during development.

When tests are added (recommended: `pytest`):

```bash
pip install pytest
python -m pytest                          # run all tests
python -m pytest tests/test_ra.py         # single file
python -m pytest -k "test_enroll"         # filter by name
```

### Linting & formatting

No linter or formatter is configured yet. If `ruff` is added to the
project:

```bash
ruff check .                             # lint
ruff format .                            # format
```

## Code conventions

### Imports

- **stdlib first**, then third-party, then local absolute imports — separated
  by a blank line between groups.
- `from fasthtml.common import *` is the only wildcard import (required by
  FastHTML's DSL).
- Local imports use **absolute paths** within the package:
  `from crypto_core.config import ADMIN_PASSWORD`
- Deferred imports inside function bodies are used to break circular
  dependencies when two `crypto_core` modules need each other:

  ```python
  def generate_user_p12(...):
      from crypto_core.escrow import store_escrow
      ...
  ```

### Naming

| Category | Convention | Examples |
|---|---|---|
| Functions & variables | `snake_case` | `generate_root_ca`, `crl_path` |
| Module-level constants | `UPPER_SNAKE_CASE` | `CRL_URL`, `SCRYPT_N`, `VALID_REASONS` |
| Internal helpers | `_underscore` prefix | `_connect()`, `_run()`, `_audit()` |
| FastHTML route handlers | `get_` / `post_` prefix | `get_root()`, `post_solicitar()` |
| Config dicts | `UPPER_SNAKE_CASE` | `ORG_DEFAULTS`, `EXPIRY_THRESHOLDS_DAYS` |

### File structure

- Module docstring in triple quotes at the top of every `.py` file.
- Section separators for long files:
  ```python
  # ──────────────────────────────────────────────────────────
  #  Section title
  # ──────────────────────────────────────────────────────────
  ```
- `if __name__ == "__main__":` block at the end of each `crypto_core/`
  module for manual testing.

### Error handling

- **Subprocess calls:** `raise RuntimeError(...)` with OpenSSL stderr on
  non-zero exit. Helper functions (`run()` / `_run()`) encapsulate this.
- **Web routes:** `try/except Exception as e` wrapping all controller logic,
  returning HTML error pages via FastHTML components.
- **Validation functions:** Return structured dicts with
  `{"passed": True/False/None, "level": "critical"|"warning"|"info", "detail": "…"}`
  — never raise exceptions.
- **Domain errors:** `ValueError` for invalid input, `FileNotFoundError` for
  missing files, `PermissionError` where appropriate.

### Subprocess (OpenSSL) patterns

- Always pass commands as **lists** (never shell strings):
  ```python
  subprocess.run(["openssl", "x509", "-req", "-in", str(csr_path), ...],
                 capture_output=True, text=True)
  ```
- Passwords via `-pass pass:{password}` or `-passin pass:{password}` /
  `-passout pass:{password}`.
- Clean up temporary files with `Path.unlink(missing_ok=True)`.

### Database (SQLite)

- `row_factory = sqlite3.Row` for dict-like row access.
- `executescript()` for DDL, `execute()` + `commit()` for DML.
- Schema migrations inline: `PRAGMA table_info(...)` followed by
  `ALTER TABLE ADD COLUMN`.
- Connections are closed in a `finally` block.

### String formatting

- **f-strings** preferred everywhere. No `%` formatting, no `.format()`.

### Type hints

- Partial usage — type hints exist on some signatures but not consistently.
  When adding hints, use `str | None` union syntax (Python 3.10+).
- No type checker is configured yet.

### Web UI (FastHTML + Pico CSS)

- HTML is built entirely with FastHTML's Python DSL — no template files.
- Use Pico CSS utility classes: `cls="container"`, `cls="contrast"`,
  `cls="outline"`, `cls="secondary"`.
- Response patterns: `Main(Article(H1(...), ...))` for pages,
  `FileResponse(path)` for downloads, `Response(content)` for raw bytes.

## Directory layout

```
.
├── main.py                  # FastHTML app (all routes)
├── requirements.txt         # Single dependency
├── dockerfile / docker-compose.yml
├── crypto_core/             # Business logic (10 modules)
│   ├── config.py            # Central configuration
│   ├── root_ca.py           # Step 1: Root CA generation
│   ├── inter_ca.py          # Step 2: Intermediate CA generation
│   ├── usuarios_p12.py      # Step 3: User PKCS#12 generation
│   ├── ra.py                # Registration Authority (SQLite)
│   ├── crl.py               # CRL management
│   ├── escrow.py            # Key Recovery Agent
│   ├── bundle.py            # ZIP bundle builder (Thunderbird)
│   ├── validation.py        # X.509 chain validation (14 checks)
│   └── openssl_ca.cnf       # OpenSSL CA config (CRL)
├── root_ca_output/          # Root CA artifacts
├── ca_intermedia_output/    # Intermediate CA + CRL + RA DB
└── usuarios_p12_output/     # User certificates (.p12 + .crt)
```
